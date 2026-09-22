# Chromium & Playwright — Setup and Usage

Everything this project does with Playwright and Chromium, in one place: why we use them, how
they're installed, exactly how the code drives them, the proxy topology that makes ZAP observe
authenticated traffic, and the gotchas we hit.

Versions in use: **Playwright 1.62.0**, Chromium build **1234** (installed via
`playwright install chromium`).

---

## 1. Why Playwright + Chromium at all

DAST scans a *running* app. ZAP on its own can crawl, but it cannot log in like a human or
execute a JavaScript SPA. Juice Shop is an Angular SPA whose interesting endpoints (`/rest/*`)
only appear after a real browser logs in and clicks around.

**Playwright drives a real Chromium** through the login and an authenticated journey; that
browser is **proxied through ZAP**, so ZAP records the authenticated requests it would never
reach on its own (FR-S1, FR-R2). Playwright is the browser-automation half of the runner; ZAP
is the scanner half.

- Used in: `runner/replay.py` (the driver) and `security/dast/juice-shop/flow.py` (the flow).
- Runtime dependency: `requirements.txt` → `playwright>=1.40`.

## 2. Installation

Two steps — the pip package, then the actual browser binary (a separate ~150 MB download):

```bash
pip install playwright            # or: pip install -r requirements.txt
playwright install chromium       # downloads Chromium into the Playwright cache
```

- The browser lands in the Playwright cache (macOS: `~/Library/Caches/ms-playwright/`,
  e.g. `chromium-1234/`). It is **not** in the repo and not a pip package.
- `playwright install chromium` installs only Chromium (not Firefox/WebKit) — all we need.
- In CI or a container this download must run once during image build (see step 6 /
  containerization in `runner_design.md`).

## 3. How the driver uses Playwright (`runner/replay.py`)

```python
from playwright.sync_api import sync_playwright   # imported LAZILY inside replay()

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=headless, proxy={"server": zap_proxy})
    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    page.route("**/*", lambda route: guard.route_handler(route))   # scope guard (FR-S4)
    result = flow_module.run(page, base_url)
    context.close(); browser.close()
```

Key choices and why:

| Call | Why |
|------|-----|
| **lazy `import`** (inside `replay()`) | so the rest of the test suite and CLIs run with no browser installed |
| `chromium.launch(proxy={"server": zap_proxy})` | routes ALL browser traffic through the ZAP daemon — this is what makes ZAP observe it |
| `headless=True` (default; `--headed` to override) | headless for automation/CI; headed for debugging |
| `new_context(ignore_https_errors=True)` | ZAP is a MITM proxy; its interception cert isn't trusted by Chromium, so TLS errors must be ignored (harmless for the local pilot; Juice Shop is HTTP anyway) |
| `page.route("**/*", guard.route_handler)` | intercept every request in-browser and apply the scope guard **before** it reaches the proxy (safety layer 2) |
| `sync_playwright` (not async) | simpler to reason about for a linear hand-authored flow |

## 4. How the flow uses Playwright (`security/dast/juice-shop/flow.py`)

The flow exposes `run(page, base_url) -> dict`. Playwright surface it touches:

| API | Use |
|-----|-----|
| `page.goto(url, wait_until="networkidle")` | navigate to `#/`, `#/login`, `#/basket`; wait for XHR to settle |
| `page.locator(sel)` + `.click()` | dismiss the welcome dialog / cookie banner (best-effort) |
| `page.fill("#email" / "#password", ...)` | type credentials into the login form |
| `page.click("#loginButton")` | submit the form |
| `page.wait_for_function("() => !!localStorage.getItem('token')")` | confirm auth success (JWT stored) |
| `page.evaluate("() => localStorage.getItem('token')")` | read the token back out |
| `page.request.post/get(...)` | register the user + `whoami` via the API through the same context/proxy |

**page.route vs page.request — an important nuance.** `page.route` intercepts *browser* traffic
(navigations, the SPA's `fetch`/XHR). It does **not** intercept `page.request.*`
(APIRequestContext) calls — those still go through the context proxy (so ZAP sees them) but
bypass the scope guard. That's why the flow also *navigates* to an authenticated view
(`#/basket`): the SPA's own authenticated XHR then flows through **both** the guard and the
proxy, giving genuine guard-enforced, ZAP-observed authenticated traffic. Register/`whoami`
via `page.request` are setup/verification calls to an already in-scope host.

## 5. The proxy topology (why `juice:3000`, not `localhost:3000`)

```
Chromium (host) ──HTTP proxy──▶ ZAP daemon (container :8080) ──▶ Juice Shop (container juice:3000)
```

When a browser uses an HTTP proxy, it sends the **full URL to the proxy** and the **proxy does
the DNS resolution**. So the browser never resolves the target itself — ZAP does. Because ZAP
runs in a container on the `dast` docker network:

- `http://juice:3000` → ZAP resolves `juice` on the docker network → reaches Juice Shop ✅
- `http://localhost:3000` → ZAP resolves `localhost` to **its own container** → fails ❌

Hence `--base-url http://juice:3000` and the app scope
(`security/dast/juice-shop/scope.json`) allow-lists **`juice`** (decision **D7** in
`decisions_and_known_issues.md`). Step 6 (containerizing browser + ZAP + target together) will
unify this back to `localhost`.

## 6. Running it

```bash
# containers up first (see reproducing_the_sample.md / runner_design.md)
docker run -d --name juice --network dast -p 3000:3000 bkimminich/juice-shop
docker run -d --name zap  --network dast -p 8080:8080 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true

python -m runner.replay \
  --scope security/dast/juice-shop/scope.json \
  --flow  security/dast/juice-shop/flow.py \
  --base-url http://juice:3000 --zap-proxy http://localhost:8080
# add --headed to watch the browser
```

Verify ZAP saw authenticated traffic:
```bash
curl -s "http://localhost:8080/JSON/search/view/messagesByRequestRegex/?regex=Authorization:%20Bearer" \
  | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["messagesByRequestRegex"]),"authenticated requests")'
```

## 7. Gotchas we actually hit

| Symptom | Cause | Fix |
|---------|-------|-----|
| `net::ERR_FAILED` on the first `goto` | scope guard aborted an out-of-allow-list host | expected when `--base-url` host isn't allow-listed; use `juice` (D7) |
| Nothing reachable via `localhost:3000` through the proxy | ZAP resolves `localhost` to its own container | navigate to `juice:3000`; the proxy resolves it (§5) |
| TLS/cert errors under the proxy | ZAP MITM cert not trusted | `new_context(ignore_https_errors=True)` |
| Login form clicks do nothing | welcome dialog / cookie banner overlay | dismiss banners first (best-effort locators) |
| Flaky "is user logged in?" | racing the SPA | assert on `localStorage.token` via `wait_for_function`, not on UI text |
| Chromium missing in a fresh env | `pip install` doesn't fetch the browser | run `playwright install chromium` separately |

## 8. Testing stance

The browser path is **live-validated**, not unit-tested (a real browser + ZAP + Juice Shop is
the only honest test). Only the pure `load_flow` helper has unit tests
(`tests/test_replay.py`). The scope guard that Playwright feeds is fully unit-tested with fake
route objects (`tests/test_scope_guard.py`). See `validation_and_testing.md` for the split.

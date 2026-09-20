# Phase 2 — Complete Step-by-Step Demo Runbook (macOS + Windows)

This is the **operator's runbook** for the whole Phase 2 demo: every window to open, every
command to run, every click, what appears on screen, and what to say — in order. It merges the
Phase 2 script (`dast_poc_phase2_demo_script.md`, which has the talking points and Q&A) with
the Playwright screen-recording runbook (`dast_poc_playwright_demo_runbook.md`) and works on
**both** demo machines: the **macOS laptop** (Docker Desktop, `$PY`) and the
**Windows workstation** (Git Bash + Podman in WSL, `.venv/Scripts/python`, images via the
Nationwide Trusted Registry). Every command below is bash — on Windows run them in **Git Bash
(MINGW64), never PowerShell or cmd**.

**Story to land:** Phase 1 proved the scanner is safe. Phase 2 proves (a) the `flow.py` that
drives it can be *recorded, explored and generated* — with an LLM that only ever emits data,
never code, and that widens coverage beyond what a human walked — and (b) findings flow
deterministically out of our JSON into SARIF and GitHub's Security tab.

**Total on-stage time:** ~22–26 min (the live scan in Part G is ~3–4 min of that; Part D2 adds ~3).

**Verification status:** the whole chain in this runbook (§1.3 health checks → record through ZAP →
seed → explore with Claude driving → generate on the LLM path → idempotency → validate live
replay → runner gate → SARIF) was executed end-to-end on the mac on 2026-09-19 with the
commands exactly as written; every SEE block shows that run's output. Windows-specific lines come from the day-1 runbook's Podman appendix and have not been
re-run there — do the §1 pre-flight on the Windows box the day before.

Legend used below:
**OPEN** = a window/tab/file to have on screen · **RUN** = type this in the named Terminal ·
**CLICK** = a mouse action · **SEE** = what success looks like · **SAY** = the talking line.

---

## Platform card — paste this FIRST in every terminal you open

The commands in this runbook use three shell variables so the same line works on both
machines. Paste the block for your OS as the **first thing in Terminal A and Terminal B**
(they are per-shell; a new tab needs it again).

**macOS (Docker Desktop):**
```bash
cd /Users/codyyang/Dast-Scanning-Tool
PY=.venv/bin/python
CT=docker                                   # container tool
JUICE_IMG=bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e
ZAP_IMG=zaproxy/zap-stable@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef
```

**Windows (Git Bash + Podman):**
```bash
cd /c/Users/yangq4/playground/Warbler-Tech/Dast-Scanning-Tool     # adjust if your checkout differs
PY=.venv/Scripts/python
CT=podman
JUICE_IMG=ntr.nwie.net/docker.io/bkimminich/juice-shop           # NTR mirror (day-1 runbook, Appendix A)
ZAP_IMG=ntr.nwie.net/docker.io/zaproxy/zap-stable
```

| Differs by OS | macOS | Windows |
|---|---|---|
| Container runtime | Docker Desktop (`open -a Docker`) | Podman machine (`podman machine start`); corporate proxy fix in `dast_poc_day1_runbook.md` App. A2 |
| Python | `.venv/bin/python` (3.12 via Homebrew) | `.venv/Scripts/python` (3.11+; create with `py -3.12 -m venv .venv` if missing) |
| Images | Docker Hub, pinned by digest (`versions.lock`) | `ntr.nwie.net/docker.io/...` by tag (`podman login ntr.nwie.net` first) |
| Switch windows | ⌘Tab | Alt+Tab |
| VS Code Markdown preview | ⇧⌘V | Ctrl+Shift+V |
| Screen recording | ⌘⇧5 (built-in), stop with ⌘⌃Esc | Win+Alt+R (Xbox Game Bar) or Snipping Tool → *Record* (Win+Shift+S → Record); stop with Win+Alt+R again |
| Terminal font | Terminal/iTerm → ⌘+ to enlarge | Git Bash window → right-click title bar → Options → Text |
| Chromium headed window | appears center-screen | same; if it doesn't, check `$PY -m playwright install chromium` ran on **this** machine |

---

## 0. The day before — one-time environment facts (macOS rows verified 2026-09-19; Windows rows from the day-1 runbook)

| Fact | Detail | Why it matters |
|---|---|---|
| Python | `$PY` = the repo venv (mac: 3.12.14; win: 3.11+) with playwright 1.62.0, anthropic, jsonschema, pytest | bare `python`/`python3` is the wrong interpreter on both machines (mac ships 3.9; Windows may pick the Store stub) — **always** use `$PY` |
| Tests | `$PY -m pytest -q` → **213 passed** in <1s | your fallback evidence (§9) |
| Container tool (mac) | Docker Desktop is at `/Applications/Docker.app`, **but** `/usr/local/bin/docker` is a broken symlink (→ `/Volumes/Docker 1/…`), so `docker` is **not on PATH** in a fresh shell | fix once, see below |
| Container tool (win) | Podman runs in a WSL VM; the VM ships a dead `127.0.0.1:8888` proxy that breaks pulls | one-time fix: `dast_poc_day1_runbook.md` Appendix A2; pull images the day before |
| Compose file | `compose.yaml` (project `ssd-dast-poc`) does **not publish ports** for `juice`/`zap` — it's for the all-in-container runner | for a host-side demo you need `localhost:3000` / `localhost:8080`, so start juice+zap with `$CT run -p …` (README "Option B"), not compose |
| GitHub | mac: `gh` is logged in as `CodyYang2016`; remote = `github.com/CodyYang2016/Dast-Scanning-Tool`; Security tab already has 38 alerts from the fixture upload on 2026-09-12. win: run `gh auth status` the day before | live SARIF upload works from the mac; on Windows only if `gh` is authenticated and the enterprise repo has code scanning enabled |
| LLM key | `ANTHROPIC_API_KEY` is **not** set in a fresh shell; keep it in gitignored `.secrets/anthropic.key` | this demo runs the LLM live (Part D2 + §5); export per §1.7 in both terminals |
| Old script drift | The Phase 2 script mentions `podman-compose`, `compose.demo.yaml`, `cleanup_demo_ports.sh`, `demo_full_scan.sh`, `/c/Users/yangq4/…` — **none of these exist here** | ignore them; this runbook has the real commands |

### macOS only — fix the `docker` command once

```bash
sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker
docker --version        # should print a client version now
```

(If you'd rather not touch `/usr/local/bin`, put `alias docker=/Applications/Docker.app/Contents/Resources/bin/docker` in `~/.zshrc`.)

### Windows only — Podman + venv once

```bash
podman machine start                        # then: podman ps must answer
podman login ntr.nwie.net -u <your-nwie-userid>
py -3.12 -m venv .venv 2>/dev/null || python -m venv .venv      # skip if .venv exists
.venv/Scripts/python -m pip install -r requirements-dev.txt
.venv/Scripts/python -m playwright install chromium
```

If a pull fails with `proxyconnect tcp: dial tcp 127.0.0.1:8888`, do the one-time WSL proxy
fix in `dast_poc_day1_runbook.md` Appendix A2 — it costs hours if discovered on demo day.

### Both — pull images ahead of time (slow on a cold network — don't do this live)

```bash
$CT pull $JUICE_IMG
$CT pull $ZAP_IMG
```

On macOS these are the digests pinned in `versions.lock` (NFR-1); on Windows the NTR mirror
serves the same upstream images by tag.

---

## 1. T-15 minutes — pre-flight (off camera)

### 1.1 Start the container runtime

**macOS — OPEN Docker Desktop:** **CLICK** Launchpad → **Docker** (or `open -a Docker`). Wait
for the whale icon in the menu bar to stop animating. If Docker Desktop shows an **error
dialog** on launch (it did once on 2026-09-18), click **Restart** / quit and relaunch it.

**Windows — RUN** `podman machine start` in Git Bash (`podman machine list` shows `Currently
running`).

Don't proceed until this answers:
```bash
$CT ps      # must NOT say "Cannot connect to the Docker daemon" / "unable to connect to Podman"
```

**If the containers already exist from a previous session** (`$CT ps -a` shows `juice` and `zap`
on network `dast`, Exited), you can just `$CT start juice zap` and skip to 1.3 — that's what was
done for the 2026-09-19 verification run.

### 1.2 RUN — start Juice Shop + ZAP with ports published (Terminal A)

```bash
# (platform card already pasted)
# clean slate: remove anything left from a previous session
$CT rm -f juice zap 2>/dev/null; $CT network rm dast 2>/dev/null

$CT network create dast
$CT run -d --name juice --network dast -p 3000:3000 $JUICE_IMG
$CT run -d --name zap --network dast -p 8080:8080 $ZAP_IMG \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true
```

Keep the single quotes around `'api.addrs.addr.name=.*'` — Git Bash globs `.*` otherwise, and
without that flag ZAP answers every host call with `curl: (52) Empty reply`.

Why these exact names: `runner`, `validate`, and the app `scope.json` all address the target as
**`juice:3000`** — the container name is the DNS name ZAP resolves on the `dast` network (D7).

### 1.3 RUN — confirm all three health checks (want `200 200 200`)

ZAP takes ~20–40 s to come up. Re-run until all three are 200:

```bash
curl -s -o /dev/null -w "juice-from-host %{http_code}\n" http://localhost:3000
curl -s -o /dev/null -w "zap-api        %{http_code}\n" http://localhost:8080/JSON/core/view/version/
$CT exec zap curl -sS -m10 -o /dev/null -w "juice-from-zap %{http_code}\n" http://juice:3000/
```

The third one is the important one: it proves ZAP can reach `juice` on the docker network,
which is exactly what `wait_ready()` in `runner/main.py` checks before scanning.

### 1.4 RUN — venv + Chromium + tests

```bash
$PY -c "from playwright.sync_api import sync_playwright as s; b=s().start().chromium.launch(); b.close(); print('chromium ok')"
$PY -m pytest -q          # SEE: 213 passed
```

### 1.5 RUN — clean scratch dir + pick demo credentials

```bash
rm -rf out/phase2-demo && mkdir -p out/phase2-demo

# One identity for the WHOLE demo. record registers this user; validate + runner only LOG IN
# (the generated flow.py has no register step), so never change these mid-demo.
export AUTH_EMAIL="dast-demo-$(date +%H%M%S)@juice-sh.op"
export AUTH_PASSWORD="Dast-Demo-passw0rd!"
echo "$AUTH_EMAIL"                      # note it down; you'll re-export it in Terminal B
```

**Do NOT** use `dast-poc@juice-sh.op` + `Passw0rd!` from the old script: that email already
exists in Juice Shop with a *different* password (the hand-authored Phase 1 flow registers it
with `Dast-POC-passw0rd!`), so login times out at `wait_for_function` — the #1 thing that sinks
a live take. A fresh timestamped email sidesteps it.

### 1.6 RUN — warm-up headed record (throwaway, so Chromium is snappy on camera)

```bash
$PY -m authoring.record --app-id juice-shop \
  --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --out-dir out/phase2-demo/warmup --headed --slow-mo 300
```

**SEE** a Chromium window open, log in, land on the basket, close; Terminal prints
`recorded: 6 interactions, 22–24 api calls, hosts=['juice'] -> out/phase2-demo/warmup/trace.json` (24 on a freshly started Juice Shop, 22 on a warm one).

> **`hosts=['juice']` is required.** If you record with `--base-url http://localhost:3000` and
> no `--zap-proxy` (as the Playwright-only runbook does), the trace says `hosts=['localhost']`,
> `generate` seeds `scope.json`'s allow-list with `localhost`, and then `validate`/`runner`
> (which go through ZAP to `juice:3000`) get **blocked by the scope guard**. The Phase 2 demo
> must record *through ZAP* so the generated scope matches the runner topology.

### 1.7 LLM key (this demo runs the LLM live in Part D2 `explore` and Part E `generate`)

```bash
export ANTHROPIC_API_KEY="$(cat .secrets/anthropic.key)"     # .secrets/ is gitignored; never paste the key on camera
$PY -c "import anthropic,os; print(anthropic.Anthropic().models.list(limit=1).data[0].id)"   # SEE: a model id => key + network OK
```

Do this in **both** terminals. Then do a full dry run of D2 → E → F **now** (≈3 min) so a bad
network or a rate limit is discovered off camera. If the key/network is dead on the day, every
LLM command below has a `--no-llm` twin that produces the same artifact shape — the demo
degrades, it doesn't stop (see §9).

### 1.8 RUN — seed the authenticated session once (needed by Part D2)

```bash
$PY -m authoring.seed --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --assisted --storage-state .secrets/storageState.json
```
**SEE** `seeded session saved -> .secrets/storageState.json` (~2 s, headless). This is the
"human logs in once" step; `--assisted` auto-fills the Juice Shop form with `AUTH_EMAIL` /
`AUTH_PASSWORD`. It must be seeded **through ZAP at `juice:3000`** — `storageState` is keyed by
origin, so a session seeded at `localhost:3000` is invisible to a scan of `juice:3000`.
You can also do this on camera (§D2.1) — it's a nice visual — but seeding here means Part D2
can't be sunk by a login hiccup.

---

## 2. Screen layout — what to have open

| Window | Where | Used in |
|---|---|---|
| **Terminal A** (mac: Terminal/iTerm; win: **Git Bash**; large font, platform card pasted, `AUTH_EMAIL`/`AUTH_PASSWORD` exported) | left half | the pipeline: record → generate → validate → runner |
| **Terminal B** (same kind of shell, platform card pasted, same two exports) | right half, or a second tab | inspection: `cat`/`diff`/`curl` ZAP, fixture pipeline |
| **Browser tab 1** — the Phase 2 script rendered with its Mermaid diagrams: open `docs/dast_poc_phase2_demo_script.md` in VS Code and press **⇧⌘V** (mac) / **Ctrl+Shift+V** (win) for Markdown preview, or use `https://github.com/CodyYang2016/Dast-Scanning-Tool/blob/main/docs/dast_poc_phase2_demo_script.md` | full-screen for Part A, then hidden | Part A |
| **Browser tab 2** — `https://github.com/CodyYang2016/Dast-Scanning-Tool/security/code-scanning` | hidden until Part B / H | Part B, H |
| **Browser tab 3** — `http://localhost:3000` (Juice Shop, just to show "the target") | shown once, then **closed** so it isn't confused with Playwright's window | Part D opener |
| **Playwright's own Chromium window** | pops up center-screen during `record --headed`; **do not open Chrome yourself for this** | Part D |

If screen-recording — **mac:** **⌘⇧5** → Options → Save to `out/pw-demo/recordings`
(gitignored), Show Mouse Clicks on → *Record Selected Portion* around Terminal A + the center of
the screen → **Record**; stop with **⌘⌃Esc**. **win:** **Win+Alt+R** starts/stops an Xbox Game
Bar recording of the active window (saved to `Videos\Captures`), or Snipping Tool → *Record* →
drag a region → Start. Turn the microphone on in either if you narrate live.

Export the credentials in Terminal B too (so the inspection commands and §6a work there):

```bash
# (platform card already pasted)
export AUTH_EMAIL="<the email you noted in 1.5>" AUTH_PASSWORD="Dast-Demo-passw0rd!"
```

---

## Part A — Big picture (2 min, no commands)

**OPEN** Browser tab 1 (the rendered Phase 2 script). Scroll to the two Mermaid diagrams under
"Big picture".

**SAY** (diagram 1 — the three phases): "Phase 1 proved the runner can safely authenticate,
stay in scope, and detect a real finding — but its `flow.py` was hand-typed. Today's question:
can we replace that hand-authored file with something recorded and generated, get findings into
SARIF in GitHub's Security tab, and do it without an LLM ever weakening the Phase 1 guarantees?
The answer has to be no-by-construction, not by promise."

**SAY** (diagram 2 — the chain): "The yellow boxes are the only new risk surface — the LLM.
Everything downstream of `validate` — runner, scope guard, normalizer, SARIF — is the exact,
unchanged Phase 1 code. The LLM only emits **data**: a schema-constrained JSON journey plan.
A deterministic renderer turns that into `flow.py`. If the model is unavailable or invalid, a
deterministic fallback builds the plan straight from the recorded trace."

Then switch to the Terminals (⌘Tab / Alt+Tab).

---

## Part B — Deterministic results pipeline first: fixture → SARIF → GitHub (3 min, Terminal B)

Deliberate order: prove the downstream half against a committed fixture *before* anything LLM.

**RUN**
```bash
sed -n '1,40p' contracts/sample_zap_output.json
```
**SAY** "A real, committed ZAP fixture — 38 alerts: 1 High (SQL injection), 14 Medium, 11 Low,
12 Informational. The results pipeline was built and tested against this file before a single
live scan ran."

**RUN**
```bash
$PY -m detections.normalizer contracts/sample_zap_output.json --app-id juice-shop \
  --scan-id demo-fixture-1 -o out/phase2-demo/records.json
head -30 out/phase2-demo/records.json
```
**SEE** a JSON array of records with `rule_id`, `severity`, `endpoint_pattern`, `fingerprint`.
**SAY** "Each record has a rule id, severity, endpoint, parameter, and a stable fingerprint —
the same shape whether alerts came from this fixture or a live scan."

**RUN**
```bash
$PY -m detections.sarif_export out/phase2-demo/records.json --app-id juice-shop \
  --driver-version "ZAP 2.17.0" -o out/phase2-demo/results.sarif
sed -n '1,25p' out/phase2-demo/results.sarif
```
**SEE** `"version": "2.1.0"`, `"$schema": …sarif-schema-2.1.0…`, a `tool.driver` block.
**SAY** "SARIF 2.1.0 — the standard GitHub Code Scanning consumes."

**Upload — choose one:**

- *Narrate only (safest):* show the command, don't run it:
  ```bash
  $PY -m detections.github_upload out/phase2-demo/results.sarif \
    --owner CodyYang2016 --repo Dast-Scanning-Tool --ref refs/heads/main
  ```
  **SAY** "This is a one-way door — it publishes to a real Security tab — so today I'm showing
  the already-uploaded result rather than re-uploading."
- *Live (this repo, `gh` is authenticated):* run the command above. It uses `git rev-parse
  HEAD` as the commit, which **must already be pushed** (`git status` clean, `git push` done).
  **SEE** `uploaded: id=…` and `status url: …`. Processing takes ~30–60 s.

**OPEN** Browser tab 2 (Security tab). **CLICK** *Code scanning* in the left rail if not
already there. **SEE** the alert list; **CLICK** the **High** "SQL Injection" alert to show
severity/CWE and the endpoint as location.
**SAY** "DAST locations are endpoints, not source lines — expected. `partialFingerprints` is
what lets GitHub track the same alert across uploads, which is what makes Phase 3's lifecycle
diff line up with the Security tab."

Switch back to the Terminals.

---

## Part C — The safety architecture (1 min, Terminal B)

**RUN**
```bash
sed -n '1,30p' docs/junior_engineer/authoring_clis_design.md
```
**SAY** "The one design decision that matters most today: `generate` asks the LLM for a
constrained **JSON journey plan**, not Python. The plan is validated against
`journey.schema.json`; only then does deterministic code render `flow.py`, which is
AST-compiled before use. A malformed plan fails loudly here, not inside a live browser."

**RUN**
```bash
cat contracts/journey.schema.json
```
**SAY** "Notice what's *not* here: no code, no shell, no file paths. A login block of selectors
plus a list of `goto` / `click` / `api_get` steps — that's the entire vocabulary the model may
use. `additionalProperties: false` everywhere."

**RUN**
```bash
cat contracts/action.schema.json
```
**SAY** "And this is the *other* place the model speaks — one action at a time during
exploration, which you'll see in Part D2. Five verbs, a path or a selector, a reason, a
confidence. Same rule: data in, code decides. Both contracts are frozen files in `contracts/`."

---

## Part D — `record`: a real browser captures the trace (3 min, Terminal A + Playwright window)

*(Optional 10-second opener)* **OPEN** Browser tab 3 (`http://localhost:3000`), **SAY** "Here's
the target — OWASP Juice Shop, an Angular SPA," then **close that tab**.

**RUN** (Terminal A)
```bash
rm -rf out/phase2-demo/trace

$PY -m authoring.record \
  --app-id juice-shop \
  --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --out-dir out/phase2-demo/trace \
  --headed --slow-mo 700
```

**SEE** (in order, ~15–20 s): a Chromium window opens → Juice Shop landing page (welcome
banner) → navigates to **#/login** → **email/password fields fill themselves** → Login click →
lands on **#/basket** → window closes. Terminal prints:
```
recorded: 6 interactions, 22–24 api calls, hosts=['juice'] -> out/phase2-demo/trace/trace.json
```

**SAY** (while it runs) "This is the same Playwright runtime the scanner uses, proxied through
ZAP exactly like the runner. It registers a test user, logs in via the real form, and visits an
authenticated page. Every navigation, form field, and `/rest/`·`/api/` XHR is captured as a raw
event; `build_trace` — a pure, unit-tested function — turns those into a schema-valid trace.
`--slow-mo 700` only slows the browser so you can watch; it doesn't change the trace."

**RUN**
```bash
ls -1 out/phase2-demo/trace/                       # SEE: index.json  trace.json
$PY -m json.tool out/phase2-demo/trace/trace.json | sed -n '1,40p'
grep -n -i "password" out/phase2-demo/trace/trace.json          # SEE: only "#password" / "field": "password"
grep -c "$AUTH_PASSWORD" out/phase2-demo/trace/trace.json || echo "password VALUE not in trace"
```
**SAY** "Hosts, page index, interactions, forms, API calls. The word `password` appears only as
a **field name** and a selector — the value never does, and there's no token. Credentials came
from environment variables; the trace only knows what to fill, not what with."

---

## Part D2 — `seed` + `explore`: the LLM widens the authenticated surface (3 min, Terminal A + Playwright window)

Part D was the **floor** — what a human walked. This is the KI4 fix: from a seeded session the
LLM drives the browser itself, one validated JSON action at a time, and emits the **same
`trace.json`** `record` does — so everything after this Part is unchanged, just fed a wider
trace.

### D2.1 (optional on camera, ~5 s) — the human seed

If you seeded in §1.8 you can skip this, or re-run it headed for the visual:
```bash
$PY -m authoring.seed --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --assisted --headed --storage-state .secrets/storageState.json
```
**SEE** Chromium opens on the login page, fills it, closes; `seeded session saved -> …`.
**SAY** "On a real target this is where a person handles SSO/MFA/CAPTCHA once. Playwright saves
the resulting session — cookies and tokens — to a gitignored file. On Juice Shop the login is
trivial, so the win here is *breadth*, not auth; the seeding value shows on enterprise apps."

### D2.2 — the exploration loop (the recorded moment)

**RUN** (Terminal A)
```bash
cat security/dast/juice-shop/seed.json         # the whole human input: 5 seed routes + a deny-list + a page budget

$PY -m authoring.explore \
  --seed  security/dast/juice-shop/seed.json \
  --scope security/dast/juice-shop/scope.json \
  --zap-proxy http://localhost:8080 \
  --out-dir out/phase2-demo/explore \
  --max-pages 12 --headed --slow-mo 500
```
**SEE** a Chromium window opens **already logged in** (no login form — the seeded session), lands
on the three seed routes, then hops through routes *it* picked — in the verified run Claude went
straight for the authenticated API surface (`/rest/order-history`, `/rest/admin/application-
configuration`, `/rest/user/whoami`, `/rest/continue-code`, `/rest/basket/…`, …) rendered as raw
JSON pages — and closes. ~30 s with the model; Terminal prints:
```json
{ "app_id": "juice-shop", "pages": 12, "api_calls": 27, "forms": 0, "hosts": ["juice"],
  "requests_seen": 45, "blocked": 0, "out_dir": "out/phase2-demo/explore" }
```
(Verified 2026-09-19 with Claude proposing every step, 0 rejections, 0 fallbacks. `record` gave
3 pages / 22 API calls from the same app. **Be straight if asked:** the `--no-llm` greedy
proposer got 15 / 30 on the same budget — it walks unvisited UI links first and each SPA page
fires fresh XHR, whereas Claude went straight for the `/rest/…` endpoints it had already seen.
On this pilot the win is *explore vs. the human walk* (both modes ~25% more detections than
`record`), not *LLM vs. the deterministic crawler*; the LLM's edge is prioritization on apps
too big to crawl greedily, which Juice Shop isn't. The page set differs run to run with the
model — expected, see the SAY below. Lines on stderr like `explore: LLM action rejected (matches deny-list …): visit_api
GET /rest/admin/…` are the **policy doing its job** — point at them, don't apologise for them.
`explore: LLM path failed … using fallback` means the loop continued deterministically; say so.)

**SAY** (while it runs) "Every step: Playwright snapshots the page — links, forms, API calls
seen — that snapshot is **redacted** (`runner/redact.py`) before it goes anywhere, then Claude
is asked for exactly *one* next action as JSON against `action.schema.json`: follow a link,
visit an API route, submit a form, or stop. Deterministic code then checks that action against
the scope allow-list and the action policy — POST/PUT/PATCH/DELETE are denied by default, the
deny-list (`logout`, `delete-account`, `purchase`…) is a code check, and a path that embeds an
off-scope URL like `/redirect?to=github.com` is refused before it's ever clicked. Only then does
the browser act. The model's own 'this is non-destructive' opinion is never trusted. `blocked: 0`
means the request-boundary guard — still on during discovery — never saw a request leave scope."

**RUN** (Terminal B) — the comparison that makes the point:
```bash
echo "record:"; $PY -m json.tool out/phase2-demo/trace/index.json
echo "explore:"; $PY -m json.tool out/phase2-demo/explore/index.json
grep -c '"url"' out/phase2-demo/trace/trace.json out/phase2-demo/explore/trace.json
```
**SAY** "Same app, same session, same output format — four times the pages and more API routes
than the human walk, with zero out-of-scope requests. And per design decision R1 the LLM only
runs *here*, at authoring time: this trace is reviewed and committed, and the monitoring scans
replay the committed bundle deterministically — which is what keeps Phase 3's lifecycle diff
honest."

From here on the demo uses **`out/phase2-demo/explore/trace.json`**. (To run Parts E–H on the
Part D trace instead, substitute `out/phase2-demo/trace/trace.json` — everything else is
identical.)

---

## Part E — `generate`: trace → plan → `flow.py` + scan config (3 min, Terminal A/B)

### 5. LLM path (live) — Claude turns the explored trace into a journey plan

**RUN** (Terminal A)
```bash
$PY -m authoring.generate --trace out/phase2-demo/explore/trace.json \
  --out-dir out/phase2-demo/gen
```
**SEE** (~6 s)
```json
{ "plan_source": "llm", "journey_steps": 12, "out_dir": "out/phase2-demo/gen" }
```
(Verified 2026-09-19: the plan was 3 `goto` + 9 `api_get`, `validate` passed with live replay.)
**SAY** "Claude gets the redacted trace plus `journey.schema.json` and returns a plan: a login
block of selectors and an ordered list of `goto` / `api_get` steps. It's validated against the
schema, then a deterministic renderer writes `flow.py` and AST-compiles it. If the model's
output doesn't validate — or the API is down — `generate` warns on stderr and falls back to a
deterministic plan built straight from the trace, so this step never blocks on the model."
(If you see `generate: LLM path failed (…); using deterministic fallback` and
`"plan_source": "fallback"`, that *is* the resilience story — say so and keep going.)

**RUN** (Terminal B) — show the plan and all six artifacts:
```bash
cat out/phase2-demo/gen/journey.json
ls out/phase2-demo/gen/            # SEE: auth.json flow.py journey.json lock manifest.json scope.json zap-policy.yaml
cat out/phase2-demo/gen/scope.json
cat out/phase2-demo/gen/auth.json
cat out/phase2-demo/gen/zap-policy.yaml
cat out/phase2-demo/gen/manifest.json
```
**SEE** `scope.json` → `"fqdn_allow_list": ["juice"]`, `"environment_class": "dev"`;
`auth.json` → only `"email_env": "AUTH_EMAIL"`, `"password_env": "AUTH_PASSWORD"`.
**SAY** "Six artifacts from one trace: the plan, the rendered `flow.py`, a `scope.json` whose
allow-list is seeded from hosts *actually seen* in the trace, `auth.json` holding only env-var
**names**, a ZAP policy, a manifest and a lock."

**SAY (known gap — say it, don't hide it):** "Only `flow.py` and `scope.json` drive the scan
today. `runner/scan.py`'s `configure_policy()` takes a time budget only — it doesn't read
`zap-policy.yaml` yet. `auth.json`, `manifest.json`, `lock` are scaffolding for a future runner
change. Tracked gap, not a demo simplification."

**RUN**
```bash
cat out/phase2-demo/gen/flow.py
```
**SAY** "Same `run(page, base_url)` contract as the hand-authored Phase 1 flow — but every line
was templated from the plan. Credentials are read from env at line 1 of `run`; nothing is
baked in."

### 5a. Idempotency proof (FR-G4) — 20 seconds, deterministic path

**RUN** (Terminal A)
```bash
$PY -m authoring.generate --trace out/phase2-demo/explore/trace.json --out-dir out/phase2-demo/gen-det  --no-llm
$PY -m authoring.generate --trace out/phase2-demo/explore/trace.json --out-dir out/phase2-demo/gen-det2 --no-llm
diff out/phase2-demo/gen-det/flow.py out/phase2-demo/gen-det2/flow.py && echo "IDENTICAL"
```
**SEE** no diff output, then `IDENTICAL`.
**SAY** "Idempotency lives in the deterministic half: same plan → byte-identical `flow.py`, and
the fallback planner is itself deterministic — same trace, two runs, identical file. The LLM
plan isn't re-generated on every scan; it's produced once at authoring time, reviewed, and
committed (R1). That's what makes Phase 3's lifecycle diffing trustworthy."

(Anticipate: "so two LLM runs could give different plans?" — Yes, and it doesn't matter: the
scan replays the *committed* bundle, never a fresh model call. Same trace → same fallback plan
is the guarantee; the model is an authoring aid, not a runtime dependency.)

---

## Part F — `validate`: allow-list + live auth replay (2 min, Terminal A)

The replay here is **headless** — no browser window will appear; that's expected.

**RUN** (Terminal A — `AUTH_EMAIL`/`AUTH_PASSWORD` must be the same ones `record` used)
```bash
$PY -m authoring.validate \
  --plan  out/phase2-demo/gen/journey.json \
  --scope out/phase2-demo/gen/scope.json \
  --flow  out/phase2-demo/gen/flow.py \
  --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --report out/phase2-demo/validation-report.json; echo "exit=$?"
```
**SEE**
```json
{ "checks": [ {"name":"allowlist","passed":true,"detail":"all hosts in allow-list"},
              {"name":"auth","passed":true,"detail":"authenticated=True"} ],
  "passed": true }
exit=0
```
**SAY** "Two checks. `check_allowlist` — pure, no network — confirms every host the plan touches
is covered by the generated scope. Then a **live replay**: the generated `flow.py` is executed
through Playwright, through ZAP, against the running app, and we confirm auth succeeded. Exit
code mirrors the report — a bad bundle never silently reaches the scanner (FR-V3)."

> Why `http://juice:3000` here but the record step also used it: anything proxied through ZAP
> must name the host **as ZAP resolves it**. `localhost` from inside the ZAP container is ZAP
> itself.

### 6a. Fail-closed on an out-of-scope plan (30 s, Terminal B, no browser)

**RUN**
```bash
$PY - <<'EOF'
import json
plan = json.load(open('out/phase2-demo/gen/journey.json'))
plan['journey'].append({'action': 'goto', 'target': 'http://evil.example.com/'})
json.dump(plan, open('out/phase2-demo/bad_plan.json', 'w'), indent=2)
EOF

$PY -m authoring.validate --plan out/phase2-demo/bad_plan.json \
  --scope out/phase2-demo/gen/scope.json --no-replay \
  --report out/phase2-demo/bad-validation-report.json; echo "exit=$?"
```
**SEE** `"passed": false`, `"detail": "out-of-scope hosts: ['evil.example.com']"`, `exit=2`.
**SAY** "Same scope, but the plan now names a host never seen in the trace. The allow-list check
fails immediately, `--no-replay` skips the browser, non-zero exit — the Phase 1 fail-closed
posture, one stage earlier."

---

## Part G — The unchanged Phase 1 runner, fed the generated bundle (~4–5 min, Terminal A)

**RUN** (Terminal A)
```bash
time $PY -m runner.main \
  --flow  out/phase2-demo/gen/flow.py \
  --scope out/phase2-demo/gen/scope.json \
  --base-url http://juice:3000 --zap-api http://localhost:8080 --zap-proxy http://localhost:8080 \
  --records-out out/phase2-demo/live-records.json \
  --coverage-out out/phase2-demo/live-coverage.json; echo "exit=$?"
```
**SAY** (as it starts) "Nothing in `runner/`, `scope_guard.py`, or the normalizer changed. Same
preflight, same guard, same bounded scan — just a generated `flow.py` and `scope.json` instead
of hand-authored ones. Preflight runs first, offline: it would abort here if the scope were
`prod` or had no allow-list, before any traffic."

**While the scan runs (~3–4 min; `--max-scan-min` defaults to 4)** — switch to **Terminal B**:

```bash
# 1) ZAP saw the *generated* flow authenticate: count Bearer requests
curl -s "http://localhost:8080/JSON/search/view/messagesByRequestRegex/?regex=Authorization:%20Bearer" \
  | $PY -c 'import sys,json;print(len(json.load(sys.stdin)["messagesByRequestRegex"]),"authenticated requests seen by ZAP")'

# 2) active-scan progress
curl -s "http://localhost:8080/JSON/ascan/view/scans/" | $PY -m json.tool

# 3) evidence is being captured next to the *generated* scope (redacted HAR)
ls -R out/phase2-demo/gen/evidence/
grep -A1 '"name": "Authorization"' out/phase2-demo/gen/evidence/*/active-scan.har | grep -c REDACTED
```
**SEE** `active-scan.har` (≈2.6 MB) and a count of redacted `Authorization` headers (>0).
**SAY** "Evidence lands under the app dir — here, next to the generated scope — and the HAR is
redacted at capture: auth headers, cookies, tokens, passwords." (Only a HAR here: the
*generated* flow doesn't take screenshots; the hand-authored Phase 1 flow does its own.)

Optionally show Phase-1 guardrails still bite (safe, offline, ~1 s each):
```bash
$PY - <<'EOF'
import json; s=json.load(open('out/phase2-demo/gen/scope.json')); s['environment_class']='prod'
json.dump(s, open('out/phase2-demo/prod_scope.json','w'))
EOF
$PY -m runner.main --flow out/phase2-demo/gen/flow.py \
  --scope out/phase2-demo/prod_scope.json --no-wait; echo "exit=$?"
```
**SEE** `RUNNER ABORT: …prod…`, `exit=2`, and **no** browser/ZAP traffic.

**Back in Terminal A, SEE** the gate:
```json
{ "scan_id": "2026…Z", "app_id": "juice-shop", "requests_seen": <n>, "blocked": 0,
  "gate": { "authenticated": true, "scope_ok": true, "has_high_or_medium": true,
            "detections": <hundreds+>, "passed": true } }
exit=0
```
(Verified on the mac 2026-09-19 with this exact command, three ways. **LLM end-to-end** —
Claude drove `explore` and authored the plan in `generate`: `requests_seen: 41, blocked: 0,
detections: 1490`, **2m54s**. Explore trace with the `--no-llm` proposer: `detections: 1581`,
2m32s. Part D **record** trace: `requests_seen: 37, blocked: 0, detections: 1214`, 2m39s.)
**SAY** "Same runner, same budget — the explored bundle surfaced 20–30% more detections than
the human walk, because it exercised more of the authenticated app. That's KI4 closing."

**SAY** "Authenticated, in scope, high/medium found, gate passed, exit 0 — the exact Phase 1
gate, driven by a generated bundle. That's the Week-2 checkpoint."

---

## Part H — Close the loop: live records → lifecycle diff → SARIF (→ GitHub) (2 min, Terminal A)

**RUN** — label this scan against the previous one, **coverage-aware**:
```bash
$PY -m detections.lifecycle_diff out/phase2-demo/live-records.json --app-id juice-shop \
  --state out/state.json --coverage out/phase2-demo/live-coverage.json \
  -o out/phase2-demo/live-labeled.json
$PY -c "import json,collections;print(collections.Counter(x['status'] for x in json.load(open('out/phase2-demo/live-labeled.json'))))"
```
**SEE** `Counter({'open': …, 'new': …, 'not_scanned': …})` — on the very first run everything is
`new`; on later runs the previous scan's findings that this journey did not reach come back as
`not_scanned`, never `resolved`. (`out/state.json` lives *outside* the per-take scratch dir on
purpose, so §10 resets don't erase the history. Delete it to start a clean lifecycle.)

**SAY** "This is the coverage-aware diff. `resolved` is only claimed when the finding's route was
scanned with its rule enabled and the finding is gone. If this run simply didn't reach a route —
a different exploration, a disabled rule — the finding is `not_scanned`, and it stays reported."

**RUN** — export from the *labeled* records:
```bash
$PY -m detections.sarif_export out/phase2-demo/live-labeled.json --app-id juice-shop \
  --driver-version "ZAP 2.17.0" -o out/phase2-demo/live-results.sarif
$PY -c "import json;s=json.load(open('out/phase2-demo/live-results.sarif'));print(len(s['runs'][0]['results']),'SARIF results')"
```
**SEE** a count = `open + new + not_scanned` (e.g. `1470 SARIF results` = 1351 open + 119
carried forward, verified 2026-09-19).
**SAY** "The export drops only `resolved` and carries `not_scanned` forward. That matters because
GitHub closes any alert missing from the newest upload as *fixed* — with no idea whether we
looked. Feeding it the coverage-aware set means the Security tab only ever closes what we
actually proved gone. `record → explore → generate → validate → runner → diff → SARIF`, end to
end; everything upstream of the runner was generated."

*Live upload* (one-way door, same caveat as Part B; HEAD must be pushed):
```bash
$PY -m detections.github_upload out/phase2-demo/live-results.sarif \
  --owner CodyYang2016 --repo Dast-Scanning-Tool --ref refs/heads/main
```
Then **OPEN** Browser tab 2 and **CLICK** refresh after ~60 s. **CLICK** *Closed* — anything there
is either a real fix or predates coverage-aware publishing.

> **Why this changed (2026-09-19, live):** two coverage-blind uploads in a row made GitHub mark
> 13 real findings on `/rest/continue-code` "fixed" — the second LLM exploration just hadn't
> visited that route. Same run also proved a `/rest/products/{id}` error-disclosure finding
> "fixed" for the same reason. The 24 alerts from those uploads are still *Closed* in the tab
> and will reopen the first time a scan covers those routes; everything since is coverage-aware.
> Use it in the demo: it's the concrete case for R2.

---

## Part I — Wrap-up (30 s, no commands)

- Results pipeline proven on a fixture **before** any live generation — external-integration
  risk retired early.
- `record → generate → validate` yields a bundle that satisfies the exact same contract as the
  hand-authored flow — the **unchanged runner** is the proof.
- `seed → explore` removes the human walk as the coverage ceiling (KI4): an LLM-driven loop
  found 3–4× the pages from five seed routes with zero out-of-scope requests — every action
  schema-checked and policy-checked by code before the browser moved, and only at authoring time
  (R1), so monitoring scans stay deterministic.
- The LLM only emits a schema-validated JSON **plan**; deterministic code renders and
  AST-checks `flow.py`. Fallback means zero hard dependency on the model.
- Idempotency shown live (§5a); fail-closed shown live (§6a + the `prod` abort).
- Next: Phase 3 — two-scan lifecycle (open/new/resolved), evidence hardening, final recording.

Q&A cheat-sheet: bottom of `docs/dast_poc_phase2_demo_script.md`.

---

## 9. If something breaks live — don't debug on stage

**SAY** "Let's not burn demo time on infra — here's the deterministic path verified earlier
today, and the suite that backs every piece." Then:

```bash
$PY -m pytest -q                          # 213 passed
sed -n '/## Verification/,/## Out of scope/p' docs/junior_engineer/authoring_clis_design.md
ls out/phase2-demo/warmup/                             # the trace you recorded in §1.6
```

Then, off camera, the usual fixes (§11).

---

## 10. Reset between takes / rehearsals

```bash
rm -rf out/phase2-demo/trace out/phase2-demo/explore out/phase2-demo/gen out/phase2-demo/gen-det* \
       out/phase2-demo/live-* out/phase2-demo/*report.json out/phase2-demo/bad_plan.json
export AUTH_EMAIL="dast-demo-$(date +%H%M%S)@juice-sh.op"      # fresh user => clean register beat
# re-export the same AUTH_EMAIL in Terminal B, then RE-SEED (the storageState belongs to the old user):
$PY -m authoring.seed --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --assisted --storage-state .secrets/storageState.json
```
(`record` in Part D must run before `seed` — it's what registers the new user. Or keep the same
`AUTH_EMAIL` across takes; re-registering no-ops and the seed stays valid until Juice Shop
restarts.)

Keep `out/phase2-demo/records.json` / `results.sarif` (Part B) — they're fixture-derived and
regenerate identically anyway. Keep `out/state.json` unless you want the lifecycle history
reset. Everything under `out/` is gitignored.

Full teardown at the end of the day: `$CT rm -f juice zap; $CT network rm dast`
(Windows: then `podman machine stop` if you like).

---

## 11. Gotchas (all hit on this machine or documented in the repo)

| Symptom | Cause | Fix |
|---|---|---|
| mac: `zsh: command not found: docker` | broken `/usr/local/bin/docker` symlink | §0 "Fix the docker command once" |
| win: `podman pull` → `proxyconnect tcp: dial tcp 127.0.0.1:8888` | dead proxy baked into the WSL VM | `dast_poc_day1_runbook.md` Appendix A2 (edit the systemd file, `daemon-reexec`) |
| win: `$PY: No such file or directory` | venv was created on the other OS / not created | `py -3.12 -m venv .venv` + installs (§0 Windows block) |
| win: commands with `$(…)`, heredocs or `time` misbehave | you're in PowerShell/cmd | use Git Bash |
| `Cannot connect to the Docker daemon` / `unable to connect to Podman` | runtime not running (mac: Docker Desktop error dialog on launch; win: machine stopped) | mac: open Docker Desktop, dismiss/restart, wait for the whale; win: `podman machine start` |
| `curl localhost:3000` → `000` but containers are "Up" | you started them with `compose` (no ports published) | `$CT rm -f …` and use the `$CT run -p` commands in §1.2 |
| `validate`/`runner`: `net::ERR_FAILED` on first `goto`, or `blocked: 1`, `scope_ok: false` | trace was recorded against `localhost` → generated allow-list is `localhost`, but the runner targets `juice` | re-record with `--base-url http://juice:3000 --zap-proxy http://localhost:8080` (§1.6 note) |
| `validate` auth check: `replay failed: … wait_for_function … Timeout` | login failed: wrong password for an existing email, **or** Juice Shop was restarted after `record` (users live in-memory, and the generated flow doesn't register) | use a fresh `AUTH_EMAIL` and re-run `record`; keep the same creds through validate/runner |
| `Passw0rd!` / `dast-poc@juice-sh.op` login times out | that email already exists with `Dast-POC-passw0rd!` | don't use it; timestamped email (§1.5) |
| `services not ready within 120s` from `runner.main` | ZAP can't reach `juice:3000` (different networks / juice exited 133 — KI3 / stale container IPs on Podman) | `$CT exec zap curl … http://juice:3000/`; do the full §1.2 reset (rm both, rm+create network, run both) |
| `curl: (52) Empty reply` from ZAP API | ZAP started without `api.addrs.addr.name=.*` | restart ZAP with the exact §1.2 command (note the quotes) |
| `github_upload` rejected | HEAD commit not on the remote, or token lacks `security_events`/`repo` | `git push` first; `gh auth status` |
| Bare `python` → `ModuleNotFoundError` | wrong interpreter (mac 3.9 / Windows Store stub) | `$PY` everywhere |
| Chromium window never appears in Part D | forgot `--headed`, or running inside a container | add `--headed`; run on the host |
| `generate`/`explore` prints `LLM path failed … using deterministic fallback` | no/invalid key, network, or off-schema output | that's the designed behavior — say so; or add `--no-llm` to avoid the wait |
| `EXPLORE ABORT: seeded session dead` | storageState is stale (Juice Shop restarted → users gone), belongs to a different `AUTH_EMAIL`, or was seeded at `localhost:3000` instead of `juice:3000` | re-run Part D `record` (registers the user) then §1.8 `seed` through ZAP at `juice:3000` |
| `explore` window shows the login page instead of being logged in | same as above — session not loaded for this origin | same fix |
| `explore` result has `blocked: >0` | the model proposed a link that fetched something off-scope (discovery mode blocks-and-continues) | fine for discovery; the trace won't contain the blocked host. If it recurs, add the term to `deny_actions` in `seed.json` |
| `validate` on the explore bundle: `Cannot navigate to invalid URL … juice:3000./redirect` | you're on a checkout older than 2026-09-19 (hrefs weren't normalized and open-redirect links weren't refused) | `git pull` — fixed in `explore.normalize_href` + `action_policy` rule 3 |
| `explore` crashes `ValueError: Invalid IPv6 URL`, or its index is full of `http://juice:3000nav [aria-label=…]` | pre-2026-09-19 checkout: LLM paths weren't normalized and `expand_nav` selectors were navigated to instead of clicked | `git pull` — `host_of` now fails closed, LLM paths are normalized, `dispatch()` clicks selectors |
| `explore` "succeeds" with `pages: 3, api_calls: 0, requests_seen: 1` | Juice Shop died (KI3 exit 133) and ZAP is answering 502; pre-2026-09-19 `prove_auth_live` only checked 401/403 | now aborts with `EXPLORE ABORT: seeded session dead (seed route returned 502)`. Fix the app: `$CT start juice`, wait for 200, re-run Part D `record` + §1.8 `seed` |
| `explore` stderr: `LLM action rejected (matches deny-list …): visit_api GET /rest/admin/application-version` | a deny term substring-matches a read-only route (`"admin"` matched `/rest/admin/*`) | that's the policy working; if it's blocking routes you *want*, narrow the term in `seed.json` (`"administration"`) — state-changing verbs are denied by default anyway |

---

## 12. One-page command card (copy/paste order)

```bash
# ---- pre-flight (Terminal A) — paste the Platform card for your OS FIRST ----
$CT rm -f juice zap 2>/dev/null; $CT network rm dast 2>/dev/null; $CT network create dast
$CT run -d --name juice --network dast -p 3000:3000 $JUICE_IMG
$CT run -d --name zap --network dast -p 8080:8080 $ZAP_IMG zap.sh -daemon -host 0.0.0.0 -port 8080 -silent -config api.disablekey=true -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true
curl -s -o /dev/null -w "juice %{http_code}\n" http://localhost:3000; curl -s -o /dev/null -w "zap %{http_code}\n" http://localhost:8080/JSON/core/view/version/; $CT exec zap curl -sS -m10 -o /dev/null -w "juice-from-zap %{http_code}\n" http://juice:3000/
$PY -m pytest -q
rm -rf out/phase2-demo && mkdir -p out/phase2-demo
export AUTH_EMAIL="dast-demo-$(date +%H%M%S)@juice-sh.op" AUTH_PASSWORD="Dast-Demo-passw0rd!"; echo $AUTH_EMAIL
$PY -m authoring.record --app-id juice-shop --base-url http://juice:3000 --zap-proxy http://localhost:8080 --out-dir out/phase2-demo/warmup --headed --slow-mo 300
export ANTHROPIC_API_KEY="$(cat .secrets/anthropic.key)"
$PY -m authoring.seed --base-url http://juice:3000 --zap-proxy http://localhost:8080 --assisted --storage-state .secrets/storageState.json

# ---- Part B (Terminal B) ----
$PY -m detections.normalizer contracts/sample_zap_output.json --app-id juice-shop --scan-id demo-fixture-1 -o out/phase2-demo/records.json
$PY -m detections.sarif_export out/phase2-demo/records.json --app-id juice-shop --driver-version "ZAP 2.17.0" -o out/phase2-demo/results.sarif
# (optional) $PY -m detections.github_upload out/phase2-demo/results.sarif --owner CodyYang2016 --repo Dast-Scanning-Tool --ref refs/heads/main

# ---- Part D (Terminal A) ----
$PY -m authoring.record --app-id juice-shop --base-url http://juice:3000 --zap-proxy http://localhost:8080 --out-dir out/phase2-demo/trace --headed --slow-mo 700

# ---- Part D2 (Terminal A; key exported per §1.7; seeded per §1.8) ----
$PY -m authoring.explore --seed security/dast/juice-shop/seed.json --scope security/dast/juice-shop/scope.json --zap-proxy http://localhost:8080 --out-dir out/phase2-demo/explore --max-pages 12 --headed --slow-mo 500

# ---- Part E (LLM live; --no-llm twin for the idempotency diff) ----
$PY -m authoring.generate --trace out/phase2-demo/explore/trace.json --out-dir out/phase2-demo/gen
$PY -m authoring.generate --trace out/phase2-demo/explore/trace.json --out-dir out/phase2-demo/gen-det --no-llm && $PY -m authoring.generate --trace out/phase2-demo/explore/trace.json --out-dir out/phase2-demo/gen-det2 --no-llm && diff out/phase2-demo/gen-det/flow.py out/phase2-demo/gen-det2/flow.py && echo IDENTICAL

# ---- Part F ----
$PY -m authoring.validate --plan out/phase2-demo/gen/journey.json --scope out/phase2-demo/gen/scope.json --flow out/phase2-demo/gen/flow.py --base-url http://juice:3000 --zap-proxy http://localhost:8080 --report out/phase2-demo/validation-report.json; echo exit=$?

# ---- Part G ----
time $PY -m runner.main --flow out/phase2-demo/gen/flow.py --scope out/phase2-demo/gen/scope.json --base-url http://juice:3000 --zap-api http://localhost:8080 --zap-proxy http://localhost:8080 --records-out out/phase2-demo/live-records.json --coverage-out out/phase2-demo/live-coverage.json; echo exit=$?

# ---- Part H (coverage-aware: diff first, export the labeled set) ----
$PY -m detections.lifecycle_diff out/phase2-demo/live-records.json --app-id juice-shop --state out/state.json --coverage out/phase2-demo/live-coverage.json -o out/phase2-demo/live-labeled.json
$PY -m detections.sarif_export out/phase2-demo/live-labeled.json --app-id juice-shop --driver-version "ZAP 2.17.0" -o out/phase2-demo/live-results.sarif
# (optional) $PY -m detections.github_upload out/phase2-demo/live-results.sarif --owner CodyYang2016 --repo Dast-Scanning-Tool --ref refs/heads/main
```

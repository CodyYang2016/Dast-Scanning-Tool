# Onboarding a new application

Everything a new application needs is one file: `security/dast/<app>/app.yaml`. Nothing under
`authoring/` or `runner/` may name an application — `tests/test_no_app_specifics.py` fails the
build if it does — so onboarding is configuration, not a code change.

The target repository has been validated with configuration-only app generation and a green
automated suite. A live lower-environment run still requires the target team's approval,
credentials, network access, and a running Nationwide Podman machine.

---

## 1. Before you start

Four facts about the target, and two things that must already be true.

| You need | Why | How to check |
|---|---|---|
| The URL **as ZAP resolves it** | The browser is proxied through ZAP, so *ZAP* does the DNS. On the compose network that is the container name, e.g. `http://my-app:8443` — not `localhost` | `podman exec zap curl -sS -o /dev/null -w '%{http_code}\n' http://<host>:<port>/` must print a 2xx/3xx |
| A **test identity** | The scanner never creates accounts unless the app explicitly allows it | Log in by hand once, in a normal browser |
| The **login form's selectors** | To drive the login | Devtools, or `curl -s <login-url> \| grep -i input` |
| A **proof of authentication** | So an unproven session is never scanned (§3) | §3's decision table |
| The environment is **non-production** | `preflight` refuses `prod`, case-insensitively, before any traffic | You state it as `environment_class`; it is the whole safety story, so get it right |
| The app is **not on port 8080** | ZAP claims proxied requests arriving on its own port as API calls, and the app never sees them (W4-7) | See §6 — this is silent, and it is the most confusing failure here |

**Environment prep is not configuration** and is not counted in the timings above: DVWA needs
its database created (`setup.php` → *Create / Reset Database*), WebGoat needs an account
registered through its signup form (its passwords cap at 10 characters). Do that first, by
hand, exactly as a person would.

### 1a. Try a bundled target first

DVWA and WebGoat are included as profile-gated targets so the configuration-only workflow can
be exercised before connecting to an internal application. The default compose run still starts
only Juice Shop. Use a local override if authoring from the host requires browser access:

```bash
cat > compose.override.yaml <<'YAML'
services:
  zap:  { ports: ["8090:8080"] }
  dvwa: { ports: ["8081:80"] }
YAML
printf '\ncompose.override.yaml\n' >> .git/info/exclude

podman compose --profile dvwa up -d dvwa zap
podman compose logs -f dvwa

# ZAP answers its own API on the published port only via the aliases in compose.yaml:
curl -sS http://127.0.0.1:8090/JSON/core/view/version/                  # expect {"version":"2.17.0"}
curl -sS -x http://127.0.0.1:8090 -o /dev/null -w '%{http_code}\n' http://dvwa/login.php   # 302
```

If the first curl returns nothing (`curl: (52) Empty reply from server`), see §6 — ZAP is
proxying the call to itself rather than answering it, and one API call fixes it at runtime.

Create the DVWA database at `http://localhost:8081/setup.php`, then run:

```bash
export DVWA_USER=admin DVWA_PASS=password
python -m dast author dvwa --explore --zap-proxy http://127.0.0.1:8090
python -m dast scan  dvwa --zap-api http://127.0.0.1:8090 --zap-proxy http://127.0.0.1:8090
python -m dast report dvwa
```

`--zap-proxy` is the address **your workstation** reaches ZAP on; the `base_url` in `app.yaml`
stays the address **ZAP** reaches the target on (`http://dvwa`). They are different machines'
views of the same network and are not interchangeable.

Exploration needs a scope and a seed. Neither is a file you write: both are derived from
`app.yaml` into `out/<app>/authoring/derived/` at author time. Commit
`security/dast/<app>/scope.json` or `seed.json` only to override that — a hand-tuned allow-list,
or seed routes that differ from `explore.seed_routes` — and the committed file then wins.

### 1b. On a Windows workstation

Verified end to end on a Nationwide-managed Windows 11 laptop in Git Bash, against DVWA,
September 2026. Five things differ from the Linux path, and each one fails in a way that does
not name its cause.

```bash
py -3 -m venv .venv && source .venv/Scripts/activate      # `python3` opens the Microsoft Store
pip install -r requirements.txt && python -m playwright install chromium

# The corporate TLS chain, for pip, requests and Playwright's downloader alike:
export NODE_EXTRA_CA_CERTS='C:\Users\<you>\certs\nw-ca-all.pem'
export REQUESTS_CA_BUNDLE="$NODE_EXTRA_CA_CERTS" SSL_CERT_FILE="$NODE_EXTRA_CA_CERTS" \
       PIP_CERT="$NODE_EXTRA_CA_CERTS"
```

The CA bundle must be a PEM chain. A DER or truststore export loads as
`error:8000007B:system library::no protocol option` and is then *silently ignored*.

**Podman, not Docker.** `podman machine` runs the containers in a WSL VM, so the VM — not your
laptop — is what resolves names and reaches the proxy:

```bash
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy    # before starting the machine, always
export NO_PROXY='localhost,127.0.0.1,.nwie.net' no_proxy="$NO_PROXY"
podman machine stop && podman machine start
```

`podman machine start` copies the current shell's proxy variables into the VM. A proxy on
`127.0.0.1:8888` is the *host's* loopback; inside the VM that address is the VM itself, and
every pull fails with `proxyconnect tcp: dial tcp 127.0.0.1:8888: connect: connection refused`.
Started with the variables unset, podman writes the reachable `host.containers.internal:8888`
itself.

Images must be mirror-qualified, since Docker Hub is not reachable — prefix the digests in
`compose.yaml` with `ntr.nwie.net/docker.io/` in your `compose.override.yaml`:

```yaml
services:
  dvwa:
    image: ntr.nwie.net/docker.io/vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7
```

Finally, publish ZAP on a port nothing else claims (`8090:8080` above). Windows forwards
published ports through `wslrelay.exe`, and a port already held by another agent accepts the
connection and closes it — indistinguishable from ZAP being down.

WebGoat is started with `podman compose --profile webgoat up -d webgoat zap` and listens on
`http://webgoat:8083`; it must not use ZAP's port `8080`. Register a 6-10 character test
account before authoring. These vulnerable targets should remain unexposed except through a
local, explicitly reviewed port override.

---

## 2. Write the config

```bash
python -m dast onboard my-app --base-url http://my-app:8443
$EDITOR security/dast/my-app/app.yaml       # every TODO is a decision you must make
```

**Or have it written for you.** `--discover` reads the login page, has a model propose the
login steps and several candidate proofs, and then *verifies* the proposal by logging in:

```bash
export MYAPP_USER=…  MYAPP_PASS=…  LLM_PROVIDER=copilot
python -m dast onboard my-app --base-url http://my-app:8443 --login-url /login \
  --zap-proxy http://localhost:8080 --discover
```

A proof is written into the config only after it has been observed to hold while logged in
**and to fail while logged out** — the second half is what a plausible-sounding guess cannot
fake. Candidates are each checked in a fresh session, and one that would navigate somewhere
session-ending is refused before it is evaluated rather than after. If nothing survives, the
command says what it tried and writes the skeleton instead, so you are never handed a config
that looks finished and is not.

Review the generated config and live proof before scanning; it is a starting point, not an
authority. The `record`/`api`/`ui` decisions remain yours.

The skeleton is a valid config with TODOs, not prose — fill them in and it loads. Three keys
carry all the judgement: the **login shape** (§3), the **proof** (§3), and the **identity**.

```yaml
auth:
  identity: provisioned     # the default, and right for almost every real application
```

Use `self-register` only where the application genuinely permits the tool to create its own
account (Juice Shop does; DVWA and WebGoat do not). It then needs a `bootstrap:` request.

---

## 3. The two decisions that matter

### Login shape

| The login is | Use |
|---|---|
| One page, an identifier field, a password field, a submit button | `auth.selectors` — the shorthand |
| Anything else: a username field you want named honestly, two pages, a keypress, a consent checkbox | `auth.steps` — `fill` / `click` / `press` / `wait_for`, in order |

Both normalize to the same step list internally, so neither is a second-class path. `value:`
names *which* credential to type (`identifier` or `secret`); credential **values** never appear
in config — `auth.credentials` names environment variables (NFR-3).

```yaml
  steps:
    - {action: fill,     selector: "input[name=username]", value: identifier}
    - {action: click,    selector: "#next"}
    - {action: wait_for, selector: "input[name=password]"}
    - {action: fill,     selector: "input[name=password]", value: secret}
    - {action: press,    selector: "input[name=password]", key: Enter}
```

### Proof of authentication

Exactly one mode, and there is no default: an unproven session must never be scanned. Pick by
what the application actually gives you.

| The app | Mode | Example |
|---|---|---|
| SPA with a token in web storage | `js` | `js: "window.localStorage.getItem('token')"` |
| Server-rendered with a session cookie, and an authenticated route that redirects when logged out | `route` | `route: {path: /index.php, forbid_redirect_to: login.php}` |
| Session cookie, but a failed login also returns 200 (so status proves nothing) | `selector` | `selector: "#menu-container"` |

Notes earned the hard way:

- **`route` needs the redirect check.** WebGoat returns **200** on `/WebGoat/login?error` after a
  failed login — a status-only check would call that authenticated.
- **`selector` matches presence, not visibility.** A marker inside a collapsed nav menu counts.
  Choose an element that exists *only* when logged in; verify by loading the login page and
  confirming it is absent there.
- Whatever you choose is used identically by the live recorder and by the generated `flow.py`,
  so an app cannot pass authoring and then fail the scan.

---

## 4. Run the loop

```bash
export MYAPP_USER=…  MYAPP_PASS=…            # the names you put in auth.credentials
python -m dast author my-app                 # record → generate → validate
python -m dast scan   my-app                 # preflight → replay → ZAP → normalize → coverage
python -m dast report my-app                 # lifecycle diff → SARIF   (--upload to publish)
```

For broader authenticated route discovery, seed a session and opt into the bounded exploration
path explicitly:

```bash
python -m dast author my-app --explore
```

Exploration is constrained by the configured scope, deny-list, write policy, authentication
proof, page budget, and redaction boundary. The model proposes actions; deterministic code decides
whether they may execute. The recorded walk remains the default target path until the
lower-environment exploration flow has been validated operationally.

What good looks like:

- **author** — `recorded: N interactions … hosts=['my-app']` (the host must be the one ZAP
  resolves), then `"passed": true` for both the allow-list and the live auth replay.
- **scan** — a gate with `authenticated: true`, `scope_ok: true`, `blocked: 0`.
- **report** — `lifecycle: new=…` on the first run, `open=…` on the next.

Artifacts land under `out/<app>/` by default: `authoring/` (trace and bundle) and
`scans/<scan_id>/` (records, coverage, labels, SARIF, redacted evidence).

### Sending them somewhere else

Three ways, highest precedence first — `--out`, then `$DAST_OUT`, then config:

```yaml
output:
  dir: ${DAST_ARTIFACTS}/dast    # ~ and ${VAR} expand; relative paths resolve from the repo root
```

`app.yaml` is committed and shared, so an absolute path in it is right on exactly one machine.
Declare the portable form in config and let `$DAST_OUT` do the per-machine work. Two things to
know before you move it:

- **Nothing outside `out/` is gitignored.** Findings, coverage and a redacted HAR will sit
  wherever you point them. Choose accordingly.
- **`state.json` moves too, and it is the lifecycle history.** Scanning once with `$DAST_OUT`
  set and once without silently compares against two different pasts, so every finding reads
  `new`. Set it consistently — which is what the config key is for.

Each run records what it resolved and **why**, in `settings.json` beside the scan:

```json
{"output_dir": {"value": "/mnt/scans", "source": "env"}}
```

### Publishing to a GitHub Security tab

```yaml
publish:
  github:
    owner: my-org
    repo: my-app-repo
    ref: refs/heads/main         # optional
    category: dast/my-app        # optional, defaults to dast/<app_id>
```

Config says *where* results would go; it never says *that* they go. Publishing still needs an
explicit `--upload`, because a Security tab is a one-way door.

**The category is not cosmetic.** GitHub keys a code-scanning analysis by *(tool, category,
ref)*, and every application here exports under the same tool name. Two applications sharing a
repository with no category share one analysis, and the newer upload **replaces** the older
one's alerts. The default of `dast/<app_id>` keeps them apart without any configuration; only
override it if your organisation already has a naming convention.

---

## 4a. Which path authored the plan?

`author` prints `"plan_source": "llm"` or `"fallback"`, and the bundle records the same thing,
so a committed bundle answers the question by itself:

```bash
python -c "import json;m=json.load(open('out/my-app/authoring/bundle/manifest.json'));print(m.get('plan_source','unrecorded — bundle predates W2-14'), m.get('model',''))"
```

(Use `.get`: a bundle generated before provenance was recorded has no such field, and should
read as *unrecorded* rather than crash or imply either answer.)

`fallback` is not a failure — it is the deterministic planner, and it is the default with
`--no-llm`. It is also what you get when the selected LLM provider is unavailable or the call
fails, so check the field rather than assuming. If you expected `llm` and got `fallback`,
rerun `python -m authoring.generate --app my-app --trace … --out-dir /tmp/x` and read stderr:
it names the reason.

For a scheduled or CI run, add `--require-llm` to `dast author` (or to `authoring.explore` /
`authoring.generate` directly). It exits non-zero instead of falling back, so an expired token,
a model id the account is not entitled to, or a missing CLI fails the run rather than quietly
producing a deterministic bundle that looks like a configuration choice.

Exploration makes one model call per step, so the flag distinguishes a flaky provider from a dead
one rather than failing on the first bad answer:

| during exploration with `--require-llm` | outcome |
|---|---|
| provider unavailable (no CLI, no token) | abort immediately — nothing in the run can improve it |
| an occasional unparseable or off-schema reply | that step falls back; the run continues |
| three such failures in a row | abort |
| the walk finishes and the model drove no step | abort |
| policy refused the proposed action | falls back — the safety layer working, not a broken provider |

When a reply cannot be parsed, the error carries an excerpt of what the model actually said, which
is usually enough to tell a refusal from a rate-limit notice or a truncated answer. For the full
picture set `LLM_DEBUG=1`, which prints the CLI's exit code, stdout and stderr for every call.

The Copilot CLI returns its answer on stdout, between `<<<DAST_JSON` markers the prompt asks for.
It is deliberately not asked to write the JSON to a file: a file write goes through the CLI's
tool-permission gate, which in a non-interactive session denies it and cannot ask anyone for
approval, so replies come back as `Blocked: the environment denied every write attempt …` and the
model's actual answer is lost.

`--require-llm` with `--no-llm` is rejected at argument-parse time, before a session is seeded.
`dast author --explore` prints `steps_by_source` (`{"llm": n, "fallback": n}`), which is how you
see how much of the walk the model actually drove without reading stderr.

## 5. Make the scan worth running

A passing gate is not the same as a useful scan. Two knobs, both configuration:

**Surface — ZAP can only attack parameters it has *seen*.** Visiting `/search` teaches it
nothing about `?q=`. Put parameterised GETs in `record.authenticated_routes`:

```yaml
record:
  authenticated_routes:
    - /vulnerabilities/sqli/?id=1&Submit=Submit
```

On DVWA that single class of change took a scan from **0 high-severity findings to 5**. If your
scan finds only headers and cookies, this is almost always why.

**You no longer have to guess whether you got this right.** `dast report` compares the parameters
your application exposes against the ones the scan actually sent:

```
reachability: 8/12 exposed parameters exercised — never sent: /vulnerabilities/brute?password
```

A route can be crawled, appear in coverage, and have a rule run to completion against it while
the parameter carrying the vulnerability was never sent — that is how two high-severity findings
stayed invisible on an application we knew well. Treat a non-empty "never sent" list as the first
thing to fix: either the walk is not submitting that form, or the parameter needs listing under
`record.authenticated_routes`. Exploration submits the forms on every page it visits, so in
practice the remaining entries are usually forms the safety policy deliberately refuses, such as
a password-change form.

**State — what does the application need to be in for a scan to mean anything?** This is the
one that cost us most. DVWA keeps its security level in a cookie; the scanner never set it,
and a deliberately vulnerable application produced **zero** findings while the SQL-injection
rule ran 660 requests. (It was not the whole story — see *Destructive controls* below — but it
was real, and it is the half you control from config.) Declare it:

```yaml
auth:
  cookies: {security: low}      # state the scan depends on, not left to chance
scan:
  state_probes:                 # hashed into coverage.json so two scans are comparable
    - /security.php
```

If your app has a feature flag, a tenant setting or a seeded dataset that decides whether the
interesting code paths are reachable, it belongs here. Without it, *"we found nothing"* and
*"there was nothing to find"* are the same sentence.

**Destructive controls — what must the scanner never touch?** This is the field most worth
getting right, and the one whose absence cost us the most. A scanner pointed at your application
will find its administrative controls and *use* them. On DVWA, one 10-minute scan submitted the
"Create / Reset Database" form about **325 times** and POSTed to the login form about **1,000**
times; roughly half of all subsequent responses were redirects to the login page, and the scan
read that silence as "no vulnerabilities here". Findings swung between 0 and 8 between runs for
this reason alone.

```yaml
scope:
  avoid_actions: [logout, setup, phpinfo, captcha]
```

These terms are matched as substrings anywhere in the URL, case-insensitively, and are excluded
from **both** the spider and the active scan. The login page is excluded automatically whether or
not you name it — attacking the form that holds the session is how a scan loses its session.

List anything that resets, seeds, migrates, exports, logs out, deletes, or sends mail. On an
internal application, one of these submitted a few hundred times is not a lost finding; it is an
incident. When a finding disappears because of one of these, `dast explain` says so by name:

```
route_excluded: /setup.php was excluded from this scan by '(?i).*setup.*',
so nothing tested it; remove the exclusion to scan it again
```

Adding exclusions to DVWA took the same bundle from **996 records and 1 high** to **617 records
and 5 highs** — five times the high-severity findings for half the requests, because the requests
finally landed on a logged-in application.

**Posture — every exclusion is a disclosed detection gap.**

```yaml
scan:
  policy: {attack_strength: high, alert_threshold: low, disabled_rules: ["40026"]}
  budgets: {max_scan_min: 6}
```

The resolved policy is pinned into `coverage.json`, so two scans can be compared honestly.
Keep DOM-XSS (`40026`) disabled unless the daemon has memory to spare: at high strength it
drives a browser per payload and **OOM-killed the ZAP container** mid-scan on DVWA.

Also set `api.patterns` to whatever your app calls its API — `/service/` for WebGoat, `/rest/`
and `/api/` for Juice Shop, nothing at all for a server-rendered app. Omitting it is correct
when there is no XHR surface; a wrong pattern quietly records nothing.

---

## 6. When it goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| The scan passes but finds nothing interesting on an app you know is vulnerable | Either the parameters were never discovered (see §5) or the app was not in a testable state | `dast explain <app>` after a second scan; check `coverage.json` for the rule's `requests`/`alerts` — a rule that sent hundreds of requests and raised nothing points at app state, not at the scanner |
| Everything returns **400**, body `Bad Format`; `podman logs zap` shows `No enum constant …Format.<APP>` | The target is on **8080**, ZAP's own port, so ZAP answers as its API and the app never sees the request (W4-7) | Move the app off 8080, or run ZAP's proxy elsewhere. **Silent** — the scan "succeeds" against nothing |
| `AuthProofError: authentication not proven (selector)` while the login clearly worked | The marker is absent on the authenticated page, or you picked one that exists on the login page too | Load both pages and compare; presence-only is enough, visibility is not required |
| `AuthProofError … (route)` | The route 302s to login, or returns 4xx/5xx | Check the route by hand with a logged-in session; add `forbid_redirect_to` |
| `Page.fill: Timeout … waiting for locator` | The selector is wrong, or the page did not load through the proxy | Check the ZAP reachability command in §1 first — a proxy problem looks like a selector problem |
| `credentials not in the environment: MYAPP_USER` | The env vars named in `auth.credentials` are not exported | Export them in the shell that runs `dast` |
| Login works by hand, fails here | A password policy (WebGoat caps at 10 characters), or the account was wiped when the container restarted | Re-provision the account; in-memory databases do not survive a restart |
| `services not ready within 120s` | ZAP cannot reach the target | `podman exec zap curl …` from §1; check both are on the same network |
| `curl: (52) Empty reply from server` from ZAP's API on a published host port | ZAP answers as its API only when the `Host` header names an address it knows itself by; a published port does not rewrite it, so ZAP tries to *proxy* the call to `127.0.0.1:<port>` inside the container, where nothing listens | `compose.yaml` registers `127.0.0.1` and `localhost` as aliases. On a ZAP started without them: `curl -sS -H 'Host: zap' 'http://127.0.0.1:8090/JSON/network/action/addAlias/?name=127.0.0.1'` — effective immediately, lost on restart |
| `ZapUnavailableError: ZAP stopped responding` | The daemon died — usually OOM (exit 137) from a browser-driven rule | `podman logs zap`; disable `40026` or give the daemon more memory |

---

## 7. If configuration is not enough

Then you have found a gap in the tool, and that is worth more than the workaround. Both of the
applications onboarded after Juice Shop found real defects this way — an unfinished live proof
path, a proof mode that demanded visibility, and ZAP's port collision.

1. Add a row to the register in `docs/dast_poc_remediation_plan.md` §3 with the evidence.
2. Fix it in the core with a test, so the *next* application gets it for free.
3. Do not special-case the app in `authoring/` or `runner/` — the guard test will reject it, and
   that rejection is the point.

The underlying CLIs (`python -m authoring.record --app …`, `generate`, `validate`,
`runner.main`) remain available for anything unusual — a different proxy, a one-off trace,
`--no-replay`. `dast` is a facade over exactly those commands, not a reimplementation.

---

## 8. The three onboarded applications, side by side

Useful as templates: find the one whose shape is closest to yours and start from its config.

| | `juice-shop` | `dvwa` | `webgoat` |
|---|---|---|---|
| Stack | Angular SPA | PHP | Spring Boot |
| Login | email + password | username + password | username + password |
| Login shape | `selectors` shorthand | `steps` | `steps` |
| Session | JWT in `localStorage` | PHPSESSID cookie | JSESSIONID cookie |
| Proof | `js` | `route` | `selector` |
| Identity | `self-register` (+ `bootstrap`) | `provisioned` | `provisioned` |
| API pattern | `/rest/`, `/api/` | none (server-rendered) | `/service/` |
| Banners to dismiss | welcome + cookie | none | none |
| Environment prep | none | create the database | register an account |
| Onboarding time | — (the original) | 4m20s | **4m32s, zero code changes** |

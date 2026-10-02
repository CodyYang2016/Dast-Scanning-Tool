# Onboarding a new application

Everything a new application needs is one file: `security/dast/<app>/app.yaml`. Nothing under
`authoring/` or `runner/` may name an application — `tests/test_no_app_specifics.py` fails the
build if it does — so onboarding is configuration, not a code change.

**Measured:** WebGoat took **4m32s** from `dast onboard` to a passing gate, DVWA **4m20s**,
excluding environment prep. If you find yourself editing Python, stop and read §7 — that is a
gap in the tool, and it should be recorded, not worked around.

---

## 1. Before you start

Four facts about the target, and two things that must already be true.

| You need | Why | How to check |
|---|---|---|
| The URL **as ZAP resolves it** | The browser is proxied through ZAP, so *ZAP* does the DNS. On the compose network that is the container name, e.g. `http://dvwa` — not `localhost` | `docker exec zap curl -sS -o /dev/null -w '%{http_code}\n' http://<host>:<port>/` must print a 2xx/3xx |
| A **test identity** | The scanner never creates accounts unless the app explicitly allows it | Log in by hand once, in a normal browser |
| The **login form's selectors** | To drive the login | Devtools, or `curl -s <login-url> \| grep -i input` |
| A **proof of authentication** | So an unproven session is never scanned (§3) | §3's decision table |
| The environment is **non-production** | `preflight` refuses `prod`, case-insensitively, before any traffic | You state it as `environment_class`; it is the whole safety story, so get it right |
| ZAP runs **with an API key** | An open ZAP API can be driven by anything that reaches it; a `test`/`staging` scan refuses one (W4-4) | Start ZAP with `-config api.key="$ZAP_API_KEY"` and export the **same** `ZAP_API_KEY` where you run `dast`. Compose refuses to start without it |
| The app is **not on port 8080** | ZAP claims proxied requests arriving on its own port as API calls, and the app never sees them (W4-7) | See §6 — this is silent, and it is the most confusing failure here |

**Environment prep is not configuration** and is not counted in the timings above: DVWA needs
its database created (`setup.php` → *Create / Reset Database*), WebGoat needs an account
registered through its signup form (its passwords cap at 10 characters). Do that first, by
hand, exactly as a person would.

### 1a. Trying it on a bundled target first

Three applications are already onboarded, and two of them exist precisely to prove this works
on something that is not the pilot app. If you want to see the whole loop before pointing it at
your own application, start one of them:

`compose.yaml` publishes **no** host ports, on purpose. But `dast author` drives a real Chromium
**on your machine** through ZAP, so for authoring both ZAP and the app have to be reachable from
there. Add a local override — compose picks the file up automatically, and it is yours, not the
repo's:

```bash
cat > compose.override.yaml <<'YAML'
services:
  zap:  { ports: ["8080:8080"] }
  dvwa: { ports: ["8081:80"] }
YAML
echo compose.override.yaml >> .git/info/exclude     # keep it local

docker compose --profile dvwa up -d dvwa zap
docker compose logs -f dvwa                          # wait for it to serve
```

Then do the prep by hand, once — browse to `http://localhost:8081/setup.php` and press
*Create / Reset Database* — and run the loop:

```bash
export DVWA_USER=admin DVWA_PASS=password
python -m dast author dvwa --explore --zap-proxy http://localhost:8080
python -m dast scan   dvwa
python -m dast report dvwa
```

Both apps are pinned by digest in `versions.lock`, so you get the images these results were
measured on rather than whatever `:latest` points at today.

Three things that will otherwise cost you an afternoon:

- **Publish ports only where that is acceptable.** These are deliberately vulnerable
  applications. The override above binds them on your machine; do not commit it, and do not do
  this on a host anyone else can reach. Without the override they are reachable only on the
  `dast` network, which is all the containerised runner needs.
- **WebGoat runs on 8083, not its default 8080.** 8080 is ZAP's own port: ZAP claims proxied
  requests arriving there as API calls, the application never sees them, and the scan finishes
  clean having tested nothing. The compose service sets `WEBGOAT_PORT=8083` for this reason, and
  it must match `base_url: http://webgoat:8083`. This is §6's most confusing failure, and it is
  silent.
- **`--profile` is required to start it.** Without it compose does not treat the service as
  part of the run, so a bare `docker compose up` brings up only the pilot app — which is the
  point, but it surprises people. If a later command seems not to see the container, pass the
  profile again.

Reading their configs side by side is the fastest way to understand the contract: `dvwa` logs in
with a username and proves the session by visiting a page, `webgoat` needs a registered account,
`juice-shop` self-registers and proves the session from `localStorage`. §8 compares all three.

---

## 2. Write the config

```bash
python -m dast onboard my-app --base-url http://my-app:8443
$EDITOR security/dast/my-app/app.yaml       # every TODO is a decision you must make
```

**Or have it written for you.** `--discover` reads the login page, has a model propose the
login steps and several candidate proofs, and then *verifies* the proposal by logging in:

```bash
export MYAPP_USER=…  MYAPP_PASS=…  ANTHROPIC_API_KEY=…
python -m dast onboard my-app --base-url http://my-app:8443 --login-url /login \
  --zap-proxy http://localhost:8080 --discover
```

A proof is written into the config only after it has been observed to hold while logged in
**and to fail while logged out** — the second half is what a plausible-sounding guess cannot
fake. Candidates are each checked in a fresh session, and one that would navigate somewhere
session-ending is refused before it is evaluated rather than after. If nothing survives, the
command says what it tried and writes the skeleton instead, so you are never handed a config
that looks finished and is not.

Measured on DVWA: **11 seconds**, three login steps and a verified `selector` proof, and the
resulting config passed `dast author` (live auth replay) unchanged. You still review it — it
is a starting point, not an authority — and the `record`/`api`/`ui` TODOs remain yours.

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
export ZAP_API_KEY=…                         # the key ZAP was started with
python -m dast author my-app                 # record → generate → validate
python -m dast scan   my-app                 # preflight → replay → ZAP → normalize → coverage
python -m dast report my-app                 # lifecycle diff → SARIF   (--upload to publish)
```

What good looks like:

- **author** — `recorded: N interactions … hosts=['my-app']` (the host must be the one ZAP
  resolves), then `"passed": true` for both the allow-list and the live auth replay.
- **scan** — a gate with `authenticated: true`, `scope_ok: true`, `routes_tested` above zero,
  `session_alive: true` (or `null` if no probe could tell — see *Shared environments* below),
  `blocked: 0`.
- **report** — `lifecycle: new=…` on the first run, `open=…` on the next, then a `gate:` line and
  `summary: …/summary.md` — one page with the verdict, counts, new findings, coverage gaps and
  whether the session held. Read that first.

### Two gates, and which one fails your build

**`scan` checks the scan was healthy**: it authenticated, stayed in scope, and tested at least
one route. A scan that tested nothing never passes — an over-broad exclusion once turned a Juice
Shop scan into exactly that, and an older gate passed it. Findings do not affect this gate, so a
clean application passes. (`--expect-findings` adds "and found a high or medium", for self-tests
against deliberately vulnerable apps where finding nothing means the scanner is broken.)

**`report` decides whether findings fail the build**, because only after the lifecycle diff is it
known which findings are **new**. It exits `1` when a new finding is at or above the threshold:

```yaml
gate:
  fail_on: high        # critical | high | medium | low | none   (default: high)
```

`--fail-on` or `$DAST_FAIL_ON` override it per run. A finding that already existed does not fail
the build again: it has been seen and is somebody's decision, and failing every build on it
forever is how gates get switched off. SARIF is written and an explicit `--upload` still runs
when the gate fails, so the evidence is published either way. Exit `2` means a tool error.

### Shared environments: scope, pace, session, stop

A `dev` target can be scoped loosely. Anything with other users (`environment_class: test` or
`staging`) is held to more:

- **Register the host.** Every `test`/`staging` host must be listed in
  `security/dast/environments.yaml` (or the file `$DAST_ENV_REGISTRY` names) with its class —
  `my-app.internal: test`. Preflight refuses an unregistered shared host, a host registered as a
  different class than `environment_class` says, and any host matching a production pattern
  (`*.prod.*`, `prod-*`, …) whatever the scope says. `dev` hosts need not be registered.
- **SSO login through an identity provider.** List it as login-only:
  `scope.traverse: [https://login.microsoftonline.com]`. The browser may reach it to log in; it
  is never explored, spidered or attacked, and ZAP forwards its traffic without recording it, so
  no finding can land on it. Exact origins only, never also in `allow`. It is exempt from the
  environment registry, because it is not scanned and is usually production.
- **Scope by origin.** `scope.allow: [https://my-app.internal:8443]` — scheme, host and port.
  A bare host (`my-app.internal`) means *every scheme and port on that machine*; preflight accepts
  it for `dev` and refuses it for `test`/`staging`, saying which origin to write instead. ZAP's
  own spider and active scan are confined to the same origins by a context created for each scan.
- **Keep it off what must not be touched.** `scope.exclude: [/api/payments, /notify, /admin/reset]`
  — each path and everything beneath it (`*` matches within one segment). Nothing is sent to
  them: not by ZAP's spider or active scan, not during exploration, and not by the browser,
  which gets a local 403 instead. Every exclusion is a detection gap to disclose.
- **Pace.** `scan.throttle: {threads_per_host: 2, delay_ms: 200}` slows ZAP down; the values in
  force are recorded in `coverage.json` under `policy`. Unset means ZAP's defaults.
- **Session.** The scan re-checks the session during the active scan and once at the end. It
  probes `scan.liveness_path` if set — any path that answers differently logged in and logged out
  (Juice Shop: `/rest/user/whoami`) — else `auth.proof.route.path`, else the first
  `scan.state_probes` entry. If the session is lost (401/403, a redirect to the login path, or the
  logged-out answer), the scan **logs in again**: it pauses ZAP, replays the login, points ZAP's
  attacks at the new session, and resumes — up to `scan.reauth.max` times (default 3). The loss
  is still recorded; the summary calls the scan *degraded*, and no finding can be marked
  `resolved` from it. If the re-login fails or the limit is reached, the active scan is stopped
  and **the scan fails**. If the app expects the session as a bearer token too, name the cookie
  that holds it: `auth.bearer_from_cookie: token`. Forms with a per-request anti-CSRF field ZAP
  does not know: `scan.anti_csrf_tokens: [user_token]`. If no probe can tell logged-in from
  logged-out, `coverage.json` says `alive_throughout: null` — unknown, not alive.
- **The stored session.** A seeded `storageState` is a working login. In CI, deliver it from
  the secret store: `auth.storage_state: env:MY_APP_SESSION` (the JSON, raw or base64); it
  exists on disk only for the run. A file copy must be mode 600, git-ignored, and younger than
  `auth.storage_state_ttl_hours` (default 12) — older, and the scan logs in with the flow
  instead and exploration asks you to re-seed.
- **Stop.** Ctrl-C stops ZAP's spider and active scan too, not just the runner (exit 130). From
  another terminal: `python -m dast stop my-app`.

**Not decided yet:** ZAP's active scan attacks every write request it has seen, whatever
`write_mode` says — `write_mode` governs only exploration (W4-8). Agree with the app team which
write endpoints are acceptable before scanning a shared environment, and put the rest in
`scope.exclude`.

### Marking a finding as a false positive, accepted risk, or not yours

Record the decision in `security/dast/<app>/suppressions.yaml`, keyed by the finding's
fingerprint (in `labeled.json`, or on the alert):

```yaml
suppressions:
  - fingerprint: 5910c6477d624b6e553d51983b2fb5beab3f6eb1357d58b06875ce0934b78487
    reason: accepted_risk          # false_positive | accepted_risk | wont_fix | test_data
    justification: "Example only — say why, so a reviewer can check it without asking."
    owner: appsec-team
    expires: "2026-12-31"          # required for accepted_risk and wont_fix
```

`dast report` then labels it `suppressed`: it no longer counts toward the gate or the totals, but
it is **still published** — dropping it from the upload is how GitHub would decide it was fixed —
and carries the justification as SARIF's suppression marker. When `expires` passes, the finding
counts again and `report` says so. The lifecycle history underneath is unchanged.

**GitHub ignores that marker.** Verified by uploading a suppressed finding: its alert (#1501, since
deleted with the rest of that test data) stayed open. A suppression here governs *this tool's* gate and counts; to hide an alert in the Security
tab, dismiss it there — and `dast triage --from-github` below brings that decision back into
`suppressions.yaml`, so the two agree.

Dismissed something in GitHub's UI instead? `dast triage <app> --from-github` reads the dismissed
alerts and writes `suppressions.proposed.yaml` beside the real file, for you to review and merge.
It never applies anything itself. GitHub does not expose fingerprints, so each alert is matched by
recomputing ours from its rule, location and the parameter its message names; an older alert that
names no parameter is matched only when that is unambiguous, and listed otherwise.

### What the scan did, on the record

Every run writes `events.jsonl` beside its artifacts: one JSON line per event, each with a
timestamp, the scan id and the app id. It covers preflight, login, every blocked or traversed
request, scan progress, session losses, aborts with their reasons, and the report's gate and
upload. It answers "what did you touch, what did you refuse, and when?" for an unattended run.
Set `DAST_LOG_FORMAT=json` to mirror the events to stderr for a log shipper.

### Running it in CI

Every push runs `ruff` and the test suite (`.github/workflows/tests.yml`). A weekly workflow,
`dast-selftest.yml`, scans Juice Shop through compose with `--expect-findings` — a canary that goes
red if the scanner ever stops finding vulnerabilities in an app that has them — and keeps the
results as a downloadable artifact. Its run page shows the scan summary, and each alert's
request/response link points at that run. It publishes nothing unless run by hand with `upload`
ticked. `dast report` appends the same summary to `$GITHUB_STEP_SUMMARY` whenever it runs inside
GitHub Actions.
For your own application, the natural home for `dast scan` and `dast report` is the app's deploy
pipeline, which knows the deployed commit to pass as `DAST_TARGET_COMMIT`. Publishing and
`triage --from-github` use `$GITHUB_TOKEN` (or `$GH_TOKEN`) over HTTP, so the pipeline needs no
`gh` CLI. On GitHub Enterprise Server, also set `$GITHUB_API_URL`. Locally, with no token, the
`gh` CLI is used as before.

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

GitHub splits the uploaded id at its **last** `/` into category and run id, so the tool sends
`dast/<app_id>/<scan_id>` and GitHub files it under `dast/<app_id>`. (Sending `dast/<app_id>` alone
was read as category `dast` for every app — found on a real upload, and why the scan id is there.)

**Branch and commit mean the deployment, not the scanner.** GitHub attaches every alert to a
branch and commit and shows them as *Affected branches*. For a DAST finding the only meaningful
values are those of the **build running in the environment you scanned**, which the scanner cannot
work out for itself — so you must say, and the upload refuses without it:

```bash
python -m dast report my-app --upload \
  --commit <full SHA of the deployed build> --ref refs/heads/<deployed branch>
```

In a pipeline, set `DAST_TARGET_COMMIT` and `DAST_TARGET_REF` in the deploy step instead; for a
target pinned to one build, `publish.github.commit`/`ref` in `app.yaml` also work. The commit must
be a full 40-character SHA and the ref a full `refs/heads/…`. Each run's `settings.json` records
which of the three supplied them. (Earlier versions defaulted to `refs/heads/main` and to the DAST
tool's *own* checkout, so early Juice Shop alerts claimed to live in the scanner's `main` — W1-8;
they have since been deleted.) Upload to the **application's** repository, not this one.

Juice Shop's own config is the worked example. GitHub only accepts a commit that exists in the
repository you upload to, so its findings go to a fork of Juice Shop, on a `deployed/v20.2.0`
branch at the commit its pinned image was built from — see `publish` in
`security/dast/juice-shop/app.yaml`, and an alert as it lands:
https://github.com/CodyYang2016/juice-shop/security/code-scanning/1195

**Moving an app that already has alerts.** Changing the category — including going from the old
no-category uploads to `dast/<app_id>` — starts a new analysis. The old alerts are not migrated;
they stop receiving updates and sit open alongside the new ones. To keep updating existing alerts
in place, keep the old category (for pre-category uploads, pass none). Also: GitHub closes as
**fixed** any alert missing from the newest upload in the same slot, so upload the *labelled*
output of `dast report`, never raw records — the lifecycle diff carries findings this scan did not
reach forward as `not_scanned` precisely so they are not falsely closed.

### What a developer sees on an alert

Each alert now says where, what proved it, how sure the scanner is, and how to fix it:

```
SQL Injection                                                  High
/rest/user/login
SQL Injection in parameter `email` — ZAP sent `'` and the server answered
`HTTP/1.1 500 Internal Server Error`. Confidence: Low.
Reproduce: `POST /rest/user/login` → 500.

▾ Rule help
  SQL injection may be possible.
  How to fix — Do not trust client side input … use PreparedStatement …
  References — OWASP SQL Injection Prevention Cheat Sheet
```

The **confidence** is worth reading first: a Low-confidence finding based on a bare 500 is a lead
to confirm by hand, not a confirmed injection. The evidence and payload are redacted (tokens,
bearer values, secret-named fields, emails) and capped at 500 characters before they are stored
or published; the redactor cannot recognise an opaque session id with no telling key name, so do
not treat excerpts as guaranteed clean.

**Reproduce** is the request a developer replays. For every high and medium finding the scan also
stores the full exchange ZAP sent and received, redacted — credential headers (`Cookie`,
`Authorization`, `Set-Cookie`, API-key headers) keep their name and lose their value, and secret
form and JSON fields are scrubbed — with the response cut to the part around the evidence. It sits
at `exchange_path` in the scan's evidence directory (`messages/<fingerprint>.txt`). It is captured
during the scan because ZAP discards it when the next scan starts.

The alert says where that file is (W1-4) — *Full request/response: …* — in one of three ways:

| Setting | The alert shows |
|---|---|
| `publish.evidence_url: https://store.example/dast/{scan_id}/{path}` | a link to the file itself, for an organisation's own artifact store |
| a page with no `{path}`, e.g. the CI run (`${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`) | the file's name **and** a link to the run. A GitHub artifact is a zip, so a link can reach the run but not the file inside |
| nothing | the file's name, inside this scan's evidence |

`--evidence-url` and `$DAST_EVIDENCE_URL` override the config, and `settings.json` records which
one won. Only `http(s)` URLs are accepted.

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
`--no-llm`. But it is also what you get **silently** when `ANTHROPIC_API_KEY` is unset or the
call fails, so check the field rather than assuming. If you expected `llm` and got `fallback`,
rerun `python -m authoring.generate --app my-app --trace … --out-dir /tmp/x` and read stderr:
it names the reason.

## 5. Make the scan worth running

A passing gate is not the same as a useful scan. Each knob below is configuration; any you leave
off is a gap to disclose when results are compared with another tool (the scorecard's SP list).

**Give it the spec, if the app has one (W6-4).** `scan.openapi: https://my-app.internal/openapi.json`
(or a path beside `app.yaml`). ZAP imports every declared endpoint and parameter, which means
more to attack than any walk finds, and the report gains a denominator: *"Tested 34 of 41
declared routes (83%) — source: OpenAPI spec"*, with the routes it missed. Without a spec, the
denominator is the routes the authoring walk discovered, and the report says so. In compose,
spec files under `security/dast/` are readable by ZAP; elsewhere, set `DAST_ZAP_SPEC_DIR` to
where that directory is mounted inside ZAP, or the spec gives the denominator only.

**Test DOM-based XSS (W6-3).** `scan.dom_xss: {enabled: true, max_min: 15}` runs ZAP's
browser-driven DOM-XSS rule in its own pass after the main scan. It gets one browser at a time,
its own time limit and the scan's session, and the main results are saved first, so if ZAP runs
out of memory you lose this pass, not the scan. On DVWA it added ten high-severity findings, with
ZAP peaking near 5 GiB, so give the ZAP container that much. `routes:` narrows it to named pages.

**Test write paths, on a disposable environment (W6-1).** ZAP's spider already submits HTML
forms. What it never sees are writes the app makes from its own JavaScript (`fetch`/XHR). With
`data_policy: disposable` and `explore.write_mode: allow`, those writes are recorded (bodies
redacted) and replayed by the scan so ZAP can attack them. The usual refusals still apply:
DELETE only with `safe_forms`, never a path in `scope.exclude`, and never a credential change.
Give the app a reset so every scan starts from the same data:

```yaml
scan:
  reset:
    url: /setup.php
    steps:
      - {action: click, selector: "input[name=create_db]"}
    verify: {path: /login.php, contains: "Username"}     # the scan does not start without it
```

A write-enabled scan still never marks a finding `resolved`: its own writes change the data
while it runs.

Two more knobs:

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
from **both** the spider and the active scan. A login page with a real path (`/login.php`,
`/WebGoat/login`) is excluded automatically whether or not you name it — attacking the form that
holds the session is how a scan loses its session.

A **hash-routed** login (`/#/login`, as in Juice Shop or any hash-mode SPA) is not excluded,
because nothing after `#` reaches the server — the browser requests `/`. An earlier version did
exclude it, derived the pattern `/`, and excluded the entire application: the scan passed its gate
with 60 passive findings instead of ~1,400 and coverage showed 0 routes. So there is now a guard:
**if any exclusion would match your application's root, the scan refuses to start** and names the
offending pattern. If you see that error, the culprit is an `avoid_actions` term that is too short
or names your host, or an `auth.login_url` whose path is `/`. If your SPA's real login endpoint is
an API call (Juice Shop's is `POST /rest/user/login`), list it in `avoid_actions` yourself — but
only if attacking it can end the session; a JWT session usually survives it, a cookie session
usually does not. Exclusion has a price: Juice Shop's High SQL injection is *on*
`/rest/user/login`, so excluding that endpoint would have hidden it.

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

A login failure is one line — `RUNNER ABORT: authentication failed — <what>` — followed by
`next: <what to do>`, exit code 2 (W5-4). A browser that is not installed says so and gives the
install command.

| Symptom | Cause | Fix |
|---|---|---|
| The scan passes but finds nothing interesting on an app you know is vulnerable | Either the parameters were never discovered (see §5) or the app was not in a testable state | `dast explain <app>` after a second scan; check `coverage.json` for the rule's `requests`/`alerts` — a rule that sent hundreds of requests and raised nothing points at app state, not at the scanner |
| Everything returns **400**, body `Bad Format`; `docker logs zap` shows `No enum constant …Format.<APP>` | The target is on **8080**, ZAP's own port, so ZAP answers as its API and the app never sees the request (W4-7) | Move the app off 8080 (`-e WEBGOAT_PORT=8083`), or run ZAP's proxy elsewhere. **Silent** — the scan "succeeds" against nothing |
| `authentication failed — the login was submitted, but authentication was not proven …` (selector proof) while the login clearly worked | The marker is absent on the authenticated page, or you picked one that exists on the login page too | Load both pages and compare; presence-only is enough, visibility is not required |
| `… not proven — auth check redirected to …/login.php` (route proof) | A wrong password lands here too — check the credentials first. Otherwise | The route 302s to login, or returns 4xx/5xx | Check the route by hand with a logged-in session; add `forbid_redirect_to` |
| `authentication failed — login page element not found: <selector>` | The selector is wrong, or the page did not load through the proxy | Check the ZAP reachability command in §1 first — a proxy problem looks like a selector problem |
| `authentication failed — credentials not in the environment: MYAPP_USER` (before any traffic) | The env vars named in `auth.credentials` are not exported | Export them in the shell that runs `dast` |
| Login works by hand, fails here | A password policy (WebGoat caps at 10 characters), or the account was wiped when the container restarted | Re-provision the account; in-memory databases do not survive a restart |
| `services not ready within 120s` | ZAP cannot reach the target | `docker exec zap curl …` from §1; check both are on the same network |
| `… matches a production hostname pattern` / `… is not registered` / `… is registered as 'dev'` | The environment registry (W4-6) disagrees with the scope | Register the host in `security/dast/environments.yaml` with its real class; never loosen a production pattern to get a scan through |
| `refusing to scan …: it is on port 8080, the port ZAP listens on` | The app shares ZAP's port; ZAP would answer as its API (W4-7) | Move the app (WebGoat: `WEBGOAT_PORT=8083`) |
| `stored session … is readable by other users` / `… not git-ignored` / `… past its 12 h limit` | The seeded session file is mishandled or stale (W5-3) | `chmod 600` it, keep it under `.secrets/`, or re-seed with `dast author <app> --explore` |
| Host-run `dast author` against **compose's** ZAP: `ZAP closed the connection` | Compose's ZAP admits only the runner's address (W4-7) | `export ZAP_API_ALLOW='.*'` before `docker compose up` — the key is still required |
| Compose: `services not ready`, ZAP logs `UnknownHost: juice` | A container from before the network change was reattached without its DNS name | `docker compose down`, then up again |
| `ZAP closed the connection without answering` | `ZAP_API_KEY` is missing or differs from the key ZAP was started with. A keyed ZAP hangs up rather than answering 401 | Export the same key in the shell that runs `dast` |
| `refusing to scan a test environment: ZAP's API is open` | ZAP was started with `api.disablekey=true` | Restart it with `-config api.key=…` |
| `… is a shared environment, so scope must name exact origins` | A bare host in `scope.allow` for `test`/`staging` | Write it as an origin, e.g. `https://my-app.internal:8443` |
| Health gate fails with `session_alive: false` | The session died mid-scan and logging in again did not bring it back, or `scan.reauth.max` was reached | `coverage.json` → `session.losses` says when and why; add the action that logs out to `scope.avoid_actions`, check `scan.anti_csrf_tokens`, or raise `scan.reauth.max` |
| `ZapUnavailableError: ZAP stopped responding` | The daemon died — usually OOM (exit 137) from a browser-driven rule | `docker logs zap`; disable `40026` or give the daemon more memory |

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

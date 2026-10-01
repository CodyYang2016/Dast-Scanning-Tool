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
python -m dast author my-app                 # record → generate → validate
python -m dast scan   my-app                 # preflight → replay → ZAP → normalize → coverage
python -m dast report my-app                 # lifecycle diff → SARIF   (--upload to publish)
```

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

**Branch and commit mean the deployment, not the scanner.** GitHub attaches every alert to a
branch and commit and shows them as *Affected branches*. For a DAST finding the only meaningful
values are those of the **build running in the environment you scanned** — which the scanner cannot
work out for itself. Today the upload defaults to `refs/heads/main` and to the commit the *DAST
tool's* own checkout is on, so an alert can claim a vulnerability lives in code that has nothing to
do with the application (this is what the Juice Shop demo alerts on the tool's own repository show).
Until that default is removed (W1-8), pass the deployed build's commit and branch explicitly:
`python -m detections.github_upload results.sarif --owner … --repo … --ref refs/heads/<deployed
branch> --commit <deployed sha>`, uploading to the application's repository, not this one.

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

▾ Rule help
  SQL injection may be possible.
  How to fix — Do not trust client side input … use PreparedStatement …
  References — OWASP SQL Injection Prevention Cheat Sheet
```

The **confidence** is worth reading first: a Low-confidence finding based on a bare 500 is a lead
to confirm by hand, not a confirmed injection. The evidence and payload are redacted (tokens,
bearer values, secret-named fields, emails) and capped at 500 characters before they are stored
or published; the redactor cannot recognise an opaque session id with no telling key name, so do
not treat excerpts as guaranteed clean. Not yet included: the full request/response pair (W1-3).

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

| Symptom | Cause | Fix |
|---|---|---|
| The scan passes but finds nothing interesting on an app you know is vulnerable | Either the parameters were never discovered (see §5) or the app was not in a testable state | `dast explain <app>` after a second scan; check `coverage.json` for the rule's `requests`/`alerts` — a rule that sent hundreds of requests and raised nothing points at app state, not at the scanner |
| Everything returns **400**, body `Bad Format`; `docker logs zap` shows `No enum constant …Format.<APP>` | The target is on **8080**, ZAP's own port, so ZAP answers as its API and the app never sees the request (W4-7) | Move the app off 8080 (`-e WEBGOAT_PORT=8083`), or run ZAP's proxy elsewhere. **Silent** — the scan "succeeds" against nothing |
| `AuthProofError: authentication not proven (selector)` while the login clearly worked | The marker is absent on the authenticated page, or you picked one that exists on the login page too | Load both pages and compare; presence-only is enough, visibility is not required |
| `AuthProofError … (route)` | The route 302s to login, or returns 4xx/5xx | Check the route by hand with a logged-in session; add `forbid_redirect_to` |
| `Page.fill: Timeout … waiting for locator` | The selector is wrong, or the page did not load through the proxy | Check the ZAP reachability command in §1 first — a proxy problem looks like a selector problem |
| `credentials not in the environment: MYAPP_USER` | The env vars named in `auth.credentials` are not exported | Export them in the shell that runs `dast` |
| Login works by hand, fails here | A password policy (WebGoat caps at 10 characters), or the account was wiped when the container restarted | Re-provision the account; in-memory databases do not survive a restart |
| `services not ready within 120s` | ZAP cannot reach the target | `docker exec zap curl …` from §1; check both are on the same network |
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

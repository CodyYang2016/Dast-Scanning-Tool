# DAST POC — Phase 1 Demo
## The Visible Minimum Viable Scanner Gate

Proving we can safely scan a live web application end-to-end — authenticate through a proxy, stay in scope, and produce a real finding — *before* any LLM generates anything.

Presenter: Cherry Yang · Developer Experience & Platform (DevXP)

---

## Agenda

* The big picture: three POC gates and where Phase 1 fits
* What Phase 1 proves (the four gate conditions)
* How the pieces fit together (architecture)
* Live demo walkthrough
* Independent proof that scanning was authenticated
* Guardrails: failing closed and staying in scope
* Evidence, wrap-up, and what comes next

---

## The Big Picture — Three Gates

```mermaid
flowchart LR
  P1["Phase 1\nSafe deterministic scanner\nProve auth, proxy, scope, detection"]
  P2["Phase 2\nGenerated artifacts + results pipeline\nRecord, generate, validate, normalize, SARIF"]
  P3["Phase 3\nLifecycle + hardening\nRe-scan, resolve, evidence, final demo"]

  P1 -->|"Scanner gate is trusted"| P2
  P2 -->|"Generated flow and SARIF path are trusted"| P3
```

The POC is split into three gates:

* Phase 1 proves the scanner can safely authenticate through ZAP, stay in scope, and produce a real finding.
* Phase 2 replaces the hand-authored flow with generated artifacts and proves the deterministic results path into SARIF / GitHub.
* Phase 3 proves lifecycle behavior: scan, fix, re-scan, and show open / resolved state.

Today is Phase 1 — because every later phase depends on this scanner gate being trustworthy.

---

## What the Full POC Becomes

```mermaid
flowchart LR
  Human["User/app owner\nInput: app URL + login journey\nOutput: demo intent"]
  Record["record CLI\nInput: app URL + browser actions\nOutput: trace.json + index.json"]
  Generate["generate CLI\nInput: trace.json + contracts\nOutput: flow.py + scope.json + policy + manifest"]
  Validate["validate CLI\nInput: generated bundle\nOutput: validation-report.json"]

  Scope[/"Scope artifact\nscope.json\nConsumed as: scan boundary"/]
  Flow[/"Flow artifact\nflow.py\nConsumed as: Playwright instructions"/]
  Playwright["Playwright-controlled Chromium\nLaunched by runner/replay.py\nOutput: browser traffic"]
  Guard["ScopeGuard\nrunner/scope_guard.py\nOutput: allow/block decisions"]
  Zap["OWASP ZAP\nInput: proxied traffic + scan command\nOutput: raw alerts JSON"]
  Juice["OWASP Juice Shop\nInput: HTTP requests\nOutput: app responses + vulnerabilities"]
  Runner["runner\nInput: flow.py + scope.json + ZAP endpoints\nOutput: gate result + out/records.json"]

  Normalize["normalizer\nInput: raw ZAP alerts\nOutput: stable detection records"]
  Sarif["SARIF export\nOutput: SARIF 2.1.0 file"]
  Github["GitHub code scanning\nOutput: security alerts"]
  Lifecycle["lifecycle diff\nOutput: open / new / resolved"]

  Human --> Record --> Generate --> Validate
  Validate --> Flow
  Validate --> Scope
  Scope --> Runner
  Flow --> Runner
  Runner --> Playwright --> Guard --> Zap --> Juice
  Zap --> Runner --> Normalize --> Sarif --> Github
  Normalize --> Lifecycle

  classDef phase1 fill:#e6f4ff,stroke:#0969da,stroke-width:2px,color:#0a3069
  classDef later fill:#f6f8fa,stroke:#8c959f,stroke-width:1px,color:#24292f
  class Scope,Flow,Playwright,Guard,Zap,Juice,Runner,Normalize phase1
  class Human,Record,Generate,Validate,Sarif,Github,Lifecycle later
```

Blue = what Phase 1 delivers today. Gray = the Phase 2 / Phase 3 pieces that build on this foundation. Slanted boxes are file artifacts; rectangles are running code or services.

---

## What Phase 1 Proves

Four things must all be true for the gate to pass:

1. It authenticates through the proxy — the browser session logs in via ZAP.
2. It never leaves scope — every request is checked against an allow-list.
3. It produces a real detection — an actual finding against a live vulnerable app.
4. Unsafe configuration is refused before a single packet goes out.

The point is not that a command returns green. We show the target app, show ZAP, show where Playwright is launched, show where the login flow lives, then prove ZAP saw authenticated traffic.

---

## How the Pieces Fit Together

```mermaid
flowchart LR
  Flow["flow.py\nscripted app journey"]
  Playwright["Playwright\nChromium browser session"]
  ScopeGuard["scope guard\nallow-list enforcement"]
  Zap["OWASP ZAP\nproxy + scanner"]
  Juice["OWASP Juice Shop\napplication under test"]
  Records["out/records.json\nnormalized findings"]

  Flow --> Playwright
  Playwright --> ScopeGuard
  ScopeGuard -->|"allowed browser traffic"| Zap
  Zap --> Juice
  Zap -->|"alerts"| Records
```

* `flow.py` — the scripted login + business journey (hand-authored for Phase 1).
* Playwright — drives a real Chromium session, launched by the runner with ZAP set as its proxy.
* ScopeGuard — attached to the browser page; checks every request against the allow-list.
* OWASP ZAP — proxy during replay, then active scanner.
* OWASP Juice Shop — the real, intentionally vulnerable application under test.

---

## Demo Step 1 — Show the Wiring

Before running anything, make the moving parts visible:

* `compose.yaml` — three services: `juice` (app), `zap` (scanner/proxy on 8080), and `runner` (Python entrypoint receiving `--flow`, `--base-url`, `--zap-api`, `--zap-proxy`).
* `runner/replay.py` — where Chromium is launched with `proxy={"server": zap_proxy}`, so the browser session sends its traffic through ZAP.
* `security/dast/juice-shop/flow.py` — the login journey: register a user, fill the real login form, click login, wait for a JWT, then call `/rest/user/whoami` with `Authorization: Bearer <token>`.

Key handoff: the runner creates the Playwright `page`, attaches the scope guard, then calls `flow_module.run(page, base_url)`. So `page.goto`, `page.fill`, and `page.click` are real browser actions.

---

## Demo Step 2 — Bring Up the App and Scanner

Start only Juice Shop and ZAP first, so the audience can see them from the host browser:

* Juice Shop mapped to `127.0.0.1:3000` — the real intentionally vulnerable application.
* ZAP mapped to `127.0.0.1:8080` — running as a daemon, controlled through its API UI.

Before the scan, ZAP's sites/messages are empty or minimal. After Playwright runs through the proxy, ZAP's API becomes our independent proof source.

---

## Demo Step 3 — Replay-Only Proof

Run the replay before the active scan to make Playwright's role visible: it loads `flow.py`, creates a browser session, logs in, and returns the flow result.

Expected result:

```text
authenticated: true
token_present: true
whoami_status: 200
requests_seen: > 0
blocked: 0
```

Plus evidence files under `out/replay-evidence/`: `active-scan.har` and `screenshot.png`.

This is the smallest live proof that `flow.py` is being consumed by Playwright — we are replaying the session, not scanning yet.

---

## Demo Step 4 — The Gate Fails Closed

Prove the guardrail in isolation, before any scan traffic:

* Valid dev scope → `preflight OK: app_id=juice-shop environment_class=dev allow_list=['localhost']`
* Flip the environment to `prod` → the scan refuses to start:

```text
PREFLIGHT ABORT: environment_class='prod' is production — refusing to scan (NFR-2).
```

Same file, environment flipped. Zero traffic is sent — it aborts before touching the network.

---

## Demo Step 5 — The Full Scan (Main Event)

One command, one network — Juice Shop, ZAP, and the runner. The phases that scroll by:

1. Runner waits for Juice Shop + ZAP to come up.
2. Playwright registers a test user and logs in through the ZAP proxy.
3. Scope guard is live during replay — every request checked against the allow-list.
4. Bounded active scan runs against the allow-listed host only.
5. Raw ZAP alerts are normalized into detection records.

Successful gate output:

```text
"gate": {
  "authenticated": true,
  "scope_ok": true,
  "has_high_or_medium": true,
  "detections": <n>,
  "passed": true
}
```

`passed: true`, exit code 0 — all four Phase 1 gate conditions in one shot.

---

## Independent Proof of Authentication

`gate.authenticated: true` is self-reported by the flow — it proves login succeeded, not that ZAP saw the traffic.

For real proof, query ZAP's own message log for requests carrying an `Authorization` header:

```text
ZAP independently recorded N request(s) carrying an Authorization header
 - GET /rest/user/whoami ...
```

This isn't our runner talking — it's ZAP's own record. If the browser had bypassed the proxy, this list would be empty no matter what our code claims. The authentication proof has two parts: the flow reports it got a token, and ZAP's log shows an authenticated request went through.

---

## Guardrail — Scope Enforcement, Live

Point the runner at a host that is NOT on the allow-list (`localhost` instead of `juice`):

* Watch the request get blocked and logged.
* The scan fails — it is not silently ignored.
* Expect a non-zero exit and `"blocked": > 0` or a `ScopeViolation` abort.

Blocked requests are blocked, logged with a reason, and the scan fails closed — never silently continues.

---

## Evidence and Detection Output

Each normalized detection record in `out/records.json` includes:

* Rule id and severity
* Endpoint and parameter
* A stable fingerprint
* A pointer to the evidence for this scan

Note: replay HAR / screenshot evidence lives inside the container and is discarded on teardown by design. Durable evidence hosting is a Phase 2 / Phase 3 concern, tracked as a known gap — not a Phase 1 defect.

---

## Wrap-Up

* All four primary gate criteria met: authenticated, in-scope, ≥1 high/medium detection, unsafe config refused pre-traffic.
* Secondary checks green: HAR / screenshot captured (redacted), single-command container, run time well under the 15-minute budget.
* Versions pinned by digest (`versions.lock`) — this exact result is reproducible.
* Backup evidence: `pytest -q` → 107 passed, plus the last known-good containerized run.

Next up — Phase 2: LLM-generated `record` / `generate` / `validate` replacing the hand-authored `flow.py`, behind the code-safety boundary already scoped in the demo plan.

---

## Q&A Cheat-Sheet

| Likely question | Answer |
| --- | --- |
| Is this hitting a real vulnerability? | Yes — a real ZAP active scan against a real intentionally vulnerable app (Juice Shop), not a mock. |
| What if it had scanned prod? | It can't start — preflight checks `environment_class` before any network call. |
| What happens to blocked requests? | Blocked, logged with a reason, and the scan fails closed — never silently continues. |
| Is `flow.py` hand-written or AI-generated? | Hand-authored for Phase 1, to de-risk the ZAP + Playwright + auth integration before adding LLM variability in Phase 2. |
| Why not test against prod-like data? | Out of POC scope by design. |

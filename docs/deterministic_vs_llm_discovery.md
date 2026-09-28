# Deterministic vs. LLM-guided discovery — what we built, and what it found

How the two authoring paths differ, what each is measurably good at, and what running them
against three real applications taught us. Every number here comes from a run on this
project's own infrastructure between 2026-09-27 and 2026-09-28; nothing is projected.

---

## 1. The two paths

Both end at the same place — a committed bundle that a deterministic scanner replays — and
they differ only in how the authenticated surface is discovered.

```mermaid
flowchart LR
  subgraph AUTH["Authoring (the only place a model runs)"]
    direction TB
    C["app.yaml<br/>one file per application"]
    R["record<br/>walk the routes a human listed"]
    S["seed<br/>capture one authenticated session"]
    E["explore<br/>discover routes from one entry point"]
    G["generate<br/>trace → journey plan → flow.py"]
    V["validate<br/>allow-list + live auth replay"]
  end
  subgraph SCAN["Scanning (no model, ever — decision R1)"]
    direction TB
    RUN["runner.main<br/>replay the committed bundle"]
    ZAP["OWASP ZAP<br/>spider + bounded active scan"]
    N["normalize → fingerprint → coverage"]
    L["lifecycle diff<br/>new / open / resolved / not_scanned"]
    X["SARIF → GitHub Security tab"]
  end

  C --> R --> G
  C --> S --> E --> G
  G --> V --> RUN --> ZAP --> N --> L --> X

  classDef llm fill:#fff3cd,stroke:#9a6700,stroke-width:2px,color:#402e00
  classDef det fill:#e6f4ff,stroke:#0969da,stroke-width:2px,color:#0a3069
  class E,G llm
  class R,S,V,RUN,ZAP,N,L,X det
```

Yellow is where a model may run. Everything else is deterministic, and the scan half has no
model in it at all — that is decision **R1**, and it is what makes `resolved` mean anything:
if a model could change what a scan does, a finding disappearing might only mean the model
chose differently today.

### What each path actually is

| | Deterministic path | LLM-guided path |
|---|---|---|
| Entry | `record` walks `record.authenticated_routes` | `explore` starts from one seed route |
| Who chooses routes | A human, in `app.yaml` | The model, one validated action at a time |
| Who decides what may execute | Code | **Code** — the model only proposes |
| Repeatability | Exact | Varies run to run |
| Cost | None | ~1 API call per step |
| Fails to | Miss what nobody listed | Wander, and vary |

---

## 2. Where the model is allowed to act, and where it is not

The safety architecture is the reason the LLM path is usable at all. The model emits **data**;
deterministic code decides whether that data may execute, and renders it into code.

```mermaid
flowchart TD
  OBS["Observation<br/>links, forms, API calls, visited"] --> RED["redact<br/>strip tokens, cookies, PII"]
  RED --> LLM["Claude<br/>proposes ONE action as JSON<br/>action.schema.json"]
  LLM --> POL{"Deterministic policy"}
  POL -->|"scope: host allow-list"| P2{" "}
  P2 -->|"deny-list (per app)"| P3{" "}
  P3 -->|"writes: environment opt-in"| P4{" "}
  P4 -->|"never: session or credential"| EXEC["Playwright executes"]
  POL -.->|refused| OBS
  P2 -.->|refused| OBS
  P3 -.->|refused| OBS
  P4 -.->|refused| OBS
  EXEC --> TRACE["trace.json<br/>same artifact record produces"]

  classDef llm fill:#fff3cd,stroke:#9a6700,stroke-width:2px,color:#402e00
  classDef guard fill:#ffe0e0,stroke:#b42318,stroke-width:2px,color:#5f1512
  class LLM llm
  class POL,P2,P3,P4 guard
```

Four gates, each of which has refused something real during development:

| Gate | Caught, in practice |
|---|---|
| Scope allow-list | A captcha lesson pulling `google.com` — blocked during discovery, and it would have failed the scan |
| Per-app deny-list | `setup`, `phpinfo`, `captcha` on DVWA |
| Write opt-in | Every POST, until an environment is declared disposable |
| Session/credential rule | A password-change form that had already emptied DVWA's admin password once (see §5) |

---

## 3. What each path found — measured

All figures from DVWA, one application, same ZAP, same policy unless stated.

### The headline

| Path | Routes given by a human | Pages reached | High-severity findings |
|---|---|---|---|
| Hand-picked `record` | 5 | 5 | **5** |
| LLM `explore`, best run | **0** | 27 | **7** |

The autonomous run found **3 of the 5** the hand-picked run found, **plus 4 it never did**:

```mermaid
flowchart LR
  subgraph H["Hand-picked only — 2"]
    H1["XSS → brute (username)"]
    H2["SQLi → brute (username)"]
  end
  subgraph B["Both — 3"]
    B1["XSS → xss_r (name)"]
    B2["XSS → sqli (id)"]
    B3["SQLi MySQL → sqli (id)"]
  end
  subgraph A["Autonomous only — 4"]
    A1["Path Traversal → fi (page)"]
    A2["SQLi → sqli (Submit)"]
    A3["SQLi → sqli_blind (id)"]
    A4["SQLi → setup.php (create_db)"]
  end
  H --- B --- A
```

`sqli_blind` and `fi` are separate lessons nobody had listed. The two the hand-picked run
owned are both on `/vulnerabilities/brute/`, which autonomous discovery only learned to reach
after the per-page form fix in §5.

### Two other things worth knowing

**The scanner is exactly repeatable.** Two scans of one bundle produced byte-identical finding
sets — 213 fingerprints, 744 records, identical severity histograms. That is what makes the
lifecycle diff trustworthy, and it is why the variance below can be attributed to the model
rather than to ZAP.

**Surface beats posture.** Raising attack strength to high and the alert threshold to low added
23 findings and no highs. Adding four parameterised GETs — `?id=1&Submit=Submit` — took the
same scan from **0 highs to 5**. ZAP can only attack a parameter it has seen.

---

## 4. Onboarding cost, which is the point of the whole exercise

```mermaid
flowchart LR
  B0["Before<br/>edit 2 Python modules<br/>+ 2 JSON files<br/>~12 commands<br/>time: unmeasured"] --> B1["After<br/>1 app.yaml<br/>4 commands<br/>DVWA 4m20s · WebGoat 4m32s"]
  classDef a fill:#e6f4ff,stroke:#0969da,color:#0a3069
  class B1 a
```

Three applications are onboarded, deliberately different in every dimension that mattered:

| | juice-shop | dvwa | webgoat |
|---|---|---|---|
| Stack | Angular SPA | PHP | Spring Boot |
| Login | email | username | username |
| Session | JWT in `localStorage` | PHPSESSID cookie | JSESSIONID cookie |
| Proof of auth | `js` | `route` | `selector` |
| API convention | `/rest/`, `/api/` | none | `/service/` |
| Onboarding | the original | 4m20s | **4m32s, zero code changes** |

WebGoat is the one that proves the claim: `git status` after the whole loop showed one new
path, `security/dast/webgoat/`, and no diff to any module. DVWA did not — it needed the live
half of the auth-proof work finished first, and that is stated plainly in the plan.

---

## 5. What running it taught us that reading it did not

Every defect below was found by running the pipeline against a real application. None was
visible in a passing test suite, and several were invisible *because* the suite passed.

| Defect | How it presented | Why it hid |
|---|---|---|
| ZAP hijacks any target on its own port | A 400 with body `Bad Format`; the app never saw a request | Juice (3000) and DVWA (80) never collided — it took a third app on 8080 |
| The model's login block failed validation | LLM path fell back **silently**; you had to diff plans to notice | Tests patched the function that contained the bug |
| Absolute journey targets glued onto `base_url` | `page.goto("http://dvwahttp://dvwa/…")` | Only appeared once the LLM path worked at all |
| `f.id` returned an HTML element | Selector `#[object HTMLInputElement]` | A form's named controls shadow its properties — only DVWA had an `<input name="id">` |
| Every page's first form looked "already tried" | 2–3 form submissions per run regardless of budget | The selector `form >> nth=0` is page-relative; `visited` was global |
| **The loop changed DVWA's admin password** | Every later login failed | The guard judged the *selector*, which was anonymous; the page URL and field names both said "password change" |

The last one is the one to carry into any real environment. An autonomous loop submitted a
password-change form and destroyed the credential the scan depended on, and the rule written
to prevent precisely that did not fire. Actions are now judged by where they are and what they
carry, not only by what they target.

### And one measurement problem we have not solved

The same pipeline, same configuration, produced **7 highs, then 2, then 0** across runs. ZAP is
deterministic, so part of that is the model's route choices — and part is the application's own
state, which we do not record at all. We currently cannot answer *"why did this finding
disappear?"* from the artifacts. That is the strongest argument in the register for recording
scan truncation and application state alongside coverage (**W6-2**), and it should be
instrumentation rather than detective work.

---

## 6. Honest scorecard

| Claim | Status |
|---|---|
| An application onboards from configuration alone | **Proven** — WebGoat, zero code diff, 4m32s |
| The LLM can discover routes a human did not list | **Proven** — 4 highs unique to autonomous discovery |
| The LLM can reach parameters behind forms | **Proven** — `sqli`, `sqli_blind`, `brute`, `xss_r`, `fi` |
| Deterministic scanning is repeatable | **Proven** — byte-identical across two scans |
| Safety policy holds against an autonomous agent | **Partly** — four gates hold; one failed live and is now fixed |
| The LLM beats the deterministic proposer | **Not established** — best autonomous run wins, but variance is larger than the difference |
| A single run is a reliable measure | **No.** Repeat, or compare unions |

**The defensible summary:** autonomous discovery finds more than a human's list, at zero
marginal human cost, inside a policy that has now been tested by an agent actively trying to
click everything. What it does not yet do is find it *reliably in one run* — and the honest
response to that is measurement and instrumentation, not prompt tuning.

---

*Sources: runs on this machine 2026-09-27/28 against OWASP Juice Shop, DVWA and WebGoat
through ZAP 2.17.0; artifacts under `out/<app>/scans/<scan_id>/`. Commits `622650c` through
`665845a`. Test suite 394 passing.*

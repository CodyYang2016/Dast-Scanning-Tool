# Seeded-Session + LLM Exploration Loop — Design

**Status:** proposal (not yet built). Concrete design for the authenticated route-discovery work
deferred as **KI4**, following the direction adopted in **D10**. Reuses the **D8** code-safety
boundary and emits the same `record` artifacts, so nothing downstream of `record` changes.

## Goal

Remove the dependency on a human hand-recording an authenticated application flow for ZAP, while
keeping login reliability and deterministic safety. The human seeds the hard-to-automate parts
(auth + guardrails) once; the LLM does the tedious breadth work (route/form discovery and
coverage). Deterministic code decides what actually executes and what ZAP scans.

## Design principles

- **The human seeds; the LLM explores; deterministic code enforces safety.**
- The LLM only *suggests* actions — scope and action-policy validation, and replay, stay
  deterministic.
- Redact all secrets **before** anything reaches the LLM.
- **Fail closed:** if login cannot be proven or a branch is ambiguous, fall back to a
  seeded/hand-authored flow rather than scanning an unauthenticated or out-of-scope surface.

## Relationship to existing decisions

This is not a new direction — it is the concrete implementation of gaps already on record:

- **KI4 (authenticated route discovery is bounded by the recorded walk).** Today the scanned
  authenticated surface ≈ what a human `record` session walked, plus SPA auto-fetched XHR, plus
  ZAP's traditional spider. This design replaces the human walk with an LLM-driven exploration
  loop that expands breadth from a few seed routes — directly closing KI4.
- **D10 (OpenAPI first, crawl fallback, recorded walk floor).** This is the **crawl fallback**,
  upgraded with a human-seeded session so autonomous login (SSO/MFA/CAPTCHA) is no longer the
  blocker. It **complements, not replaces, the OpenAPI-first path**: prefer an OpenAPI spec where
  the app publishes an accurate one (deterministic, complete, no browser); use this seeded crawl
  for spec-less apps or to catch undocumented endpoints a spec omits.
- **D8 (LLM emits a JSON journey plan; deterministic code renders `flow.py`).** The exploration
  loop reuses this boundary exactly — the LLM emits constrained JSON, never executable code.
- **Artifact compatibility.** Stage 4 emits the same `trace.json` / `index.json` that
  `authoring/record.py` produces today, so `generate → validate → runner` are unchanged. In effect
  this is a **new mode of `record`** (an `explore` sibling), not a new pipeline.

## Split of labor

| Task | Owner | Rationale |
|------|-------|-----------|
| Login / auth (SSO, MFA, CAPTCHA) | Human (once) | Where autonomous login fails most often |
| Session capture / storage | Automated | Reuse the human-authenticated session |
| Route & form discovery | LLM | Tedious breadth work the LLM is good at |
| Scope / action policy | Human-defined, code-enforced | Safety must remain deterministic |
| Replay + ZAP scan | Deterministic code | Preserves the code-safety boundary |

## Stage 1 — Human seed (minutes, not a full recording)

The human provides four inputs, once per target:

1. **Authenticated session** — the human logs in once through a Playwright browser (handling
   SSO/MFA/CAPTCHA manually). Playwright saves `storageState` (cookies + tokens) to disk. This
   converts the unreliable part (autonomous auth) into a solved input.
2. **Seed routes** — 2–3 known authenticated URLs and any important API base paths, used as
   exploration entry points.
3. **Action deny-list** — destructive actions to never perform: logout, delete, purchase, password
   change, admin mutations, destructive POST/PUT/DELETE.
4. **Scope file** — the allow-list and environment class, validated by the existing preflight gate
   before any traffic.

### Seed config shape

```yaml
target:
  base_url: https://dev.app.example.internal
  scope_file: security/dast/app/scope.json
session:
  storage_state: .secrets/storageState.json   # gitignored
seed_routes:
  - /dashboard
  - /account/profile
  - /api/v1/orders
deny_actions:
  - logout
  - delete
  - purchase
  - change-password
  - admin-mutation
exploration:
  max_pages: 50
  max_depth: 4
  time_budget_minutes: 8
```

## Stage 2 — Session load & preflight

- Run **preflight** on the scope file; abort on production or missing allow-list (existing gate,
  NFR-2).
- Launch Playwright with the seeded `storageState` so the browser starts already authenticated.
- **Assert the session is live:** visit a seed route and confirm it is not redirected to login and
  does not return 401/403. If the session is dead, stop and ask the human to re-seed.

## Stage 3 — LLM-driven exploration loop

The loop repeats until a budget (pages, depth, or time) is hit:

1. **Observe** — Playwright captures the current page's DOM summary, links, forms, and observed
   XHR/fetch/API calls.
2. **Redact** — strip passwords, cookies, bearer tokens, CSRF values, and personal data; keep
   names, methods, paths, status codes, and redirect relationships.
3. **Propose** — the LLM receives the redacted state plus coverage so far and returns a constrained
   JSON action: follow an in-scope link, submit a non-destructive form, expand navigation, or visit
   an observed API route. It also flags unexplored branches to prioritize.
4. **Validate** — the proposed action is checked against the scope allow-list and the action
   deny-list. Anything out of scope or destructive is rejected before execution.
5. **Execute** — Playwright performs only validated actions.
6. **Capture** — the action, request/response metadata, and new routes are appended to the
   exploration trace.

### LLM action contract (JSON, not code)

```json
{
  "action": "follow_link | submit_form | visit_api | expand_nav",
  "target": {
    "method": "GET",
    "path": "/account/orders",
    "field_bindings": ["search_term"]
  },
  "reason": "unexplored authenticated branch off dashboard",
  "confidence": 0.82
}
```

## Stage 4 — Trace capture

The exploration produces the recorder output (`trace.json`, `index.json`) — the same artifact a
human recording would produce, but authored by the agent:

- Page URLs and navigation transitions
- Forms and links
- XHR/fetch/API requests with methods, paths, parameters, and status
- Authentication evidence (session artifact names, protected-route proof)
- Coverage map and unexplored branches

## Stage 5 — Deterministic flow render

A deterministic renderer converts the redacted JSON journey plan into an executable `flow.py`. The
LLM never emits executable code directly; this is the **D8 code-safety boundary** (`render_flow` in
`authoring/generate.py`, AST-compiled before use).

## Stage 6 — ZAP scan

The rendered flow:

- Establishes the authenticated session through the ZAP proxy (reusing seeded session artifacts).
- Replays discovered authenticated routes so ZAP sees them.
- Seeds ZAP with observed URLs and API endpoints.
- Runs passive analysis first.
- Runs bounded active scanning only against the approved allow-listed scope.

## Full pipeline

```
Human (once): log in + seed routes + deny-list + scope
   -> save authenticated session (storageState)
   -> preflight + load session + prove auth is live
   -> LLM exploration loop:
        observe -> redact -> LLM proposes JSON -> scope/action validate -> Playwright executes -> capture
   -> trace.json / index.json (agent-authored)
   -> deterministic flow render (flow.py)
   -> ZAP passive scan -> bounded active scan (allow-list only)
```

## Failure handling & fallback

- **Dead/expired session** — stop and request human re-seed; never scan unauthenticated.
- **Low-confidence or ambiguous branch** — skip or fall back to the seeded/hand-authored flow
  rather than guessing.
- **Scope violation** — block, log the reason, and fail closed.
- **Auth loss mid-exploration** — halt exploration; do not continue against a downgraded surface.

## Why this is the right compromise

- Removes the biggest automation blocker (login) with a few minutes of human effort instead of a
  full manual recording.
- Keeps determinism where it matters — scope and action safety stay human-defined and
  code-enforced.
- Improves coverage over a single hand-authored flow because the LLM expands breadth from the
  seeds.
- Preserves a clear fallback consistent with the existing Phase 2 risk mitigation.

---

## Open questions / review notes

These are the tensions surfaced in review — decisions to resolve before building, not settled
positions.

1. **Decouple exploration from scanning to protect the FR-L2 lifecycle diff (load-bearing).**
   The fingerprint/lifecycle system rests on the invariant that *two scans of an unchanged app
   produce byte-identical fingerprints* (`fingerprint.py`, `lifecycle_diff.py`). An LLM in the loop
   on every scan is nondeterministic: different runs discover different routes → different endpoints
   scanned → findings blink in and out for reasons unrelated to a real fix → spurious
   `new`/`resolved` labels (exactly the "noisy lifecycle diff" risk named in D10). Proposed stance:
   treat LLM exploration as a **trace-authoring** step whose output (`trace.json`) is reviewed and
   **committed**; scans replay the *committed* trace deterministically. `generate` is already
   idempotent (FR-G4: same trace → byte-identical `flow.py`), so this preserves FR-L2. Exploration
   becomes an occasional "re-map the app" activity, decoupled from repeatable monitoring scans.

2. **Deny-list enforcement must be deterministic, not an LLM judgment.** Scope is host-based and
   trivially enforced; "logout / delete / purchase / admin-mutation" are *semantic*. The design must
   not trust the LLM's `"non-destructive"` self-label (that violates principle 2). Fail-closed
   answer: **default-deny all state-changing methods (POST/PUT/PATCH/DELETE)** during exploration
   except an explicit allow-list of known-safe forms, plus per-app deny path patterns. This is the
   `avoid_action_list` enforcement mechanism left unspecified in the issue-#1 contract-freeze
   checklist.

3. **Session expiry mid-active-scan.** Seeding solves login, but the seeded token can expire during
   the (minutes-long) ZAP active scan (Stage 6), silently downgrading to an unauthenticated surface.
   Failure handling covers auth loss mid-*exploration* but not mid-*scan*. Needs a continuous
   logged-in check during the scan and a defined re-auth (or halt) story — noting re-auth is the
   part deliberately deferred to the human.

4. **The redactor surface grows.** Today's `record` is "secret-free by construction" (it captures
   names/URLs, not values — the documented Phase 2 gap). This design feeds **live DOM + XHR response
   bodies** to the LLM, so the redactor must scrub response bodies, PII, and CSRF, not just header
   names. Build on `runner/evidence.py::redact_har` (JWT + token-field regexes, sensitive-header
   list), but this needs its **own adversarial test suite** — higher stakes than the current partial
   redactor.

5. **Keep BOTH safety layers during exploration.** The runner's real guarantee is two independent,
   fail-closed layers (D2/D6): action/preflight validation **and** the `page.route` request-boundary
   guard. An in-scope `follow_link` can still fire an out-of-scope XHR. Retain the request-boundary
   guard during exploration; do not rely on action-validation alone.

6. **Phase-split the scope policy.** "Block, log, fail closed" is right for the active scan, but a
   hard fail on the first stray request would abort the whole crawl during discovery. Adopt KI4's
   split: **block-and-continue during discovery, block/log/fail during the active scan.**

7. **Pilot reality check.** The headline benefit — seeding a hard SSO/MFA/CAPTCHA login — **will not
   be exercised by Juice Shop**, whose login is already trivially automatable (the current `flow.py`
   does it; its JWT lives in `localStorage`, so `storageState` seeding works but isn't *needed*). On
   the pilot the demonstrable win is the **coverage/breadth** improvement (the KI4 fix), not the auth
   seeding; the seeding value shows on real enterprise targets. Worth stating so the demo isn't
   oversold.

## Suggested staging

Split so the high-value/low-risk half lands first, and the LLM bet stays opt-in:

- **Phase A (low LLM risk):** session seeding + "prove auth is live" (Stage 2) + replay a seeded
  `storageState` through the ZAP proxy, with a hand-authored/seeded fallback. Removes the login
  dependency with almost no nondeterminism.
- **Phase B (behind an opt-in `--explore` / `--crawl` flag, per KI4):** the LLM exploration loop
  (Stage 3), producing a *committed* trace; deterministic scans replay it. The default flow stays
  deterministic.

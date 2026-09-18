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
- **Scope violation** — block and log the reason. Handling is **phase-split** (see open question 5):
  *block-and-continue* during discovery (reject the out-of-scope action, keep exploring) and
  *block/log/fail-closed* during the active scan.
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

## Decisions (resolved in review)

These were open tensions in the first draft; the team resolved them in review.

**R1 — The LLM runs only at authoring/discovery time; monitoring scans replay a committed bundle.**
The LLM is *never* in the loop on a routine scan. There are two run modes:

- **Authoring / discovery run** (LLM in the loop, occasional): seeded session → exploration loop →
  `trace.json` → `generate` → the flow bundle (`flow.py`, `scope.json`, `zap-policy`,
  `manifest.json`, `lock`, `auth.json`). A human reviews and **commits** it.
- **Monitoring scan run** (no LLM, repeatable): the runner replays the *committed* bundle through
  ZAP; this feeds `lifecycle_diff.py`, and it is fully deterministic.

This maps onto the existing architecture with no structural change — `record`/`generate`/`validate`
are already authoring-time and the runner is already the repeatable scan, so this is effectively a
new *mode of `record`*. Because the output is human-reviewed before use, the exploration loop
**does not itself need to be deterministic** (a human walk isn't either) — the review step is
load-bearing instead. This preserves FR-L2, and FR-G4 idempotency (same trace → equivalent bundle)
still holds downstream.

*Pinned artifact:* commit **both** `trace.json` (the reviewable "what the LLM discovered") and the
generated bundle, but treat the **bundle** as the source of truth for reproducibility. *(Default —
override if you'd rather commit the trace only and always regenerate.)*

**R2 — Coverage-aware `resolved`: assert a fix only for (route × rule) pairs the scan actually exercised.**
A finding disappearing between scans has two very different causes that must not be conflated:
*fix-driven* (same surface tested, finding genuinely gone) vs *coverage-driven* (we never looked
there this run — a re-authored flow dropped the route, or the ZAP rule that found it was disabled).
Only the first is a real `resolved`.

So the lifecycle diff becomes **coverage-aware at (route × rule) granularity**. A finding's route is
already the `endpoint_pattern` component of its fingerprint (carried as `endpoint` on every record),
and its rule is `rule_id`. At scan time we capture the set of `(endpoint_pattern, rule_id)` pairs the
scan **actually exercised — from ZAP's real accessed-URL / active-scan data**, not the flow's
*intended* routes — canonicalized through the same `endpoint_pattern()` so it is directly comparable.
Then:

```
previous-only finding F, with pair (R, rule) = (F.endpoint_pattern, F.rule_id):
  (R, rule) exercised this scan     -> resolved      (we tested it; it's gone -> real fix)
  (R, rule) NOT exercised this scan -> not_scanned   (we didn't test for it; no fix claim)
```

This adds a `not_scanned` value to the record `status` enum (`{new, open, resolved, not_scanned}`)
and persists the exercised-pair set per scan in the lifecycle state (today `save_state` stores
`scan_id` + `records`; add `coverage`). Using **ZAP's actual coverage** plus the **rule** dimension
is what keeps `resolved` honest — notably it stops the issue-#7 "disable the SQLi rule for scan 2"
case from being mislabeled a fix: the route is still covered, but the SQLi rule wasn't run, so the
pair is *not exercised* → `not_scanned`, not `resolved`.

## Open questions / review notes

Still open — decisions to resolve before building, not settled positions.

1. **Deny-list enforcement must be deterministic, not an LLM judgment.** Scope is host-based and
   trivially enforced; "logout / delete / purchase / admin-mutation" are *semantic*. The design must
   not trust the LLM's `"non-destructive"` self-label (that violates principle 2). Fail-closed
   answer: **default-deny all state-changing methods (POST/PUT/PATCH/DELETE)** during exploration
   except an explicit allow-list of known-safe forms, plus per-app deny path patterns. This is the
   `avoid_action_list` enforcement mechanism left unspecified in the issue-#1 contract-freeze
   checklist. Concretely, Stage 3's `"submit a non-destructive form"` means **a form on the
   known-safe allow-list** — the LLM's own `"non-destructive"` label is never authoritative; the
   deterministic method/path check decides.

2. **Session expiry mid-active-scan.** Seeding solves login, but the seeded token can expire during
   the (minutes-long) ZAP active scan (Stage 6), silently downgrading to an unauthenticated surface.
   Failure handling covers auth loss mid-*exploration* but not mid-*scan*. Needs a continuous
   logged-in check during the scan and a defined re-auth (or halt) story — noting re-auth is the
   part deliberately deferred to the human.

3. **The redactor surface grows.** Today's `record` is "secret-free by construction" (it captures
   names/URLs, not values — the documented Phase 2 gap). This design feeds **live DOM + XHR response
   bodies** to the LLM, so the redactor must scrub response bodies, PII, and CSRF, not just header
   names. Build on `runner/evidence.py::redact_har` (JWT + token-field regexes, sensitive-header
   list), but this needs its **own adversarial test suite** — higher stakes than the current partial
   redactor.

4. **Keep BOTH safety layers during exploration.** The runner's real guarantee is two independent,
   fail-closed layers (D2/D6): action/preflight validation **and** the `page.route` request-boundary
   guard. An in-scope `follow_link` can still fire an out-of-scope XHR. Retain the request-boundary
   guard during exploration; do not rely on action-validation alone.

5. **Phase-split the scope policy.** "Block, log, fail closed" is right for the active scan, but a
   hard fail on the first stray request would abort the whole crawl during discovery. Adopt KI4's
   split: **block-and-continue during discovery, block/log/fail during the active scan.**

6. **Pilot reality check.** The headline benefit — seeding a hard SSO/MFA/CAPTCHA login — **will not
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

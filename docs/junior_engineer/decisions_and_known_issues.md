# Decisions & Known Issues

A running log of design decisions we've committed to and known limitations we've consciously
deferred. Each entry says what, why, status, and — for deferred items — the trigger that
should make us act.

---

## Index
- D1 — stream by default (scalability convention)
- D2 — runner safety model: two independent layers, fail-closed
- D3 — production rejection is explicit + case-insensitive (defense-in-depth)
- D4 — FR-S4 out-of-scope policy: block, log, fail
- D5 — scope granularity is host-based for the POC
- D6 — scope matching: exact allow, wildcard deny, deny-precedence, fail-closed
- D7 — replay topology: browser proxied through ZAP → app scope allow-lists `juice`
- KI1 — endpoint_pattern id-collapsing heuristic (deferred fix)
- KI2 — scope-enforcement edge cases (deferred)
- KI3 — Juice Shop container exits (133) between sessions

---

## D1 — Scalability convention: stream by default (ADOPTED)

**Decision.** Pipeline stages process detections as a **stream**, never materializing the
whole set unless a stage genuinely needs it. Concretely:

- `detections/normalizer.py` `normalize()` takes an *iterable of alerts* and **yields**
  records (a generator), so memory stays flat regardless of scan size.
- All whole-file reading is isolated in one function, `iter_alerts()` — the single **swap
  point** to drop in an incremental JSON parser (e.g. `ijson.items(fh, "alerts.item")`) later.
- Output is written incrementally (`write_json_array` streams the array; `write_ndjson`
  emits newline-delimited JSON, the most stream-friendly interchange).

**Why.** The raw ZAP export before capping was 5.2 MB / 2,497 alerts; production apps can
produce far larger reports. The old code did three full in-memory copies (load dict → build
full list → serialize full string). Streaming interfaces remove that ceiling.

**What we did NOT do (yet).** `iter_alerts()` still calls `json.load` (whole-file) — the
*interface* is streaming-ready, but the incremental parser is deferred (no dependency added
today). Because `normalize()` already consumes a lazy iterable, that swap is a one-function
change with zero downstream impact.

**Rule for future components (SARIF export, lifecycle diff, runner):** accept iterables,
yield results, and hold only bounded aggregates in memory. The lifecycle diff needs the full
*fingerprint set* — but that's 64-char strings, not full records, so it stays small. SARIF is
one document but can be written incrementally.

**Guarded by tests:** `tests/test_normalizer.py::test_normalize_is_a_lazy_generator` (feeds an
endless source and takes one — would hang if eager), plus `iter_alerts` / writer round-trip
tests.

---

## KI1 — `endpoint_pattern` id-collapsing is a heuristic (DEFERRED fix: per-app route config)

**Issue.** `detections/fingerprint.py` collapses any all-digit / UUID / long-hex path segment
to `{id}` (`/weather/456` → `/weather/{id}`). This is a *guess* and fails both ways:

- **False positive:** a meaningful, stable numeric segment (a location code, a year like
  `/reports/2024`, a category) is collapsed → distinct endpoints **share one fingerprint** →
  findings collide and the lifecycle diff mislabels them.
- **False negative:** a variable non-numeric segment (a slug/username like `/users/jane-doe`)
  is **not** collapsed → the fingerprint churns across scans → an unchanged finding looks
  "resolved then new."

**Why deferred.** At POC scale, the pilot app (Juice Shop) doesn't exercise these edge cases,
and `endpoint_pattern` feeds the **frozen fingerprint** — changing it is a contract change
(re-pin the worked examples), which we don't want to churn mid-build.

**Chosen direction when we act (in order of preference):**
1. **OpenAPI/Swagger route templates** — if the target app publishes a spec, classify
   segments by ground truth (`/weather/{cityId}`), not a regex. Most correct.
2. **Per-app route config** (`contracts/routes/<app>.yaml`) — explicit, reviewed regex→
   template rules, versioned alongside the other contracts. The pragmatic default.
3. **Statistical collapse** — only collapse a numeric segment when the scan saw the same
   skeleton with *many distinct values*. A cheap accuracy boost, no config, layerable later.

**Trigger to act.** The first time a real target either (a) has meaningful numeric path
segments, or (b) shows fingerprint churn / collisions across two scans of an unchanged app.
Treat any change as a fingerprint-contract change: bump `fingerprint_version` and re-pin the
worked examples in `contracts/README.md` (per that file's change policy).

---

## D2 — Runner safety model: two independent layers, fail-closed (ADOPTED)

**Decision.** The runner never relies on a single check to keep traffic safe (NFR-2). Two
independent layers:
1. **Preflight** (`runner/preflight.py`) — validates `scope.json` *before any traffic* and
   aborts on unsafe config (built now; FR-S3).
2. **Request-boundary enforcement** — a Playwright `page.route` interceptor that blocks any
   non-allow-listed host *during* the scan (component 3; FR-S4).

Both **fail closed**: any doubt → raise `PreflightError` / non-zero exit / blocked request.
`check_scope` is a pure function (dict in, raise/return) so the safety logic is unit-tested
with no I/O, independent of the schema and the filesystem.

**Why.** A single guardrail is one bug away from sending unsafe traffic. Layering means a
defect in one still leaves the other standing.

**How to interrogate later.** See `tests/test_preflight.py` (adversarial: prod, missing/empty
allow-list, missing file, schema violations) and `runner_design.md` §2. To revisit, change the
layer boundaries there and re-run the safety suite.

## D3 — Production rejection is explicit + case-insensitive (ADOPTED)

**Decision.** `check_scope` rejects `environment_class` ∈ {`prod`, `production`} (any case),
*in addition to* the schema enum (`dev|test|staging`). It does not rely on the schema alone.

**Why.** The schema is editable; a well-meaning change could add `prod` to the enum and
silently enable production scanning — the exact catastrophe NFR-2 forbids. The explicit
denylist is defense-in-depth so that can't happen from a schema edit.

**How to interrogate later.** `_PROD_VALUES` in `runner/preflight.py`; tests
`test_prod_aborts` / `test_prod_case_insensitive_aborts`. If the org uses other production
labels (e.g. `live`, `prd`), add them to `_PROD_VALUES` (and a test) — don't loosen it.

## D4 — FR-S4 out-of-scope policy: block, log, fail (ADOPTED)

**Decision.** An in-flight request to a non-allow-listed (or deny-listed) host is **blocked,
logged, and fails the scan** (non-zero exit) — not block-and-continue.

**Why.** For a safety POC, an out-of-scope request is a scope violation, not a warning; the
scan result is only trustworthy if the boundary held. Failing loudly surfaces
misconfiguration immediately.

**How to interrogate later.** Enforced by component 3 (`runner/scope_guard.py`, todo). If a
"block-and-continue" mode is ever wanted (e.g. noisy third-party assets), add it as an
explicit opt-in flag, never the default.

## D5 — Scope granularity is host-based for the POC (ADOPTED, with a known gap)

**Decision.** The allow/deny lists match on **host** (per `scope.schema.json`). Scheme, port,
path, redirects, IPv6/IP-literal forms are not part of matching for the POC.

**Why.** Host-based matching is enough to demonstrate the guardrail on the single pinned pilot
app; a full matching matrix is production hardening (out of scope, requirements §3.2).

**How to interrogate later.** See KI2 for the deferred edge cases and the trigger to expand.

---

## D6 — Scope matching rules: exact allow, wildcard deny, deny-precedence, fail-closed (ADOPTED)

**Decision.** The request-boundary guard (`runner/scope_guard.py`) matches on **host** (D5)
with these precise rules:
- **allow-list** = exact host, **case-insensitive** (no wildcards);
- **deny-list** = **wildcard** patterns via `fnmatch` (e.g. `*.google-analytics.com`);
- **deny precedence** — a deny match blocks even an allow-listed host;
- **scheme and port are ignored** (`http://localhost:3000` ≡ host `localhost`);
- **fail closed** — a request with no parseable host is blocked.

**Why.** Exact allow keeps the in-scope set unambiguous and small (the pilot has one host);
wildcard deny is what real deny-lists look like (whole analytics/ad domains). Deny-precedence
and fail-closed both bias toward *not* sending traffic when uncertain — the NFR-2 stance.

**How to interrogate later.** `ScopeGuard._evaluate` in `runner/scope_guard.py`; tests
`test_denylist_wildcard_blocks`, `test_deny_precedence_over_allow`, `test_no_host_blocked`,
`test_port_ignored`, `test_scheme_ignored`. If wildcard *allow* is ever needed, add it
explicitly with tests — don't silently widen exact matching. Port/scheme sensitivity and other
host forms are the deferred KI2 edge cases.

---

## D7 — Replay topology: browser proxied through ZAP; app scope allow-lists `juice` (ADOPTED)

**Decision.** In `runner/replay.py`, Chromium is proxied through the ZAP daemon, so **ZAP
resolves the target host**. With ZAP in a container on the `dast` network, the reachable target
is `http://juice:3000`; therefore the app scope `security/dast/juice-shop/scope.json`
allow-lists **`juice`**. The canonical `contracts/scope.json` keeps `localhost` as the
documented example.

**Why.** A browser using an HTTP proxy hands the full URL to the proxy for DNS. `localhost`
from inside the ZAP container is ZAP itself, not Juice Shop — so the browser must request
`juice:3000`, which only resolves inside the docker network (at ZAP).

**How to interrogate / when it changes.** Step 6 (containerization) bundles browser + ZAP +
target under one host view, at which point `localhost` works uniformly and the app scope can
collapse back to the canonical value. Until then, two scope instances coexist by design:
`contracts/scope.json` (example, `localhost`) and the app scope (`juice`). Both pass preflight
and the same schema.

---

## KI2 — Scope-enforcement edge cases (DEFERRED)

**Issue.** Host-only matching (D5) does not handle: alternate ports, scheme differences,
redirect chains to out-of-scope hosts, host aliases, IPv6/IP-literal forms.

**Why deferred.** Not exercised by the pilot app; production hardening per requirements §3.2.

**Trigger to act.** Onboarding any target where these forms occur, or any evidence a request
slipped the host-only check. Expansion goes in `runner/scope_guard.py` with adversarial tests
per new form.

---

## KI3 — Juice Shop container exits (133) between sessions (OPERATIONAL)

**Issue.** The `bkimminich/juice-shop` container is observed exiting with code 133 after a
period of inactivity, so `localhost:3000` starts returning connection failures between work
sessions. ZAP (long-lived) stays up; only the pilot app drops.

**Impact.** Purely local/dev-loop friction — not a product defect. A run started against a
dead app fails fast (preflight passes, replay's first navigation errors).

**Workaround.** Re-create it before a run:
`docker rm -f juice && docker run -d --name juice --network dast -p 3000:3000 bkimminich/juice-shop`,
then confirm `curl -s -o /dev/null -w '%{http_code}' localhost:3000` is 200 and
`docker exec zap curl -sS -m10 -o /dev/null -w '%{http_code}' http://juice:3000/` is 200.

**Trigger to act.** If it recurs mid-scan (not just between sessions), pin a specific Juice
Shop image tag in the lock file (NFR-1, step 6) and add a `--restart=unless-stopped` policy or
a healthcheck+auto-recreate in the containerized runner (step 6).

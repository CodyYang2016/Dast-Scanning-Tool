# Scan Runner — Design & Build Plan (FR-S1–S5, R2, E1, NFR-2/4/5)

The runner is Phase 1 of the demo plan (`docs/dast_poc_demo_plan.md`) — the **critical path**
and the **safety boundary**. It turns a hand-authored flow + `scope.json` into a *safe,
authenticated, scope-bounded* ZAP scan whose raw output feeds the already-built results
pipeline (`detections/`). This doc is the living overview; each component gets a frozen
test-first spec here as it's built (preflight is specified in §7 below).

## 1. Where this fits

```
                          ┌──────────────── runner/ (this doc, Phase 1) ────────────────┐
scope.json ─▶ preflight ─▶ replay (Playwright ──▶ ZAP proxy) ─▶ scope-enforced active scan ─┐
   (S3,NFR-2)  ABORT if      (S1,R2)   page.route block/log/fail (S4,NFR-4)     (S1,S2)      │
   unsafe                                                                                     ▼
                                                                              raw ZAP JSON ──▶ detections/ (DONE)
                                                                                normalizer→SARIF→GitHub / diff
                            evidence: HAR + screenshot (E1) ───────────────────────────────┘
```

The whole **results half is already built and tested** (normalizer, fingerprint, SARIF,
GitHub upload, lifecycle diff). The runner produces the *live* input those consume, replacing
the `sample_zap_output.json` fixture.

## 2. Safety model (NFR-2 — the single most important guardrail)

Two independent layers, so a bug in one doesn't send unsafe traffic:

1. **Preflight (before any traffic):** refuse to run if `scope.json` is missing, has no
   `environment_class`, is `prod`, or has no allow-list. Fail closed. (§7, built first.)
2. **Request-boundary enforcement (during the scan):** a Playwright `page.route` interceptor
   blocks any request to a host not in `fqdn_allow_list` (or in `fqdn_deny_list`), logs each
   decision (NFR-4), and **fails the scan** — the frozen **block/log/fail** policy (FR-S4).

## 3. Build order (from the demo plan's Phase 1 completion plan)

Pure-Python, testable-without-a-live-scan pieces come first, to lock the safety contract
before the risky auth-replay spike.

| # | Component | File | FRs | Testability | Status |
|---|-----------|------|-----|-------------|--------|
| 1 | **Preflight safety gate** | `runner/preflight.py` | S3, NFR-2 | **pure — test-first** | ✅ done |
| 2 | Hand-authored flow + auth replay | `security/dast/juice-shop/flow.py`, `runner/replay.py` | S1, R2 | live (spike) | ✅ done |
| 3 | Request-boundary scope enforcement | `runner/scope_guard.py` | S4, NFR-4 | mostly pure — test-first | ✅ done |
| 4 | Active-scan orchestration | `runner/scan.py` | S1, S2 | live; ports capture script | ✅ done |
| 5 | Evidence capture | `runner/evidence.py` | E1 | live + pure redactor | ✅ done |
| 6 | Packaging + version pins | `Containerfile`, `compose.yaml`, `versions.lock` | NFR-5, NFR-1 | built + run | ✅ done |
| 7 | Wire the gate | `runner/main.py` | all | integration | ✅ done |

**Reusable head start:** `runner/capture_zap_fixture.sh` already proves the exact ZAP API
choreography step 4 needs (`accessUrl` → spider → bounded `ascan` → alerts export, host-bounded).

## 4. Testing strategy per component

- **Pure/test-first (1, 3):** frozen objective tests before code — same discipline as the
  `detections/` modules. Oracles = the safety rules stated independently + the committed
  contracts (`scope.json` / `scope.schema.json`).
- **Live/integration (2, 4, 5, 7):** validated by driving the real ZAP + Juice Shop containers
  and observing behaviour (authenticated request seen by ZAP; injected out-of-scope host
  blocked in the log; end-to-end under 15 min). Not forced into brittle unit tests.

## 5. Frozen contract decisions used by the runner

- **FR-S4 policy: block, log, fail** — an out-of-scope request is blocked, recorded, and the
  scan exits non-zero. (Not block-and-continue.)
- **Scope granularity: host-based** for the POC (allow-list holds exact hosts, per
  `scope.schema.json`); scheme/port/redirect edge cases are documented known gaps.
- **Prod rejection is explicit and case-insensitive** (`prod`, `Prod`, `production`, …) —
  defense-in-depth beyond the schema enum, so loosening the schema can't re-enable prod.

## 6. Out of scope (known gaps, per requirements §3.2 and the demo plan)
Scope edge cases (IPv6, host aliases, alternate ports, redirect chains, IP literals);
production/blackbox scanning; durable evidence hosting beyond a CI artifact; GitHub alert
auto-resolution semantics.

---

## 7. Component 1 — `runner/preflight.py` (FROZEN test-first spec)

**Built test-first:** `tests/test_preflight.py` + this spec are frozen *before* the code, so
the implementation must conform to them.

### Purpose
Refuse to scan an unsafe configuration **before any network traffic** (FR-S3, NFR-2). This is
the gate every later step runs behind.

### Frozen API
```python
# runner/preflight.py

class PreflightError(Exception):
    """Raised when a scope is unsafe/invalid to scan. Callers must abort (no traffic)."""

def check_scope(scope: dict) -> None:
    """Safety checks on an in-memory scope. Raise PreflightError if unsafe. Pure; no I/O.
    Rejects: missing environment_class; environment_class prod/production (case-insensitive);
    missing or empty fqdn_allow_list."""

def preflight(scope_path: str, schema_path: str = <contracts/scope.schema.json>) -> dict:
    """Load scope.json, run check_scope(), then full JSON-Schema validation. Return the
    validated scope dict, or raise PreflightError (missing file, bad JSON, schema violation,
    or unsafe config). Never performs network I/O."""

def main(argv=None) -> int:
    """CLI: --scope PATH [--schema PATH]. Exit 0 if safe; non-zero (with a clear stderr
    message) if not — so a scan wrapper must stop on non-zero."""
```

### Frozen behavioural decisions
- **Fail closed:** any doubt → raise / non-zero exit. Silence is never "safe".
- **Order:** explicit safety checks first (clear, safety-specific messages), then full schema
  validation (structural completeness). Prod is caught by the explicit check *and* the schema
  enum.
- **`check_scope` is pure** (dict in, raise/return) so it's unit-testable with no files.
- **`preflight` returns the validated scope** on success for the caller to use.

### Frozen objective tests (`tests/test_preflight.py`)
Oracle = the safety rules stated independently + the committed `scope.json`/`scope.schema.json`.

| Test | Asserts |
|------|---------|
| `test_valid_scope_passes` | a well-formed scope raises nothing |
| `test_committed_scope_passes` | the real `contracts/scope.json` passes preflight (ground truth) |
| `test_prod_aborts` | `environment_class == "prod"` → PreflightError |
| `test_prod_case_insensitive_aborts` | `PROD`, `Prod`, `production`, `Production` all abort |
| `test_missing_environment_class_aborts` | no `environment_class` → abort |
| `test_missing_allow_list_aborts` | no `fqdn_allow_list` → abort |
| `test_empty_allow_list_aborts` | `fqdn_allow_list == []` → abort |
| `test_missing_file_aborts` | nonexistent scope path → abort |
| `test_schema_violation_aborts` | unknown field (additionalProperties:false) → abort |
| `test_invalid_environment_class_aborts` | `environment_class == "qa"` (not in enum) → abort |
| `test_preflight_returns_validated_scope` | returns the scope dict on success |
| `test_cli_exit_zero_on_valid` / `test_cli_exit_nonzero_on_prod` | CLI exit codes gate a scan |

Plus a **"does it bite?"** check after implementation: neuter the prod check and confirm
`test_prod_*` fail; then revert.

### Verify (after implementation)
```bash
pytest tests/test_preflight.py -q      # green only once implemented
pytest -q                               # whole suite stays green
python -m runner.preflight --scope contracts/scope.json   # exit 0
```

---

## 8. Component 3 — `runner/scope_guard.py` (FROZEN test-first spec)

**Built test-first.** The **second, independent** safety layer (D2): where preflight validates
config before traffic, the scope guard enforces the boundary **on every in-flight request**
during the scan — the FR-S4 / NFR-4 guardrail. The decision logic and the block/log/fail
bookkeeping are pure and unit-tested; only the `page.route` wiring into a live Playwright page
is integration (and even that is tested with a fake route object).

### Purpose
Block any request to a host not in `fqdn_allow_list` (or matching `fqdn_deny_list`), **log**
each decision (NFR-4), and **fail** the scan if any violation occurred (D4 / FR-S4).

### Frozen decisions
- **Host-based matching (D5):** compare on hostname only; **scheme and port are ignored**
  (`http://localhost:3000` and `https://localhost` both match host `localhost`).
- **Allow-list = exact host, case-insensitive.** Deny-list = **wildcard** patterns via
  `fnmatch` (e.g. `*.google-analytics.com`).
- **Deny precedence:** a host matching the deny-list is blocked even if it is allow-listed.
- **Fail closed:** a request with no parseable host is **blocked** ("no host").
- **Block / log / fail (D4):** blocked requests are recorded as violations; `route_handler`
  aborts them; `raise_if_violated()` fails the scan afterward (the runner calls it).
- **Structured decision record (NFR-4):** each decision carries `allowed`, `url`, `host`,
  `reason`.

### Frozen API
```python
# runner/scope_guard.py

class ScopeViolation(Exception): ...

@dataclass
class Decision:
    allowed: bool
    url: str
    host: str | None
    reason: str

def host_of(url: str) -> str | None:            # hostname, lowercased, port stripped; None if absent

class ScopeGuard:
    def __init__(self, scope: dict): ...
    def check(self, url: str) -> Decision:       # records + logs; appends to violations if blocked
    @property
    def decisions(self) -> list[Decision]: ...
    @property
    def violations(self) -> list[Decision]: ...
    @property
    def ok(self) -> bool: ...                    # no violations
    def raise_if_violated(self) -> None: ...      # raise ScopeViolation if any (FR-S4 "fail")
    def route_handler(self, route) -> None: ...   # Playwright: allowed -> route.continue_(); else route.abort()
```

### Frozen objective tests (`tests/test_scope_guard.py`)
Oracle = hand-defined scope + URLs with known allow/block outcomes (host/set logic).

| Test | Asserts |
|------|---------|
| `test_allowlisted_host_allowed` | host in allow-list → allowed |
| `test_non_allowlisted_host_blocked` | host not in allow-list → blocked |
| `test_denylist_wildcard_blocks` | `*.google-analytics.com` blocks `www.google-analytics.com` |
| `test_deny_precedence_over_allow` | host in allow AND deny → blocked |
| `test_port_ignored` | `http://localhost:3000` allowed when `localhost` allow-listed |
| `test_scheme_ignored` | `https://localhost` allowed same as `http` |
| `test_host_case_insensitive` | `LOCALHOST` allowed |
| `test_no_host_blocked` | url with no host → blocked (fail closed) |
| `test_check_records_decision` | `check()` appends to `decisions` |
| `test_violation_recorded_and_ok_false` | a block → `violations` non-empty, `ok` is False |
| `test_raise_if_violated` | raises after a block; does not raise when clean |
| `test_route_handler_allows` | fake in-scope route → `continue_` called, not `abort` |
| `test_route_handler_blocks` | fake out-of-scope route → `abort` called, not `continue_` |
| `test_injected_out_of_scope_blocked` | FR-S4: injected off-list host is blocked + fails |
| `test_decision_has_structured_fields` | NFR-4: decision has allowed/url/host/reason |

Plus a **"does it bite?"** check: make `check()` always allow and confirm the block tests fail.

### Verify (after implementation)
```bash
pytest tests/test_scope_guard.py -q     # green only once implemented
pytest -q
```

---

## 9. Component 2 — auth replay (`runner/replay.py` + flow) — LIVE-VALIDATED

Not test-first (agreed): this is the integration spike. Validated by driving the real
containers and confirming ZAP observes authenticated traffic. Only the pure `load_flow` helper
has unit tests (`tests/test_replay.py`); the browser path is exercised live.

### What it does
`runner/replay.py` launches Chromium with its proxy pointed at the ZAP daemon, attaches the
scope guard as a `page.route` interceptor (safety layer 2), runs preflight first (safety layer
1), then executes the hand-authored `security/dast/juice-shop/flow.py`: register a test user →
form login → visit an authenticated view (`#/basket`) → `whoami`.

### Topology decision (why the app scope allow-lists `juice`, not `localhost`)
The browser is proxied through ZAP, so **ZAP resolves the target host, not the browser**. With
ZAP in a container on the `dast` network, the reachable target is `http://juice:3000`
(`localhost:3000` would resolve to ZAP's own container). So the app scope
(`security/dast/juice-shop/scope.json`) allow-lists **`juice`**. The canonical
`contracts/scope.json` still uses `localhost` as the documented example; **step 6
(containerization) unifies these** by running the browser + ZAP + target under one host view.
Recorded as decision D7.

### Verified live (2026-09-13)
```
python -m runner.replay --scope security/dast/juice-shop/scope.json \
  --flow security/dast/juice-shop/flow.py --base-url http://juice:3000
# result: authenticated=true, whoami 200 (dast-poc@juice-sh.op), 56 requests, 0 blocked
```
ZAP's history confirmed: the `POST /rest/user/login` and **8 authenticated requests**
(`Authorization: Bearer`, incl. `/rest/user/whoami`, `/rest/basket/6`) — FR-S1 "an
authenticated request is visible in ZAP" met.

### Runtime dependency
`playwright` + a Chromium download (`playwright install chromium`) — see `requirements.txt`.
Imported lazily in `replay()` so the rest of the suite runs without a browser.

---

## 10. Component 4 — active-scan orchestration (`runner/scan.py`) — LIVE-VALIDATED

Python port of `runner/capture_zap_fixture.sh`: `accessUrl` → spider → bounded active-scan →
alerts export, using the stdlib (`urllib`) — no new deps. The DOM-XSS scanner (40026) is
disabled and scan/rule durations are capped, same as the capture script.

### Safety
`scan()` refuses out-of-scope targets **before touching ZAP**: the target host must be in the
scope allow-list, else `ScanScopeError` (NFR-2). This is the one pure branch and it's unit
tested (`tests/test_scan.py`) with an *exploding* ZAP URL, proving no traffic on refusal.

### Output
Emits raw ZAP alerts (`{"alerts": [...]}`) — the exact shape the normalizer already consumes,
so the live path is `scan.py → detections/normalizer.py` with no glue.

### Verified live (2026-09-13)
Ran replay (populate ZAP with authenticated traffic) → `runner/scan.py` (bounded active scan) →
`detections/normalizer.py`. Real result: **16,181 raw alerts → 16,181 detection records**,
1 High (SQL Injection, `/rest/products/search`). The streaming normalizer (D1) handled 16k
records with no memory issue — closing the **live scan → detection** path (no fixture).

### Known consideration
ZAP accumulates alerts across a session, so counts grow run-over-run (the 16k reflects the
whole session). Resolved in step 7 via a fresh ZAP session per run (`scan.new_session`).

---

## 11. Component 7 — end-to-end gate (`runner/main.py`) — the payoff

One command chains the whole loop and returns the Phase 1 gate as its exit code:

```
preflight (S3/NFR-2) → fresh ZAP session → replay auth via ZAP proxy (S1/R2) with the
scope guard live (S4/NFR-4) → bounded active scan (S1/S2) → normalize (N1)
```

### The gate (pure, unit-tested in `tests/test_main.py`)
`evaluate_gate(...)` returns `passed = authenticated AND scope_ok AND has_high_or_medium`.
Exit 0 only if the gate passes; non-zero on any abort (preflight/scope/scan) or a failed gate.

### Fresh session per run
`scan.new_session(zap_api)` starts a clean in-memory ZAP session first, so results are
**per-scan** — this run reported **1,345** detections vs the **16,181** accumulated before the
fix.

### Verified live (2026-09-13)
```
python -m runner.main --scope security/dast/juice-shop/scope.json \
  --flow security/dast/juice-shop/flow.py --base-url http://juice:3000 \
  --records-out records.json
# -> gate: {authenticated: true, scope_ok: true, has_high_or_medium: true,
#           detections: 1345, passed: true}  (exit 0)
```

### Run command (single documented entrypoint)
The above `python -m runner.main ...` is the "single documented command" (NFR-5); step 6
wraps it in a Containerfile so ZAP + Chromium + runner ship together.

---

## 12. Component 5 — evidence capture + redaction (`runner/evidence.py`) — FR-E1

Each run captures a **HAR** (`active-scan.har`) and a **screenshot** (`screenshot.png`) under
`security/dast/<app>/evidence/<scan_id>/` (gitignored). Playwright records the HAR via the
context's `record_har_path`; the screenshot is taken before the context closes.

### Redaction is mandatory (safety, not polish)
A raw HAR contains bearer tokens, cookies, and passwords. `redact_har` scrubs sensitive
headers (`Authorization`, `Cookie`, `Set-Cookie`, …), cookie values, and token/password/JWT
bodies **immediately after capture, before anything could publish it**. The pure redactor is
objectively tested (`tests/test_evidence.py`): the oracle re-scans the serialized HAR and
asserts **no secret survives** while non-sensitive fields are preserved.

### Referenced from results
Each detection record's `evidence_path` is set to `evidence/<scan_id>/active-scan.har`
(requirements §7.2 shape); the SARIF exporter turns that into a `result.attachments` entry
(FR-E1 "referenced from the SARIF results").

### Verified live (2026-09-13)
End-to-end run produced `active-scan.har` (3.1 MB) + `screenshot.png`; the HAR had **0 leaked
JWTs / no raw `Bearer` values / 130 `REDACTED` markers**, and records carried the evidence
path. Gate still passed.

### Publishing note
Local evidence is gitignored. Before publishing evidence externally (CI artifact / SARIF
link), it is already redacted at capture — but confirm the destination is access-controlled
(demo plan Phase 2). Durable/governed evidence hosting remains a documented gap.

---

## 13. Component 6 — packaging + version pins (NFR-5, NFR-1) — BUILT + VERIFIED

**Verified end-to-end.** The image builds (~2.6 GB) and `docker compose up …` ran the whole
stack: the runner authenticated, stayed in scope (0 blocked), scanned, normalized, and exited
**0 with the gate passed** (1351 detections); `./out/records.json` was produced. Runner
wall-clock ≈ **3m36s** — well under the 15-minute budget (FR-S5). Three packaging issues were
found and fixed (distroless healthcheck, Chromium root/sandbox, Playwright pin) — see
`testing_and_running_roadmap.md` §6 for the full report.

### Files
- `Containerfile` — runner image: base `mcr.microsoft.com/playwright/python:v1.62.0-jammy`
  (pins Playwright + Chromium), `pip install -r requirements.txt`, copies the code;
  entrypoint `python -m runner.main`.
- `compose.yaml` — three services on one network: `juice` (pinned by digest, healthchecked via
  node), `zap` (pinned by digest; `-silent` + `api.addrs` allow-list), `runner` (built here,
  `depends_on` juice healthy). Records land in `./out/records.json` (gitignored).
- `versions.lock` — the reproducibility pin (NFR-1): juice + zap **image digests**, ZAP
  2.17.0, Playwright 1.62.0, Chromium build 1234, Python 3.12.

### The single command (NFR-5)
```bash
docker compose up --build --abort-on-container-exit --exit-code-from runner
# builds the runner, starts juice + zap, runs the scan, and exits with the Phase 1 gate code
```

### Readiness
`runner/main.py` `wait_ready()` polls the ZAP API and the target before scanning, so container
start-ordering can't cause a flaky first run (returns immediately when already up locally).
Compose also gates the runner on `juice: service_healthy`.

### Why digests, not tags
`bkimminich/juice-shop:latest` and `zaproxy/zap-stable:latest` move over time; pinning by
`@sha256:...` makes a scan reproducible regardless of when it runs (NFR-1). Bump deliberately
via PR when upgrading, and re-verify the fingerprint worked examples if ZAP output shifts.

### Verified run
`docker compose up --build --abort-on-container-exit --exit-code-from runner` → runner exits 0
(gate passed), `out/records.json` written, ~3m36s. See `testing_and_running_roadmap.md`.

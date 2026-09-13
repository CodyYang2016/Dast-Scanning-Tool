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
| 1 | **Preflight safety gate** | `runner/preflight.py` | S3, NFR-2 | **pure — test-first** | ← building now |
| 2 | Hand-authored flow + auth replay | `security/dast/juice-shop/flow.py`, `runner/replay.py` | S1, R2 | live (spike) | todo |
| 3 | Request-boundary scope enforcement | `runner/scope_guard.py` | S4, NFR-4 | mostly pure — test-first | todo |
| 4 | Active-scan orchestration | `runner/scan.py` | S1, S2 | live; ports capture script | todo |
| 5 | Evidence capture | `runner/evidence.py` | E1 | live | todo |
| 6 | Packaging + version pins | `Containerfile`, lock file | NFR-5, NFR-1 | manual | todo |
| 7 | Wire the gate | `runner/main.py` | all | integration | todo |

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

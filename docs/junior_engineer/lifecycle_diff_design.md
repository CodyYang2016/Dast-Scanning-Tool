# Lifecycle Diff — Design & Frozen Criteria (FR-L1/L2)  — TEST-FIRST

**Workflow note:** this component is built **test-first**. This doc + `tests/test_lifecycle_diff.py`
are written and reviewed/frozen **before** `detections/lifecycle_diff.py` exists. The tests
therefore cannot conform to the implementation — the implementation must conform to them.
Until you approve, no `lifecycle_diff.py` is written (the test suite is intentionally "red").

---

## 1. Purpose

Track findings across scans (proof point #4). Given this scan's detections and the previous
scan's, label each **new / open / resolved**, and persist state so the *next* scan can diff
against this one.

- **FR-L1:** persist the scan's fingerprint set to a local state file, keyed by `app_id`.
- **FR-L2:** compare against the previous scan; label each detection.

## 2. Definitions (the ground truth the tests encode)

Identity is the **fingerprint** (from `contracts/README.md`). Comparing two scans is set
arithmetic on fingerprints:

| Label | Condition |
|-------|-----------|
| **new** | fingerprint in *current* scan, NOT in previous |
| **open** | fingerprint in *current* scan AND in previous (persists) |
| **resolved** | fingerprint in *previous* scan, NOT in current (it's gone → fixed) |

A resolved finding isn't in the current scan, so the diff must **emit** it from the previous
state (with its last-seen context), status `resolved`.

## 3. Frozen API (what the tests call — implementation must match)

```python
# detections/lifecycle_diff.py

def diff(current_records: Iterable[dict], previous_records: Iterable[dict]) -> list[dict]:
    """Return current records labeled new/open, followed by resolved records reconstructed
    from previous_records (fingerprints gone from current). Pure; no I/O."""

def save_state(state_path: str, app_id: str, records: Iterable[dict]) -> None:
    """Persist this scan's records (fingerprints included) under app_id, MERGING into any
    existing file so other apps' state is preserved (FR-L1)."""

def load_previous(state_path: str, app_id: str) -> list[dict]:
    """Return the previous scan's records for app_id, or [] if the file/app is absent."""
```

### Behavioural decisions (frozen)
- **Labeling** produces copies: `{**record, "status": "open"|"new"}`; the input records are
  not mutated.
- **Resolved entries** are `{**previous_record, "status": "resolved"}` — they keep the
  previous scan's context (title, endpoint, scan_id) so the report is meaningful.
- **Order** is deterministic: labeled current records in input order, then resolved records in
  previous order.
- **Membership is by fingerprint set** (duplicates in a scan are each labeled consistently).
- **Status enum** is exactly `open|new|resolved` (matches `detection.schema.json`).

### State file format (frozen)
```jsonc
{
  "<app_id>": { "scan_id": "<optional>", "records": [ <detection record>, ... ] }
}
```
Keyed by `app_id` (FR-L1); stores records so the fingerprint set is derivable AND resolved
context is available. `save_state` merges (never clobbers other apps).

## 4. Objective tests (frozen) — oracle = hand-built sets with known answers

Each case fixes the inputs and the expected labels **by hand**, so correctness is judged
against set theory / a known answer, not against the code.

**Pure `diff` logic**
- `test_first_scan_all_new` — previous empty → every current is `new`, no resolved.
- `test_unchanged_scan_all_open` — same fingerprints both scans → all `open`, none new/resolved.
- `test_fixed_finding_becomes_resolved` — B disappears → A `open`, B `resolved`, nothing `new`.
- `test_new_finding_labeled_new` — C appears → A `open`, C `new`.
- `test_all_fixed_all_resolved` — current empty → every previous is `resolved`.
- `test_resolved_carries_previous_context` — resolved entry keeps the previous title/endpoint/fp.
- `test_counts_conserved` — `len(diff) == len(current) + |prev_fps − current_fps|` (set math).
- `test_labels_are_valid_enum` — every status ∈ {open,new,resolved}.
- `test_partition_no_double_labeling` — no fingerprint is both `new` and `resolved`.
- `test_inputs_not_mutated` — the caller's record dicts are unchanged.

**State persistence (FR-L1)**
- `test_save_then_load_roundtrips_fingerprints` — saved then loaded → same fingerprint set.
- `test_state_is_keyed_by_app_id` — saving app B preserves app A's state (merge, no clobber).
- `test_load_missing_returns_empty` — no file / unknown app → `[]`.

**Two-scan integration (the FR-L2 demo, proof point #4)**
- `test_two_scans_fix_one` — save scan1; scan2 = scan1 minus fpX plus fpY; then
  `diff(scan2, load_previous(state, app))` → fpX `resolved`, fpY `new`, the rest `open`.

**Scalability (D1)**
- `test_diff_accepts_iterators` — `diff` works when both args are one-shot iterators.

Plus a **"does it bite?"** check after implementation: swap `new`/`resolved` logic and confirm
`test_fixed_finding_becomes_resolved` + `test_two_scans_fix_one` fail; then revert.

## 5. Verify (after implementation)
```bash
pytest tests/test_lifecycle_diff.py -q     # must go green only once implemented
pytest -q                                   # whole suite stays green
```

## 6. Out of scope
- Wiring into the runner / real two-scan run on Juice Shop (that's integration, later).
- Any change to the fingerprint formula (frozen).

## 7. R2 extension — coverage-aware `resolved` (added after freeze)

The frozen sections above stay valid; this extension only refines how a previous-only finding is
labeled. Decided in review as **R2** (see
`docs/junior_engineer/seeded_session_exploration_design.md`).

**Why.** `resolved` must mean *fixed*, not *we stopped looking*. A finding can vanish for two
different reasons: a real fix, or a coverage change (a re-authored flow dropped the route, or the
rule that found it was disabled). Only the first is a real `resolved`.

**Refinement.** A previous-only finding is now split by whether this scan actually exercised its
`(route × rule)` pair — `route = record.endpoint` (the fingerprint's `endpoint_pattern`),
`rule = record.rule_id` (the ZAP pluginId):

| Label | Condition |
|-------|-----------|
| **resolved** | fingerprint in previous only **and** its `(route × rule)` pair was exercised this scan |
| **not_scanned** | fingerprint in previous only **and** its `(route × rule)` pair was **not** exercised |

`not_scanned` is added to the status enum (`open|new|resolved|not_scanned`, matches
`detection.schema.json`). `new`/`open` are unchanged.

**API delta (backward compatible).**
```python
def diff(current, previous, covered=None) -> list[dict]: ...
#   covered=None  -> coverage-blind: every previous-only finding is `resolved` (legacy behavior,
#                    so all section-4 tests still hold verbatim)
#   covered={"routes": [...], "rules": [...]}  -> resolved iff route in routes AND rule in rules
#   covered=<iterable of (route, rule) pairs>  -> resolved iff the exact pair is present

def save_state(state_path, app_id, records, coverage=None) -> None: ...  # persists coverage too
def load_coverage(state_path, app_id): ...                               # or None if absent
```

**Coverage source (runner).** `runner/coverage.py::capture(zap_api, target)` returns
`{"routes": [...], "rules": [...]}`: ZAP's accessed URLs (`/JSON/core/view/urls`) canonicalized
with the same `endpoint_pattern()` as the fingerprint, crossed with the **enabled** active-scan
plugins (`/JSON/ascan/view/scanners`). `runner/main.py --coverage-out` writes it; pass it to the
diff via `lifecycle_diff --coverage`.

**Added tests** (`tests/test_lifecycle_diff.py`): resolved requires route+rule covered;
`not_scanned` when the route isn't covered; `not_scanned` when the rule was disabled (the issue-#7
shape); `covered=None` stays legacy-`resolved`; pair-set form; coverage persistence round-trip; and
a `not_scanned` record validates against `detection.schema.json`.

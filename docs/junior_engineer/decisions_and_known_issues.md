# Decisions & Known Issues

A running log of design decisions we've committed to and known limitations we've consciously
deferred. Each entry says what, why, status, and — for deferred items — the trigger that
should make us act.

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

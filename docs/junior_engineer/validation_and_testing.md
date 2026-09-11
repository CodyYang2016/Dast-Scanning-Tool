# Validation & Testing — Process, Catalogue, and Acceptance Criteria

This document is **two things at once**:
1. A **durable record of how and why we test** this project (Part 1 & 4) — the method, so
   the same discipline carries to every future component.
2. A **hands-on validation guide** (Part 2 & 3) — what to run and check to *assess* the work
   without having to trust it.

It currently covers the detection pipeline built so far: `detections/normalizer.py` (FR-N1)
and `detections/fingerprint.py` (FR-N2). SARIF export, lifecycle diff, and the runner get
their own criteria added here as they land (see the placeholders in Part 4).

---

## Part 1 — Testing philosophy (the process)

### The problem: conformance tests
A test written *after* the code, by looking at the code, tends to assert **"the function
returns what the function returns."** Example of a worthless test:

```python
assert fingerprint("40018", "/x", "q", "sqli") == fingerprint("40018", "/x", "q", "sqli")
```

That passes no matter how wrong `fingerprint` is. It conforms to the implementation instead
of checking it against reality. If the code has a bug, a conformance test happily locks the
bug in place.

### The fix: anchor every expectation to an INDEPENDENT oracle
An *objective* test compares the code's output to something computed **without** the code.
We use five independent oracles:

| # | Oracle | Why it's independent |
|---|--------|----------------------|
| 1 | **A different SHA implementation** (`shasum -a 256` via subprocess) | Not Python's `hashlib`. If our fingerprint matches an external tool hashing a by-hand preimage, both the field assembly *and* the digest are correct. |
| 2 | **Published external facts** (SQL Injection is CWE-89; ZAP "High" → "high") | Comes from the CWE catalog / ZAP docs, not our code. |
| 3 | **The raw ZAP fixture as ground truth** | We assert records are faithfully derived from the real `sample_zap_output.json` (count conserved, param preserved, query dropped). |
| 4 | **A third-party schema validator** (`jsonschema`) | An external library judges our output against `contracts/detection.schema.json`. Neither we nor our code is the judge. |
| 5 | **Sensitivity / negative checks** | Mutate one input; require the output to change. This catches the blind spot a conformance test structurally cannot see. |

### The decisive proof: the tests must *bite*
Passing tests are necessary but not sufficient — a test that can't fail is worthless. So we
verify the suite catches a real bug. We temporarily removed `payload_family` from the
fingerprint's preimage and re-ran:

```
FAILED test_fingerprint_matches_external_shasum          (oracle 1 caught it)
FAILED test_contract_worked_examples_are_self_consistent (contract anchor caught it)
FAILED test_each_field_changes_the_fingerprint           (oracle 5 caught it)
3 failed, 10 passed
```

Then restored the line → 13 passed. **If you ever doubt the suite, redo this** (see Part 3,
check A6). A suite that never fails is proving nothing.

---

## Part 2 — Test catalogue (`tests/test_acceptance.py`)

Every test, what it proves, and which oracle makes it objective.

| Test | What it proves | Oracle |
|------|----------------|--------|
| `test_fingerprint_matches_external_shasum` | Our fingerprint == an external SHA of a by-hand preimage | 1 |
| `test_contract_worked_examples_are_self_consistent` | README's two published digests are correct AND our code reproduces them | 1 + contract |
| `test_each_field_changes_the_fingerprint` | All four inputs actually participate (no field silently ignored) | 5 |
| `test_field_order_matters` | Fields are positionally bound (swapping values changes the digest) | 5 |
| `test_record_count_conserved` | One record per raw alert — no silent drops/dupes | 3 |
| `test_sqli_is_cwe_89` | SQL Injection maps to CWE-89 | 2 |
| `test_severity_mapping_matches_zap_risk` | Every record's severity = documented mapping of its raw ZAP risk | 2 + 3 |
| `test_endpoint_is_path_only` | Endpoint is a bare path (no query, scheme, or host) | 3 |
| `test_parameter_preserved_or_nulled` | Non-empty ZAP param preserved; empty → null | 3 |
| `test_every_fingerprint_is_64_lowercase_hex` | Fingerprint format matches the contract regex | 3 |
| `test_all_records_validate_against_schema` | Every record passes the JSON Schema (third-party validator) | 4 |
| `test_normalization_is_deterministic` | Same input → identical output | invariant |
| `test_endpoint_pattern_is_idempotent` | Re-patterning a pattern doesn't change it | invariant |

> Note: `tests/test_fingerprint.py` and `tests/test_normalizer.py` also exist. They are finer-
> grained and useful, but more implementation-adjacent; `test_acceptance.py` is the objective
> layer you rely on to *assess* the work.

---

## Part 3 — Acceptance criteria checklist

Work top to bottom. Each row is a concrete goal, how to check it, and what "pass" means.

### Automated (run: `pytest -q` from the repo root)

| # | Goal | Check | Pass condition |
|---|------|-------|----------------|
| A1 | Fingerprint is a correct SHA-256 of the right fields | `test_fingerprint_matches_external_shasum` | green |
| A2 | The contract's worked examples are real, not invented | `test_contract_worked_examples_are_self_consistent` | green |
| A3 | Every fingerprint field matters | `test_each_field_changes_the_fingerprint`, `test_field_order_matters` | green |
| A4 | ZAP → record mapping is faithful | the five `test_*` in catalogue group C | green |
| A5 | Output obeys the contract | `test_all_records_validate_against_schema` | green |
| A6 | **The suite actually bites** | See "decisive proof" (Part 1); redo the break/restore | 3 tests fail when broken, all pass when restored |

### Manual (build understanding — do these by hand)

- **M1 — trace one finding by eye.** Open `contracts/sample_zap_output.json`, find the alert
  with `"pluginId": "40018"`. Read its `url`, `param`, `cweid`, `risk`. Then run:
  ```bash
  python -m detections.normalizer contracts/sample_zap_output.json --app-id juice-shop
  ```
  Find the matching record. Confirm: `url` → `endpoint` (path only, `?q=...` gone), `param`
  "q" preserved, `cweid` "89" → `CWE-89`, `risk` "High" → `severity` "high". *You now know
  exactly what the normalizer does.*

- **M2 — hash a fingerprint by hand.** Run:
  ```bash
  printf '%s' '40018|/rest/products/search|q|sqli' | shasum -a 256
  ```
  Confirm the digest equals the `fingerprint` on the SQLi record from M1 **and** the digest
  in `contracts/README.md`. *You now know a fingerprint is just a SHA-256 of four fields
  joined by pipes.*

- **M3 — see sensitivity for yourself.** Change one character:
  ```bash
  printf '%s' '40018|/rest/products/search|x|sqli' | shasum -a 256
  ```
  It's a completely different digest. *This is why an unchanged app must produce byte-identical
  inputs — otherwise the lifecycle diff would call an unchanged finding "resolved."*

- **M4 — run the suite.** `pytest -q` → read the one-line summary (expect `29 passed`).

---

## Part 4 — How to extend (the recipe for the next component)

When you build the next module, write its acceptance tests the same way — **find an
independent oracle before you write the assertion.** A quick guide per upcoming component:

- **SARIF exporter (FR-X1):** oracle = the **official SARIF 2.1.0 JSON Schema** (third-party
  validator, like oracle 4) + a sensitivity check that our fingerprint survives into
  `partialFingerprints`. Don't assert "the SARIF looks like our SARIF"; assert it validates
  against the published schema and that severity maps to the documented SARIF `level`.
- **Lifecycle diff (FR-L2):** oracle = **hand-constructed fingerprint sets** with a known
  answer. Feed set A (scan 1) and set B (scan 2) where you *decided in advance* which are new/
  open/resolved; assert the diff reproduces your answer. Include the key negative case: a
  fixed finding must flip to `resolved`, an unchanged one must stay `open`.
- **Scan runner (FR-S3/S4, the safety guardrail):** oracle = **behaviour, not return values**.
  Assert it *refuses to run* on `environment_class: prod` (exit non-zero) and *blocks* an
  injected out-of-allow-list host (appears in the log). This is the single most important
  guardrail (NFR-2) — test it adversarially.

General rule: for every new claim, ask "what would prove this *without* running my code?"
If the only proof is running your code, it's a conformance test — find a real oracle.

---

## Running everything

```bash
python3.12 -m venv .venv && source .venv/bin/activate   # or reuse an existing venv
pip install -r requirements-dev.txt
pytest -q                    # whole suite
pytest tests/test_acceptance.py -v   # just the objective layer, named
```

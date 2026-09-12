# SARIF Exporter — Design Breakdown (FR-X1)

Read this while it's being built. It explains *what* SARIF is, *what document we emit*, the
*exact field mapping*, *why each choice*, and *how we prove it's correct* (objective tests).

---

## 1. Purpose

Turn our normalized detection records (from `detections/normalizer.py`) into a **valid SARIF
2.1.0 document** that GitHub's Security tab natively ingests (FR-X1), carrying our stable
fingerprint so GitHub can track a finding across scans (sets up FR-X2 upload and FR-L2
lifecycle). We do **not** re-derive findings here — this is a pure format translation:
detection records in → one SARIF log out.

## 2. What SARIF is (30-second version)

SARIF (Static Analysis Results Interchange Format) is a **standard JSON shape for security/
analysis results**. GitHub reads it and renders each *result* as an alert in the Security tab.
The parts we care about:

- a **log** has `runs`; we emit exactly one run.
- a **run** has a **tool.driver** (who found this) and a list of **results** (the findings).
- a **driver** has **rules** (metadata about each rule that can fire).
- a **result** points at a `ruleId`, has a `level`, a `message`, `locations`, and
  `partialFingerprints` (stable identity for tracking across runs).

## 3. Input / output

- **Input:** an iterable of detection records (contracts/detection.schema.json shape).
  Streamed in, per the D1 convention (see decisions_and_known_issues.md).
- **Output:** one SARIF 2.1.0 JSON document (`{"version":"2.1.0","$schema":...,"runs":[...]}`).

> Scalability note: SARIF is one document, so this is a D1 "genuinely needs the aggregate"
> stage — like the lifecycle diff. We consume the input in a **single pass**, holding only the
> results + a small rules index, then serialize. GitHub's upload needs the whole file anyway.

## 4. The document we emit (concrete shape)

```jsonc
{
  "version": "2.1.0",
  "$schema": "https://.../sarif-schema-2.1.0.json",
  "runs": [{
    "tool": { "driver": {
      "name": "OWASP ZAP (ssd-dast-poc)",
      "informationUri": "https://www.zaproxy.org/",
      "version": "2.17.0",
      "rules": [{
        "id": "40018",
        "name": "SQLInjection",
        "shortDescription": { "text": "SQL Injection" },
        "properties": {
          "tags": ["security", "external/cwe/cwe-89"],
          "security-severity": "8.0"      // drives GitHub's severity bucket
        }
      }]
    }},
    "results": [{
      "ruleId": "40018",
      "ruleIndex": 0,                       // index into driver.rules
      "level": "error",                     // from severity (table below)
      "message": { "text": "SQL Injection" },
      "locations": [{
        "physicalLocation": { "artifactLocation": { "uri": "/rest/products/search" } }
      }],
      "partialFingerprints": { "dastFingerprint/v1": "ece130…" },
      "properties": { "severity": "high", "parameter": "q", "cwe_id": "CWE-89",
                      "scan_id": "20260909T170000Z" }
    }]
  }]
}
```

## 5. Field mapping (detection record → SARIF)

| Detection field | SARIF location | Notes |
|-----------------|----------------|-------|
| `rule_id` | `result.ruleId` + `driver.rules[].id` | ZAP pluginId as string |
| `title` | `rule.shortDescription.text` + `result.message.text` | human name |
| `severity` | `result.level` + `rule.properties.security-severity` | two mappings, below |
| `cwe_id` | `rule.properties.tags` → `external/cwe/cwe-89` | drives GitHub CWE tagging |
| `endpoint` | `result.locations[].physicalLocation.artifactLocation.uri` | our path pattern |
| `fingerprint` | `result.partialFingerprints["dastFingerprint/v1"]` | stable cross-scan identity |
| `parameter`, `scan_id`, `severity` | `result.properties.*` | preserved context |

### 5a. severity → `result.level` (SARIF enum: error/warning/note/none)

| severity | level |
|----------|-------|
| critical | error |
| high | error |
| medium | warning |
| low | note |
| info | note |

### 5b. severity → `security-severity` (GitHub's numeric band → Security-tab severity)

GitHub buckets by number: ≥9.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low.

| severity | security-severity |
|----------|-------------------|
| critical | "9.5" |
| high | "8.0" |
| medium | "5.0" |
| low | "3.0" |
| info | "0.0" |

## 6. Why these choices

- **`partialFingerprints`, not `fingerprints`.** GitHub uses partialFingerprints to correlate
  the "same" alert across runs. Feeding *our* fingerprint means GitHub's dedup agrees with our
  lifecycle diff — one source of identity truth. Key name is versioned (`/v1`) so we can
  evolve it (ties to the fingerprint change policy in contracts/README.md).
- **`security-severity` property.** Without it GitHub shows every alert as "warning". This is
  the documented lever to make the Security tab reflect real severity.
- **CWE via `tags`.** `external/cwe/cwe-89` is the convention GitHub reads to attach a CWE.
- **`ruleIndex` + a deduped `rules` array.** Referential integrity: every result's ruleId
  resolves to a rule with metadata. One rule entry per distinct `rule_id`.

## 7. Files

- `detections/sarif_export.py` — `to_sarif(records) -> dict`, `write_sarif(records, fh)`, CLI.
- `contracts/sarif-2.1.0.schema.json` — **vendored official schema**, the test oracle.
- `tests/test_sarif_export.py` — objective suite (below).

## 8. How we prove it's correct (objective tests — the independent oracles)

Following `validation_and_testing.md` Part 4 — find an oracle independent of our code:

| Test | What it proves | Oracle |
|------|----------------|--------|
| `test_sarif_validates_against_official_schema` | Output is real SARIF 2.1.0 | **Vendored official OASIS schema** via `jsonschema` (third party) |
| `test_result_count_conserved` | One result per detection, no drops | raw record count |
| `test_every_fingerprint_carried` | Our fingerprint survives into `partialFingerprints` | the input records |
| `test_sqli_level_is_error_and_high_band` | high→`error` + security-severity in 7.0–8.9 | documented mapping (recomputed in-test) + GitHub's published bands |
| `test_cwe_tag_present_for_sqli` | SQLi rule tagged `external/cwe/cwe-89` | CWE catalog fact |
| `test_referential_integrity` | every `result.ruleId` exists in `driver.rules` | SARIF structural rule |
| `test_level_mapping_matches_table` | each result.level = documented map of its severity | independent table in test |
| `test_export_is_single_pass_iterable` | accepts a one-shot iterator (D1) | behavioural |

Plus the **"does it bite?"** check: temporarily emit a wrong `level` (e.g. always "note") and
confirm `test_level_mapping_matches_table` / `test_sqli_level_is_error_and_high_band` fail;
then revert.

## 9. Verify end-to-end

```bash
pytest -q                                   # whole suite incl. SARIF
python -m detections.normalizer contracts/sample_zap_output.json --app-id juice-shop \
  | python -m detections.sarif_export --app-id juice-shop -o out.sarif   # records -> SARIF
```
Then (FR-X2, next step) upload `out.sarif` to the GitHub Security tab via the code-scanning API.

## 10. Out of scope here
- Uploading to GitHub (FR-X2) — separate step.
- Evidence file references (FR-E1) — the runner captures HAR/screenshots; we leave
  `result.properties` room to add an evidence path later.

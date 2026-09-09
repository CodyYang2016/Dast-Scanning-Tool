# Detection Contracts

This directory holds the **frozen contracts** for the DAST pipeline. They change **only by pull request** with review from both engineers. Code (normalizer, exporter, lifecycle diff) is written *to* these files — never the other way around.

| File | What it is |
|------|------------|
| `scope.json` | Per-app scan boundary instance (hand-authored on Day 1; `generate` CLI emits it later). |
| `scope.schema.json` | JSON Schema validating `scope.json`. |
| `detection.schema.json` | JSON Schema for the normalized detection record the normalizer emits. |
| `sample_zap_output.json` | Real captured ZAP alerts, the fixture the normalizer is built against. |
| `README.md` (this file) | The **fingerprint formula** — frozen here, not in code. |

## Fingerprint formula (FROZEN)

The fingerprint is the stable identity of a finding across scans. It is the backbone of the lifecycle diff (FR-L2): the diff decides `new` / `open` / `resolved` purely by comparing fingerprints between two scans. **If the formula drifts, every "resolved" label is wrong** — an unchanged finding gets a new fingerprint, looks "resolved," and a brand-new one appears. That is why it lives in a versioned contract with worked examples, and why NFR-2/FR-N2 require identical fingerprints for an unchanged app.

```
fingerprint = sha256( rule_id + "|" + endpoint_pattern + "|" + parameter + "|" + payload_family )
```

* Encoding: UTF-8. Output: lowercase hex, 64 chars (matches `^[a-f0-9]{64}$` in `detection.schema.json`).
* Separator: a single literal pipe `|`. Inputs must never contain a raw `|`; if one ever could, it is stripped during derivation (below).
* Order is fixed: `rule_id`, `endpoint_pattern`, `parameter`, `payload_family`. Never reorder.

### The four inputs — derivation rule and empty-case

Each input has a deterministic derivation and a **fixed sentinel for the empty case**. The sentinels are part of the contract: they are what guarantee two scans of an unchanged app produce byte-identical fingerprints.

| Input | Derived from | Normalization rule | Empty-case sentinel |
|-------|--------------|--------------------|---------------------|
| `rule_id` | ZAP `pluginId` | Use the numeric plugin ID as a string, verbatim. Always present. | n/a (never empty) |
| `endpoint_pattern` | ZAP alert `url` (path only) | Lowercase host-less path; collapse variable path segments to named placeholders so IDs don't churn the fingerprint. Drop the query string. | `/` if path is empty |
| `parameter` | ZAP alert `param` | Use verbatim. This is the injected/affected parameter name. | empty string `""` |
| `payload_family` | ZAP `alert` name / plugin category (NOT a native field) | Map the ZAP rule to a coarse family bucket (see below). This is the one derived, ambiguous input. | `"none"` |

### `endpoint_pattern` — the ID-collapsing rule

Collapse anything that varies per-request so the fingerprint tracks the *endpoint*, not the specific object:

* Numeric segments -> `{id}`  (`/rest/user/42` -> `/rest/user/{id}`)
* UUIDs / hashes -> `{id}`  (`/api/order/9f2c...` -> `/api/order/{id}`)
* Drop the query string entirely (`/search?q=x` -> `/search`)
* Lowercase; strip trailing slash except root.

### `payload_family` — the derived bucket (pin this against the fixture)

`payload_family` is **not** something ZAP emits. Derive it by mapping the alert's rule/category into a small, fixed vocabulary so related payloads share one identity. Frozen vocabulary:

* `sqli` — SQL injection family
* `xss` — reflected/stored/DOM XSS
* `headers` — security-header / info-leak passive alerts
* `auth` — authentication / session issues
* `crypto` — transport/cert findings (reserved for the future sslyze/testssl.sh source; ZAP will not emit these)
* `misc` — anything unmapped
* `none` — empty-case sentinel (no meaningful family)

The exact ZAP-rule -> family mapping table MUST be pinned from the real fixture once `capture_zap_fixture.sh` runs. Do not guess it from memory.

### Worked examples

> PLACEHOLDER VALUES — replace each row with real values pulled from `sample_zap_output.json` after the capture script runs. Recompute the hash from the actual inputs; do not hand-copy these digests.

**Example 1 — SQL injection on login**

```
rule_id          = "40018"
endpoint_pattern = "/rest/user/login"
parameter        = "email"
payload_family   = "sqli"
preimage         = "40018|/rest/user/login|email|sqli"
fingerprint      = sha256(preimage)   # -> <64-hex, fill from real fixture>
```

**Example 2 — passive header alert, no parameter**

```
rule_id          = "10038"
endpoint_pattern = "/"
parameter        = ""            # empty-case sentinel
payload_family   = "headers"
preimage         = "10038|/|(empty)|headers"   # note: the empty string is literal, shown as (empty) for readability only
fingerprint      = sha256("10038|/||headers")  # actual preimage has two adjacent pipes
```

The Example 2 detail — an empty `parameter` produces two adjacent pipes (`||`) in the preimage — is the kind of thing that MUST be identical in the code and here, or fingerprints won't match across runs.

### Reference implementation (informative, not authoritative)

The formula above is the contract; this snippet only illustrates it.

```python
import hashlib

def fingerprint(rule_id: str, endpoint_pattern: str, parameter: str, payload_family: str) -> str:
    parts = [
        rule_id,
        endpoint_pattern or "/",
        parameter or "",
        payload_family or "none",
    ]
    preimage = "|".join(p.replace("|", "") for p in parts)
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()
```

### Change policy

* This formula is **frozen**. Any change is a breaking change to the lifecycle diff and MUST be a reviewed PR.
* On any change, bump a `fingerprint_version` recorded alongside scans, because fingerprints computed under different versions are not comparable and prior "resolved" history is invalidated.
* Re-pin the worked examples from a fresh fixture in the same PR.

# Junior Engineer (Engineer 1) — Setup + Working Plan

A focused guide distilled from `dast_poc_requirements.md`, `dast_poc_3week_plan.md`,
and `dast_poc_day1_runbook.md`. Read those for full detail; this is your on-ramp.

## Your role in one line

You own the **contract-bounded, fixture-testable modules**: "JSON in → JSON out."
None of your work needs the live scanner. You build against a saved
`contracts/sample_zap_output.json`, so you are **never blocked** waiting on the
senior's ZAP/Playwright integration.

## What you own

| Component | FRs | What it is |
|---|---|---|
| **Normalizer + fingerprint** | FR-N1, FR-N2 | Pure function: raw ZAP JSON → normalized detection records + a stable `sha256` hash |
| **SARIF exporter** | FR-X1 | Map normalized records → valid SARIF 2.1.0 (use a helper lib) |
| **Lifecycle diff** | FR-L1, FR-L2 | Set comparison of two fingerprint sets → label `open` / `new` / `resolved` |
| **`record` CLI (thin)** | FR-R1, FR-R3 | Drives Playwright crawl → `trace.json` / `index.json` (good ramp-up) |
| **`validate` CLI (thin)** | FR-V2, FR-V3 | Replay flow + allow-list check + validation report with non-zero exit |
| **Deterministic `generate` pieces** | FR-G2, FR-G3, FR-G4 | Emit `scope.json`, `zap-policy`, `manifest`, `lock`; idempotency |
| **`generate` LLM part** | FR-G1 | *Pair with senior* — high teaching value |

## Prerequisites (you genuinely have enough if…)

- Solid **Python** (subprocess, JSON, small testable pure functions) and **JSON/schema** thinking
- HTTP basics, Git/PR workflow, command line
- Willingness to **learn SARIF** (just a JSON format — read the spec, map fields) and the
  **fingerprint** concept (a hash of 4 fields)
- Basic **set operations** for the diff
- **Not required:** ZAP internals, proxies, pentesting skills, security certs. That grows
  through the Week 2 pairing sessions.

## Setup (do the day before Day 1, ~30 min)

1. Container runtime (**Podman** = Nationwide default; Docker only where licensed),
   **Python 3.11+**, access to the enterprise GitHub org.
2. Authenticate to the Nationwide Trusted Registry and pre-pull images — *do this cold the
   day before; the WSL proxy fix (Appendix A2 of the Day 1 runbook) can eat hours.*
3. Run the pilot app locally: OWASP Juice Shop on `http://localhost:3000`.
4. Read Sections 6, 7, and 13 of the requirements doc plus the Day 1 runbook.

## Day 1 (you're heavily involved)

- **You drive** the repo scaffold & push (Block 2) — senior pairs.
- **Both** freeze the three contracts (Block 3): `scope.json` + `scope.schema.json`, the
  normalized detection record + `detection.schema.json`, and the **exact fingerprint
  formula** with worked examples.
- **You pair** while the senior captures the real `sample_zap_output.json` (Block 4) —
  confirm every field maps to the frozen record.
- **You author** the Speckit constitution (Block 5): NFR-2 safety, NFR-3 secrets, NFR-4 logging.

## Week-by-week

### Week 1 — build in isolation against the fixture
Normalizer → fingerprint → SARIF exporter → lifecycle diff, all unit-tested against
`sample_zap_output.json`. Upload a **hand-made SARIF** to the GitHub Security tab to prove
that path independently.

*Checkpoint (end of Week 1):* wire the real runner output into your normalizer — assembly,
not a rewrite, because you both coded to the same contract.

### Week 2 — finish thin CLIs + harden
Complete `record` and `validate`; add tests; **pair with the senior on `generate`** (LLM
call + brittle output parsing).

*Checkpoint (end of Week 2):* first full-chain run
`record → generate → validate → runner → normalizer → SARIF → GitHub`.

### Week 3 — integrate continuously (mostly together)
Run two consecutive scans to exercise the lifecycle diff (fix one bug in Juice Shop → that
detection flips to `resolved`), fix seams, build the demo.

## The two rules that keep you unblocked

1. **Contracts before code** — every interface is a written schema + a sample file.
2. **Mock the neighbor, never wait** — you always build against the checked-in
   `sample_zap_output.json`; the senior builds against a hand-written `scope.json`. You only
   sync at the three scheduled handshakes (end of Day 1, Week 1, Week 2), plus continuous
   integration in Week 3.

## ⚠️ Open gap to confirm

`contracts/sample_zap_output.json` is currently just `{}` (empty). Your **entire Week 1
depends on this fixture being real** — it must be a genuine ZAP export with at least one
high/critical finding and two distinct rule types (per Day 1 Block 4 and the exit
checklist). Until the senior captures it on Day 1, you are blocked on the very thing Day 1
exists to unblock. Confirm this lands first.

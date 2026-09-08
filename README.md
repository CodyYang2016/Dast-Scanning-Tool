# ssd-dast-poc

Proof-of-concept for the Agentic DAST platform (Step 1: authenticated non-prod loop).

## Layout
- `authoring/`   record -> generate -> validate CLIs
- `runner/`      scan orchestration: ZAP + Playwright + scope enforcement
- `detections/`  normalizer, fingerprint, SARIF exporter, lifecycle diff
- `contracts/`   shared schemas (scope.json, detection record) + sample fixtures
- `security/dast/<app>/`  generated scan artifacts for the pilot app
- `tests/`       unit + integration tests

## Prerequisites
Python 3.11+, OWASP ZAP, Playwright (+ Chromium). See requirements doc for details.

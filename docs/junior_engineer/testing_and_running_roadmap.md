# Testing & Running Roadmap

How to test and run the whole DAST POC, what "working" looks like, and the issues found while
containerizing it (with fixes). All of this is **verified** — the containerized single command
ran end-to-end and the gate passed.

---

## 0. What "working" means (the acceptance surface)

| Layer | How it's verified | Status |
|-------|-------------------|--------|
| Unit / contract logic | `pytest` — 107 objective tests | ✅ green |
| Results pipeline on real data | fixture → normalize → SARIF → GitHub Security tab | ✅ verified (38 alerts) |
| Runner end-to-end (local) | `python -m runner.main …` → gate | ✅ gate passed |
| Runner end-to-end (container, one command) | `docker compose up …` → gate | ✅ gate passed (1351 detections, exit 0) |
| Reproducibility (NFR-1) | images pinned by digest in `versions.lock` | ✅ |
| Time budget (FR-S5, <15 min) | measured runner wall-clock | ✅ ~3m36s |

You do **not** need the container build to prove the application works — the same code is
validated locally and by the test suite. The container proves the *packaging/orchestration*.

---

## 1. Prerequisites

- Docker (or Podman). Docker 29.x used.
- Python 3.11+ for the local loop / tests (`brew install python@3.12`; macOS ships 3.9).
- `pip install -r requirements-dev.txt` then `python -m playwright install chromium` (local only).

---

## 2. Run path A — one command (containerized) ✅ verified

```bash
docker compose up --build --abort-on-container-exit --exit-code-from runner
```

- Builds the runner image (base `mcr.microsoft.com/playwright/python:v1.62.0-jammy`, ~2.6 GB),
  starts Juice Shop + ZAP + runner on one network, runs a safe authenticated scan, and **exits
  with the Phase 1 gate as its code** (0 = pass).
- Output: `./out/records.json` (detection records; gitignored).
- Expected tail:
  ```
  runner-1 | "gate": { "authenticated": true, "scope_ok": true,
  runner-1 |            "has_high_or_medium": true, "detections": <n>, "passed": true }
  runner-1 exited with code 0
  ```
- Measure the budget: `time docker compose up --abort-on-container-exit --exit-code-from runner`
  (observed runner wall-clock ≈ 3m36s; well under the 15-minute FR-S5 target).
- Tear down: `docker compose down -v`.

> Evidence note: in compose the HAR + screenshot are written **inside** the runner container
> (gitignored path) and are discarded on teardown; only `./out/records.json` is mounted out.
> To keep evidence, add a volume for `security/dast/juice-shop/evidence`.

## 3. Run path B — local dev loop

```bash
docker network create dast
docker run -d --name juice --network dast -p 3000:3000 bkimminich/juice-shop
docker run -d --name zap  --network dast -p 8080:8080 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true

python -m runner.main --scope security/dast/juice-shop/scope.json \
  --flow security/dast/juice-shop/flow.py --base-url http://juice:3000 \
  --records-out out/records.json
```

Then publish + lifecycle (see the top-level `README.md`). The results pipeline also runs
standalone against `contracts/sample_zap_output.json` with no scanner.

## 4. Tests

```bash
pip install -r requirements-dev.txt
pytest -q          # 107 tests
```

Objective / test-first philosophy and the "does it bite?" checks: see
`validation_and_testing.md`. Safety-critical modules (preflight, scope guard, lifecycle diff)
were committed **red** first, then implemented to green.

## 5. Verification checklist — the four proof points

1. **Authenticated scan** — gate `authenticated: true`; ZAP recorded `Authorization: Bearer`
   requests (`.../search/view/messagesByRequestRegex/?regex=Authorization:%20Bearer`).
2. **Scope enforcement** — gate `scope_ok: true`, `blocked: 0` on the pilot; pointing
   `--base-url` at a non-allow-listed host is blocked and fails (try `http://localhost:3000`).
3. **GitHub Security tab** — `sarif_export` + `github_upload`; alerts render with severity/CWE.
4. **Lifecycle** — two scans across a fix → the fixed finding flips to `resolved`.

---

## 6. Issues found while containerizing (report) — all fixed

| # | Symptom | Root cause | Fix |
|---|---------|-----------|-----|
| 1 | `juice` container **unhealthy**, runner never starts (`dependency failed to start`) | The `bkimminich/juice-shop` image is **distroless** — no `/bin/sh`, so a `CMD-SHELL` healthcheck can't execute (`exec: "/bin/sh": no such file or directory`) | Removed the compose healthcheck; readiness handled by the runner's `wait_ready()` (polls `juice:3000` + the ZAP API). `depends_on: [juice, zap]` (service_started). |
| 2 | Chromium would fail as **root** in-container (`Running as root without --no-sandbox…`) + crash on small `/dev/shm` | Container runs as root with a tiny shared-memory mount | `replay.py` adds `--no-sandbox --disable-dev-shm-usage` when `RUNNER_CHROMIUM_NO_SANDBOX=1` (set by compose); local non-root runs unaffected |
| 3 | Risk of Chromium/Playwright **version mismatch** in the image | `requirements.txt` had `playwright>=1.40`; the base image bundles a specific Chromium for 1.62.0 | Pinned `playwright==1.62.0` (matches base image + `versions.lock`); dropped the redundant `playwright install chromium` build step |

Issues 2 and 3 were fixed **preemptively** (predicted before the first build); issue 1 was
found by the first `docker compose up` and fixed on the second — which passed.

## 7. Known gaps (out of POC scope — see `decisions_and_known_issues.md`)
- `endpoint_pattern` id-collapsing heuristic (KI1); scope-matching edge cases (KI2);
  Juice Shop container exit-133 flakiness between sessions (KI3).
- Evidence persistence in compose (add a volume) and durable/governed evidence hosting.

## 8. Troubleshooting quick table
| Symptom | Fix |
|---------|-----|
| `dependency juice failed to start … unhealthy` | You re-added a shell healthcheck; juice is distroless — remove it (issue 1) |
| `Running as root without --no-sandbox` | Ensure `RUNNER_CHROMIUM_NO_SANDBOX=1` is set for the runner (compose sets it) |
| `curl: (52) Empty reply` from ZAP | ZAP needs `-config 'api.addrs.addr.name=.*'` (quote it in a shell) |
| Local `localhost:3000` blocked by the guard | Use `--base-url http://juice:3000` — ZAP resolves it (D7) |
| `juice` gone between sessions (exit 133) | Recreate it (KI3) |

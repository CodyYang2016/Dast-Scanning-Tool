# Phase 1 Live Demo Script — Minimum Viable Scanner Gate

Follow top to bottom. Each step has: the command, what to say while it runs, and what
"success" looks like on screen. Total run time budget: ~10 minutes (scan itself ~4 min).
See `dast_poc_demo_plan.md` (Phase 1) for the underlying gate definition and
`docs/junior_engineer/testing_and_running_roadmap.md` for troubleshooting detail.

---

## 0. Pre-demo setup (do this 10-15 min BEFORE the audience arrives)

- [ ] Confirm Docker/Podman daemon is running (`docker version` or `podman machine list`).
- [ ] **If on a corporate network with a proxy**, confirm image registries are reachable
      (`docker pull mcr.microsoft.com/playwright/python:v1.62.0-jammy` once, ahead of time,
      so the demo doesn't stall on a cold pull). This is the #1 live-demo risk.
- [ ] `cd` to the repo root; `git pull` to make sure you're on the latest `main`.
- [ ] Free ports 3000/8080 (`docker ps` — stop any stray `juice`/`zap` containers from a
      previous session).
- [ ] Run `pytest -q` once and confirm **107 passed** — this is your fallback evidence if
      live infra hiccups (see §6).
- [ ] Have a second terminal tab ready for the "break it on purpose" steps (§3, §4).

---

## 1. Talking point — what this demo proves (30 sec, no commands)

> "This is the Phase 1 gate: prove we can safely scan a live app end-to-end before we ever
> let an LLM generate anything. Four things have to be true: it authenticates through the
> proxy, it never leaves scope, it produces a real detection, and unsafe configuration is
> refused before a single packet goes out."

---

## 2. Show the safety gate fails CLOSED (no network, instant, do this first)

Prove the guardrail works in isolation before anything else runs.

```bash
python -m runner.preflight --scope security/dast/juice-shop/scope.json
```
**Say:** "This is the real scope file — dev, allow-list of one host." **Expect:**
```
preflight OK: app_id=juice-shop environment_class=dev allow_list=['localhost']
```

Now break it on purpose — a prod scope must never scan:

```bash
python -c "import json; s=json.load(open('security/dast/juice-shop/scope.json')); s['environment_class']='prod'; json.dump(s, open('/tmp/prod_scope.json','w'))"
python -m runner.preflight --scope /tmp/prod_scope.json
```
**Say:** "Same file, environment flipped to prod. Zero traffic is sent — it aborts before
touching the network." **Expect:** exit code 2 and
```
PREFLIGHT ABORT: environment_class='prod' is production — refusing to scan (NFR-2).
```

---

## 3. Run the full containerized scan — the main event

```bash
docker compose up --build --abort-on-container-exit --exit-code-from runner
```
*(swap `docker` for `podman` if that's your engine)*

**While it builds/starts (~30-60s), say:**
> "One command, one network — Juice Shop, ZAP, and the runner. No manual proxy setup, no
> separate terminal juggling."

**While it runs (~3-4 min), narrate the phases as they scroll:**
1. Runner waits for Juice Shop + ZAP to come up (`wait_ready`).
2. Playwright registers a test user and logs in **through the ZAP proxy** — call out the
   authenticated request lines if visible.
3. Scope guard is live during replay — every request is checked against the allow-list.
4. Bounded active scan runs against the allow-listed host only.
5. Raw ZAP alerts are normalized into detection records.

**Expected tail (success):**
```
runner-1 | {
runner-1 |   "scan_id": "...",
runner-1 |   "app_id": "juice-shop",
runner-1 |   "requests_seen": <n>,
runner-1 |   "blocked": 0,
runner-1 |   "gate": {
runner-1 |     "authenticated": true,
runner-1 |     "scope_ok": true,
runner-1 |     "has_high_or_medium": true,
runner-1 |     "detections": <n>,
runner-1 |     "passed": true
runner-1 |   }
runner-1 | }
runner-1 exited with code 0
```
**Say:** "`passed: true`, exit code 0 — that's all four Phase 1 gate conditions in one shot."

---

## 4. Show scope enforcement blocking (the guardrail, live)

In the second terminal tab, point the runner at a host that is NOT in the allow-list:

```bash
docker compose run --rm runner --scope security/dast/juice-shop/scope.json \
  --flow security/dast/juice-shop/flow.py --base-url http://localhost:3000 \
  --zap-api http://zap:8080 --zap-proxy http://zap:8080
```
**Say:** "Same command, but the target host isn't on the allow-list — `localhost` instead of
`juice`. Watch it get blocked, logged, and the scan fails — not silently ignored."
**Expect:** non-zero exit, `"blocked": >0` or a `ScopeViolation` abort message in stderr.

---

## 5. Show the evidence and detection output

```bash
cat out/records.json | head -40
```
**Say:** "Each normalized detection record — rule id, severity, endpoint, parameter, stable
fingerprint, and a pointer to the evidence for this scan." Point out `severity` and
`fingerprint` fields.

*(Evidence HAR/screenshot live inside the container and are gitignored/discarded on
teardown by design — mention this is a known Phase 1 scope choice, not a gap: "durable
evidence hosting is a Phase 2/3 concern, tracked as a known gap.")*

---

## 6. Fallback if live infra fails (proxy, registry pull, flaky network)

Don't debug live. Say the line and pivot:
> "Let's not burn demo time on network flakiness — here's the same result verified earlier
> today, plus the test suite that backs it."

```bash
pytest -q
```
**Expect:** `107 passed`. Then show `docs/junior_engineer/testing_and_running_roadmap.md`
§2 for the last known-good containerized run output as backup evidence.

---

## 7. Wrap-up talking points (30 sec)

- All four **primary gate criteria** met: authenticated, in-scope, ≥1 high/medium
  detection, unsafe config refused pre-traffic.
- **Secondary checks** also green: HAR/screenshot captured (redacted), single-command
  container, ~3m36s well under the 15-minute budget.
- Versions pinned by digest (`versions.lock`) — this exact result is reproducible.
- Next up: Phase 2 — LLM-generated `record`/`generate`/`validate` replacing the
  hand-authored `flow.py`, behind the code-safety boundary already scoped in the demo plan.

---

## Quick Q&A cheat-sheet

| Likely question | Answer |
|---|---|
| "Is this hitting a real vulnerability?" | Yes — real ZAP active scan against a real intentionally-vulnerable app (Juice Shop), not a mock. |
| "What if it had scanned prod?" | It can't start — preflight checks `environment_class` before any network call (§2 above). |
| "What happens to blocked requests?" | Blocked, logged with reason, and the scan fails closed — never silently continues (FR-S4). |
| "Is the flow.py hand-written or AI-generated?" | Hand-authored intentionally for Phase 1, to de-risk the ZAP+Playwright+auth integration before adding LLM variability in Phase 2. |
| "Why not test against prod-like data?" | Out of POC scope by design — see requirements §3.2. |

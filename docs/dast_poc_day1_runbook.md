# DAST POC — Day 1 Runbook

## Day 1 goal

Lock the shared contracts and produce one real ZAP fixture, so that Engineer 1's Speckit modules can be built against fixtures **before** the scan runner exists, and Engineer 2 can start the integration spike from an agreed interface.

By end of day, the following are true:

* The `ssd-dast-poc` repo exists, is pushed to the enterprise GitHub org, and both engineers can clone and run the setup.
* `scope.json`, the normalized detection record, and the fingerprint formula are frozen and committed as versioned contract files in `contracts/`.
* A real, hand-captured `sample_zap_output.json` from a ZAP scan of the pilot app is committed to `contracts/`.
* The Speckit constitution encoding NFR-2/3/4 is written.
* The two work streams are formally split and the three handshake checkpoints are on the calendar.

If all six are true, Day 1 succeeded and neither engineer is blocked on the other for Week 1.

## Before you start (pre-Day-1 setup, ~30 min the day before)

Do this ahead of time so Day 1 is not spent fighting installs:

* Both engineers have a working container runtime (Podman is the Nationwide default; Docker only where licensed), Python 3.11+, and access to the enterprise GitHub org.
* Both can pull images from the Nationwide Trusted Registry (`ntr.nwie.net`) — see Appendix A for the container setup and the Windows/WSL proxy fix. Do this the day before; the proxy fix alone can eat hours if hit cold.
* One machine has OWASP ZAP available (desktop app or the `ntr.nwie.net/docker.io/zaproxy/zap-stable` image) and can launch it.
* The pilot app runs locally on `http://localhost:3000` (Juice Shop) — see Appendix A for the exact Podman/Docker command.
* Both have read this document and Sections 6, 7, and 13 of the requirements doc.

## Timeboxed agenda (one working day, ~6.5 focused hours)

| Block | Time | Who | Output |
|-------|------|-----|--------|
| 1. Kickoff & alignment | 30 min | Both | Shared understanding of the four demo acceptance steps and the build-vs-spike split |
| 2. Repo scaffold & push | 45 min | Eng 1 drives, Eng 2 pairs | `ssd-dast-poc` live on GitHub, both cloned |
| 3. Freeze the contracts | 90 min | Both | `scope.json`, detection record, fingerprint formula committed |
| 4. Capture the ZAP fixture | 90 min | Eng 2 drives, Eng 1 pairs | Real `sample_zap_output.json` committed |
| 5. Write the constitution | 45 min | Eng 1 | Speckit constitution with NFR-2/3/4 |
| 6. Split & schedule | 30 min | Both | Work streams assigned, checkpoints booked |
| 7. Day 1 review | 20 min | Both | Exit checklist confirmed |

## Block 1 — Kickoff & alignment (30 min)

Get on the same page before touching code:

* Walk the four demo acceptance steps (Section 9) out loud. Everything built this POC exists to make that four-step demo work — nothing else.
* Confirm the build-vs-spike split from Section 13: Engineer 1 owns the deterministic Speckit modules; Engineer 2 owns the ZAP + Playwright + auth-replay spike.
* State the single most important guardrail out loud (NFR-2): the runner must never contact a host outside the allow-list and must never run against `environment_class: prod`. Everyone agrees this is non-negotiable.
* Agree the working rule: **contracts change only by a PR that both approve.** Once frozen today, the schemas are stable for Week 1.

## Block 2 — Repo scaffold & push (45 min)

Engineer 1 drives; Engineer 2 pairs so both understand the layout.

1. Run the scaffold script (`setup_ssd_dast_poc.sh`) to create the `ssd-dast-poc` tree: `authoring/`, `runner/`, `detections/`, `contracts/`, `security/dast/juice-shop/`, `tests/`.
2. Push to the enterprise GitHub org (not public GitHub). Prefer the `gh` one-liner if available; otherwise create the empty repo in the web UI first and push.
3. Confirm the `.gitignore` excludes `*.har`, `evidence/`, and raw ZAP reports — evidence can contain auth tokens and session cookies and must never land in source control (NFR-3).
4. Both engineers clone the repo fresh and confirm the tree matches. This proves the setup path works before any real code lands.
5. Turn on branch protection on `main` (require one review) so the "contracts change only by reviewed PR" rule is enforced by tooling.

## Block 3 — Freeze the contracts (90 min)

This is the heart of Day 1. Work through each contract together, commit each as a file in `contracts/`, and treat them as frozen afterward.

### 3.1 scope.json (start from Section 7.1)

Confirm every field and its meaning, then commit the pilot instance:

```jsonc
{
  "app_id": "juice-shop",
  "environment_class": "dev",              // must not be "prod"
  "target_fqdn": "localhost",
  "fqdn_allow_list": ["localhost"],        // only these hosts may be contacted
  "fqdn_deny_list": ["*.google-analytics.com"],
  "avoid_action_list": ["logout", "delete-account"]
}
```

Decisions to nail down and write into `contracts/README.md`:

* Is `environment_class` validated as an enum (`dev|test|staging`) with `prod` explicitly rejected? Yes — this is the FR-S3 guard and the NFR-2 safety line.
* Does `fqdn_allow_list` support wildcards, or exact hosts only for the POC? Recommend exact hosts only to keep enforcement simple.
* What does `avoid_action_list` match against — URL substrings, link text, or both? Pick one and document it, since both `record` and the runner depend on it.

Also author a JSON Schema for `scope.json` in `contracts/scope.schema.json`. FR-G2 and FR-V2 both validate against it, so it must exist before Speckit generates those modules.

### 3.2 Normalized detection record (Section 7.2)

Freeze the shape the normalizer emits and the exporter/diff consume:

```jsonc
{
  "app_id": "juice-shop",
  "scan_id": "2025-01-01T10-00-00",
  "fingerprint": "sha256:...",             // stable across scans
  "rule_id": "zap-40018",
  "title": "SQL Injection",
  "severity": "high",                      // critical|high|medium|low|info
  "cwe_id": "CWE-89",
  "endpoint": "/rest/user/login",
  "parameter": "email",
  "status": "open",                        // open|new|resolved
  "evidence_path": "evidence/2025-01-01T10-00-00/active-scan.har"
}
```

Decisions to nail down:

* Which fields are required vs. optional when ZAP omits them (e.g., `cwe_id`, `parameter` may be absent)? Define the fallback (e.g., `cwe_id: null`) so FR-N1's "CWE where available" is unambiguous.
* Fix the `scan_id` format exactly (the timestamp pattern shown) since it also names the evidence directory in FR-E1.
* Confirm the `severity` enum ordering so the SARIF exporter (FR-X1) maps ZAP risk levels to SARIF levels deterministically.

Author `contracts/detection.schema.json` alongside it.

### 3.3 Fingerprint formula (Section 7.3)

Freeze this exactly — it is the backbone of the lifecycle diff (FR-L2), and if it drifts, every "resolved" label is wrong:

```
fingerprint = sha256( rule_id + "|" + endpoint_pattern + "|" + parameter + "|" + payload_family )
```

Decisions to nail down and write down with examples:

* Define `endpoint_pattern` — is `/rest/user/login` used raw, or are numeric/UUID path segments normalized (e.g., `/rest/user/{id}`)? Normalizing prevents fingerprints from churning on IDs; decide and document the rule.
* Define `payload_family` — where does it come from in ZAP output, and what is its value when absent? This is the field most likely to be ambiguous, so pin it with a concrete example from the fixture captured in Block 4.
* Confirm empty-field handling: what string is hashed when `parameter` is missing? Choose a fixed sentinel (e.g., empty string) so FR-N2's "identical fingerprints on unchanged app" holds.

Write two or three worked fingerprint examples into `contracts/README.md` using real values from the Block 4 fixture, so Engineer 1 can unit-test against them.

## Block 4 — Capture the ZAP fixture (90 min)

Engineer 2 drives (this doubles as the first probe of the integration spike); Engineer 1 pairs to confirm the output matches the detection-record contract just frozen.

Goal: a real `sample_zap_output.json` so Engineer 1 can build the normalizer (FR-N1/N2) against genuine ZAP data instead of a guess.

1. Start the pilot app: `docker run --rm -p 3000:3000 bkimminich/juice-shop`.
2. Launch ZAP and set it as the browser proxy (or use ZAP's own browser). Confirm ZAP sees traffic to `localhost:3000`.
3. Manually exercise a few flows that reliably produce findings: the login form, the product search, and one REST endpoint. Juice Shop's login and search are known to surface SQL injection and XSS, which gives varied severities.
4. Run a **bounded** active scan against `localhost:3000` only. Keep it short — this is a fixture, not a full scan.
5. Export the results as JSON (ZAP: Report > Generate Report > JSON, or the `/JSON/core/view/alerts` API). Save it to `contracts/sample_zap_output.json`.
6. Together, walk a few alerts from the export and map each field to the frozen detection record. If ZAP does not provide a clean `payload_family` or `cwe_id`, this is where you discover it — feed that back into the Block 3 decisions and re-freeze if needed.
7. Sanity-check that at least one finding is high/critical (so the SARIF Security-tab demo looks meaningful) and that at least two distinct rule types are present (so the fingerprint diff has variety).

Note: this fixture is a scan of a deliberately vulnerable app on localhost — it contains no real secrets and is safe to commit. Do not commit the HAR/evidence from this run.

## Block 5 — Write the Speckit constitution (45 min)

Engineer 1 authors while the context is fresh. The constitution is the set of house rules Speckit applies to every generated module, so it carries the cross-cutting NFRs rather than repeating them per spec:

* NFR-2 (safety): generated code must validate `scope.json` before any network action and must hard-fail on `environment_class: prod` or a missing allow-list.
* NFR-3 (config/secrets): no hardcoded targets, credentials, or options — everything from files or environment variables; no secrets in the repo.
* NFR-4 (observability): every module emits structured, timestamped logs.
* Project conventions: Python 3.11+, the repo's folder ownership, the contract files in `contracts/` are the single source of truth, and generated code must validate against the committed schemas.

Commit the constitution to the repo so it is versioned with the specs it governs.

## Block 6 — Split & schedule (30 min)

Turn the Section 13 buckets into assigned work and calendar entries:

* Engineer 1, Week 1 (Speckit-first against the fixture): normalizer + fingerprint (FR-N1/N2), SARIF exporter (FR-X1), lifecycle diff (FR-L1/L2), and the deterministic `generate`/`validate` pieces (FR-G2/G3/G4, FR-V2/V3), plus forms/API capture (FR-R3). None of these need the runner.
* Engineer 2, Week 1 (spike, no Speckit ceremony): ZAP proxy + Playwright replay (FR-S1), active scan via API (FR-S2), authenticated-flow recording (FR-R2), and the scope-enforcement mechanism (FR-S4).
* Book the three handshake checkpoints now: end of Day 1 (contracts frozen — today), end of Week 1 (spike proves the authenticated scan works; Speckit modules pass fixture tests), end of Week 2 (integration and pairing on the hybrid FRs).

## Block 7 — Day 1 review (20 min)

Confirm the exit checklist together before closing out:

* [ ] `ssd-dast-poc` is on the enterprise GitHub org; both engineers cloned it clean.
* [ ] `contracts/scope.json` + `scope.schema.json` committed and agreed.
* [ ] `contracts/detection.schema.json` committed and agreed.
* [ ] Fingerprint formula frozen in `contracts/README.md` with worked examples from the real fixture.
* [ ] `contracts/sample_zap_output.json` committed (real ZAP output, at least one high finding, two rule types).
* [ ] Speckit constitution committed with NFR-2/3/4 encoded.
* [ ] Week 1 work assigned; three checkpoints on the calendar.
* [ ] Branch protection on `main` requires review (enforces "contracts change by PR only").

If any box is unchecked, it is the first thing to finish tomorrow morning before Week 1 work proceeds — an unfrozen contract or a missing fixture reintroduces exactly the cross-engineer dependency Day 1 exists to remove.

## Why this ordering matters

The whole point of Day 1 is to decouple the two engineers for Week 1. The fixture (`sample_zap_output.json`) is what lets Engineer 1's normalizer, fingerprint, exporter, and diff be built and unit-tested with zero dependency on the scan runner that Engineer 2 is still spiking. Freezing the three contracts up front means that when the spike and the Speckit modules meet in Week 2, they meet at an interface both agreed to on Day 1 — not one improvised under time pressure. Capturing real ZAP output today (rather than inventing a mock) also front-loads the discovery of ZAP's actual field quirks into a low-stakes moment, instead of during Week 2 integration.

## Appendix A — ZAP & pilot-app container setup (Podman and Docker)

Two self-contained tracks. **Use Track A (Podman)** on Nationwide-managed Windows workstations. **Use Track B (Docker)** only where Docker is licensed/supported. Both pull through the Nationwide Trusted Registry (NTR) rather than Docker Hub directly.

Images (same for both runtimes):
* ZAP: `ntr.nwie.net/docker.io/zaproxy/zap-stable`
* Juice Shop (pilot app): `ntr.nwie.net/docker.io/bkimminich/juice-shop`

### Track A — Podman (Windows / WSL, Nationwide default)

**A1. Authenticate to NTR** (once per token):
```bash
podman login ntr.nwie.net -u <your-nwie-userid>
```

**A2. Clear the stale WSL proxy (one-time).** On Windows, Podman runs in a WSL VM that ships a dead `127.0.0.1:8888` proxy pinned via `DefaultEnvironment=` in systemd. If a pull fails with `proxyconnect tcp: dial tcp 127.0.0.1:8888: connect: connection refused`, fix it inside the VM:
```bash
podman machine ssh
# at [root@... ~]# :
FILE=$(grep -rl '127.0.0.1:8888' /etc/systemd/ 2>/dev/null)
sed -i -E 's#[Hh][Tt][Tt][Pp][Ss]?_[Pp][Rr][Oo][Xx][Yy]=http://127\.0\.0\.1:8888##g' $FILE
systemctl daemon-reexec          # NOT daemon-reload
systemctl restart podman.socket
systemctl show-environment | grep -i proxy   # should show no 8888
exit
```
Notes: `systemctl` runs only inside the VM (never Git Bash); a runtime `systemctl unset-environment` will NOT stick because the proxy is static config. Full details in the standalone runbook "Fixing Podman Image Pulls Behind the Nationwide Proxy (Windows / WSL)".

**A3. Pull the images:**
```bash
podman pull ntr.nwie.net/docker.io/zaproxy/zap-stable
podman pull ntr.nwie.net/docker.io/bkimminich/juice-shop
```

**A4. Run the pilot app and ZAP on one network:**
```bash
podman network create dast
podman run -d --name juice --network dast -p 3000:3000 ntr.nwie.net/docker.io/bkimminich/juice-shop
podman run --rm --network dast -p 8080:8080 ntr.nwie.net/docker.io/zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
# From inside the ZAP container, target the pilot app as http://juice:3000
```

**A5. Verify:**
```bash
curl "http://localhost:8080/JSON/core/view/version/"   # ZAP API up
podman run --rm ntr.nwie.net/docker.io/zaproxy/zap-stable zap.sh -version
```

### Track B — Docker (only where Docker is licensed)

**B1. Point Docker at the NTR Docker Hub mirror** (avoids Docker Hub rate limits / blocks). Add to Docker Desktop's Engine JSON or `/etc/docker/daemon.json`:
```jsonc
{ "registry-mirrors": ["https://dockerhub-mirror.apps.nwie.net"] }
```
Apply/restart Docker. (The mirror only works on VPN.)

**B2. Authenticate to NTR:**
```bash
docker login ntr.nwie.net -u <your-nwie-userid>
```

**B3. Pull the images** (explicit NTR path is most reliable):
```bash
docker pull ntr.nwie.net/docker.io/zaproxy/zap-stable
docker pull ntr.nwie.net/docker.io/bkimminich/juice-shop
```

**B4. Run the pilot app and ZAP on one network:**
```bash
docker network create dast
docker run -d --name juice --network dast -p 3000:3000 ntr.nwie.net/docker.io/bkimminich/juice-shop
docker run --rm --network dast -p 8080:8080 ntr.nwie.net/docker.io/zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
# From inside the ZAP container, target the pilot app as http://juice:3000
```

**B5. Verify:**
```bash
curl "http://localhost:8080/JSON/core/view/version/"
docker run --rm ntr.nwie.net/docker.io/zaproxy/zap-stable zap.sh -version
```

### Shared notes (both tracks)

* For the Day 1 manual fixture capture (Block 4), the **ZAP desktop app** is often easier for clicking through login/search than the daemon; switch to the containerized daemon when Engineer 2 wires the runner in Week 1.
* Pin a specific ZAP tag (e.g. `...zaproxy/zap-stable:2.15.0`) when you freeze the lock file (NFR-1) so scans are reproducible regardless of runtime.
* Never commit HAR/evidence produced by a scan — it can contain auth tokens and session cookies (NFR-3).
* If a pull reaches NTR but fails on a `...amazonaws.com` layer URL, the dead proxy is still bypassing only internal hosts — remove it entirely per A2 so the external S3 layer download also goes direct.

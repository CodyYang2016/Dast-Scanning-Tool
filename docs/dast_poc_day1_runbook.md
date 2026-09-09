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

* Both engineers have a working container runtime (Podman is the Nationwide default; Docker only where licensed), Python 3.11+, and access to the enterprise GitHub org. Note: macOS ships with an older system Python (e.g. 3.9), which is below the 3.11+ requirement — install a current version first, e.g. `brew install python@3.12`, and confirm with `python3.12 --version`.
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
On the workstation this was verified on, `$FILE` resolved to `/etc/systemd/system.conf.d/default-env.conf`, which pinned the proxy via `DefaultEnvironment=` lines. Notes confirmed the hard way:
* `systemctl` runs only inside the VM (after `podman machine ssh`), never in Git Bash.
* A runtime `systemctl unset-environment ...` will **NOT** stick — the proxy is static `DefaultEnvironment=` config, so it must be edited in the file and reloaded with `daemon-reexec` (not `daemon-reload`).
* The pull may succeed on the manifest but then fail on a `...amazonaws.com` layer URL: NTR/Harbor stores blobs in AWS S3 and redirects layer downloads there, so a pull touches both internal and external hosts. Removing the dead proxy entirely (as above) fixes both; a `NO_PROXY`-only workaround must also include `.amazonaws.com` or the layer download still fails.

Full details in the standalone runbook "Fixing Podman Image Pulls Behind the Nationwide Proxy (Windows / WSL)".

**A3. Pull the images:**
```bash
podman pull ntr.nwie.net/docker.io/zaproxy/zap-stable
podman pull ntr.nwie.net/docker.io/bkimminich/juice-shop
```

**A4. Run the pilot app and ZAP on one network:**
```bash
podman network create dast
podman run -d --name juice --network dast -p 3000:3000 ntr.nwie.net/docker.io/bkimminich/juice-shop
podman run -d --name zap --network dast -p 8080:8080 ntr.nwie.net/docker.io/zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true \
  -config 'api.addrs.addr.name=.*' \
  -config api.addrs.addr.regex=true
# From inside the ZAP container, target the pilot app as http://juice:3000
```
The two `api.addrs.addr.*` flags are **required**, not optional. Without them, ZAP 2.17 only accepts API calls from loopback *inside* the container and rejects requests arriving through the Podman port-forward — you get `curl: (52) Empty reply from server` on the host and `Request to API URL ... from 10.88.0.1 not permitted` in `podman logs`. The allow-list makes ZAP accept the forwarded call. **Quote** `'api.addrs.addr.name=.*'` so Git Bash / MINGW64 does not glob or mangle the `.*`.

Use **`-silent`** to stop ZAP from checking for add-on updates and sending telemetry on the locked-down Nationwide network. It is the correct built-in flag and replaces both `-config telemetry.enabled=false` and the **invalid** `-addonupdate=false`. Do **not** pass `-addonupdate=false`: it is not a recognized ZAP option, so the daemon bootstrap aborts with `ERROR ... DaemonBootstrap - Unsupported option '-addonupdate=false'`, leaving the container `Up` with port 8080 mapped but the API/proxy never fully started — after which *every* request (API and proxy alike) returns `curl: (52) Empty reply from server`. This exact failure cost hours during the POC. A clean start instead logs `Shh! No check-for-update - silent mode enabled` and `ZAP is now listening on 0.0.0.0:8080`.

**A5. Verify the setup (verified working sequence).** Check in layers, from "the image runs" up to "ZAP can proxy the target." Give the daemon 30-60s on first run before curling.
```bash
# 1. Image + ZAP itself
podman run --rm ntr.nwie.net/docker.io/zaproxy/zap-stable zap.sh -version   # prints e.g. 2.17.0

# 2. Daemon up
podman ps                     # zap should be "Up", port 0.0.0.0:8080->8080/tcp
podman logs zap | tail -30    # look for "ZAP is now listening on 0.0.0.0:8080"

# 3. API reachable (the definitive up-check)
curl "http://localhost:8080/JSON/core/view/version/"     # -> {"version":"2.17.0"}

# 4. Scan subsystems loaded
curl "http://localhost:8080/JSON/core/view/sites/"          # -> {"sites":[]}  (empty is fine)
curl "http://localhost:8080/JSON/ascan/view/scanners/" | head   # long JSON list of active-scan rules

# 5. Target reachable from inside the ZAP container (must print 200)
podman exec zap curl -sS -m 10 -o /dev/null -w "%{http_code}\n" http://juice:3000/

# 6. Proxy actually intercepts (crux of FR-S1) — drive it via the API, NOT a host proxy
curl "http://localhost:8080/JSON/core/action/accessUrl/?url=http://juice:3000/&followRedirects=true"
#   -> {"accessUrl":[{ ... "responseHeader":"HTTP/1.1 200 OK ...", "requestHeader":"GET http://juice:3000/ ..." }]}
curl "http://localhost:8080/JSON/core/view/sites/"          # 'juice:3000' now backed by a real fetch
```
What "correct" looks like and two benign results that are **not** errors:
* `{"sites":[]}` before any traffic is expected — it fills in after step 5.
* `spider/view/status/` returning `{"code":"does_not_exist","message":"Does Not Exist"}` is **normal** — that endpoint needs a `scanId` from a spider run, and none exists yet. The plugin is loaded fine.
* With `-silent` set (A4), ZAP does **not** phone home, so you should not see the `ExtensionCallHome` / update-check stack traces at all — the log instead shows `Shh! ... silent mode enabled` and `Shh! Silent mode or telemetry turned off`. If those traces *do* appear, `-silent` didn't take effect — most often because the invalid `-addonupdate=false` flag aborted startup first (see A4).
* **The Sites tree is not proof of a successful fetch.** ZAP records a target in `/JSON/core/view/sites/` the moment a request is *attempted* through the proxy, even if it times out — so `{"sites":["http://juice:3000"]}` can appear alongside a `Failed to read ... within 20 seconds` error. Use the `accessUrl` response's `responseHeader:"HTTP/1.1 200 OK"` (step 6) as the real proof, not mere presence in the Sites list.
* **Don't rely on `curl -x http://localhost:8080 ...` from the host.** Routing the host's own traffic out through ZAP's proxy port over the Podman port-forward is flaky and returns `curl: (52) Empty reply` / `(56) Connection aborted` even when ZAP is healthy. It is not the path the scanner uses — the runner drives ZAP through the API (`accessUrl`, spider, ascan), which is what step 6 verifies.

**If steps 5-6 fail with a connect timeout / `000` (containers can't talk):** you have likely accumulated stale container IPs from recreating `juice` (or `zap`) several times — the DNS name resolves to an old IP. Do a clean full reset in order rather than reconnecting a live container:
```bash
podman rm -f zap juice
podman network rm dast 2>/dev/null; podman network create dast
podman run -d --name juice --network dast -p 3000:3000 ntr.nwie.net/docker.io/bkimminich/juice-shop
podman run -d --name zap --network dast -p 8080:8080 ntr.nwie.net/docker.io/zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true
# then confirm BOTH are attached before testing:
podman network inspect dast --format '{{range .Containers}}{{.Name}} {{end}}'   # must list: zap juice
```

Cleanup when done: `podman rm -f zap juice`.

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
docker run -d --name zap --network dast -p 8080:8080 ntr.nwie.net/docker.io/zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true \
  -config 'api.addrs.addr.name=.*' \
  -config api.addrs.addr.regex=true
# From inside the ZAP container, target the pilot app as http://juice:3000
```
The `api.addrs.addr.*` flags are required for the same reason as Track A — without them the API rejects calls forwarded through the container port and `curl` returns an empty reply. Use `-silent` (not the invalid `-addonupdate=false`, which aborts ZAP's daemon bootstrap) to suppress update checks and telemetry, and quote `'api.addrs.addr.name=.*'` in bash — same reasoning as Track A's A4.

**B5. Verify:** same layered checks as Track A's A5 (swap `podman`->`docker`):
```bash
docker run --rm ntr.nwie.net/docker.io/zaproxy/zap-stable zap.sh -version
docker ps
docker logs zap | tail -30
curl "http://localhost:8080/JSON/core/view/version/"     # -> {"version":"2.17.0"}
curl "http://localhost:8080/JSON/core/view/sites/"        # {"sites":[]} until traffic is proxied
```
The same two benign results apply: an empty `sites` list before traffic, and the `ExtensionCallHome` telemetry stack trace in the logs.

### Shared notes (both tracks)

* For the Day 1 manual fixture capture (Block 4), the **ZAP desktop app** is often easier for clicking through login/search than the daemon; switch to the containerized daemon when Engineer 2 wires the runner in Week 1.
* Pin a specific ZAP tag (e.g. `...zaproxy/zap-stable:2.17.0`, the version verified for this POC) when you freeze the lock file (NFR-1) so scans are reproducible regardless of runtime.
* **Security caveat (POC-only):** `api.addrs.addr.name=.*` combined with `api.disablekey=true` means anyone who can reach port 8080 can drive ZAP unauthenticated. That is acceptable for a local, throwaway container on a workstation, but when Engineer 2 wires the runner for real, tighten it: keep an API key (`-config api.key=<from-env>`, per NFR-3) instead of `disablekey`, and scope `api.addrs` to the runner's actual subnet rather than `.*`.
* Never commit HAR/evidence produced by a scan — it can contain auth tokens and session cookies (NFR-3).
* If a pull reaches NTR but fails on a `...amazonaws.com` layer URL, the dead proxy is still bypassing only internal hosts — remove it entirely per A2 so the external S3 layer download also goes direct.

## Appendix B — Capturing the Day-1 fixture (spider -> active scan -> export)

This is the scripted version of Block 4: it drives ZAP entirely through its REST API to produce `contracts/sample_zap_output.json`, the real ZAP alerts export the normalizer (FR-N1) is built against. **No `record` CLI / Playwright is involved** — this uses ZAP's own spider to seed traffic, which is the fast path to real findings on Day 1. The output shape (ZAP alerts JSON) is identical to what an authenticated, Playwright-seeded scan produces later, so building the normalizer against it is valid.

**How it works (three async phases + export):**
1. **Spider** discovers URLs by following links and populates ZAP's Sites tree. Fast (seconds-minutes).
2. **Passive-scan drain** — wait for ZAP to finish analysing what the spider queued.
3. **Active scan** replays and mutates those requests with attack payloads. This is the slow phase (~5-40 min on Juice Shop depending on breadth) and is where the actual findings come from.
4. **Export** pulls the alerts via `/JSON/core/view/alerts` and writes the fixture.

Each `action/scan` call returns *immediately* with a numeric scan ID; the work runs in the background, so the script **polls** `view/status` (0-100) until each phase reaches 100 before moving on. Exporting early yields partial/empty results.

The script uses only `curl` + `grep`/`sed`, so it runs in Git Bash with no `jq` or Python dependency.

```bash
#!/usr/bin/env bash
# A capture the Day-1 ZAP fixture: spider -> active scan -> export alerts JSON
ZAP="http://localhost:8080"
TARGET="http://juice:3000"
OUT="contracts/sample_zap_output.json"
mkdir -p "$(dirname "$OUT")"

num() { grep -o '[0-9][0-9]*' | head -1; }   # first integer in a ZAP JSON reply

echo ">> 0. ZAP up?"
curl -sS "$ZAP/JSON/core/view/version/"; echo

echo ">> Seed the target so the spider has a root"
curl -sS "$ZAP/JSON/core/action/accessUrl/?url=$TARGET/&followRedirects=true" >/dev/null

echo ">> 1. Spider (discovery)"
SID=$(curl -sS "$ZAP/JSON/spider/action/scan/?url=$TARGET/&recurse=true" | num); SID=${SID:-0}
echo "   spider scanId=$SID"
while :; do
  P=$(curl -sS "$ZAP/JSON/spider/view/status/?scanId=$SID" | num); P=${P:-0}
  echo "   spider: ${P}%"; [ "$P" -ge 100 ] && break; sleep 3
done

echo ">> 2. Let passive scanning drain"
while :; do
  Q=$(curl -sS "$ZAP/JSON/pscan/view/recordsToScan/" | num); Q=${Q:-0}
  echo "   pscan queue: $Q"; [ "$Q" -le 0 ] && break; sleep 2
done

echo ">> 3. Active scan (attack - slow phase)"
AID=$(curl -sS "$ZAP/JSON/ascan/action/scan/?url=$TARGET/&recurse=true&inScopeOnly=false" | num); AID=${AID:-0}
echo "   ascan scanId=$AID"
while :; do
  P=$(curl -sS "$ZAP/JSON/ascan/view/status/?scanId=$AID" | num); P=${P:-0}
  echo "   ascan: ${P}%"; [ "$P" -ge 100 ] && break; sleep 5
done

echo ">> 4. Export alerts -> $OUT"
curl -sS "$ZAP/JSON/core/view/alerts/?baseurl=$TARGET&start=0&count=9999" -o "$OUT"

echo ">> 5. Sanity check (fixture must have >=1 High and >=2 rule types)"
echo "   total alerts:      $(grep -o '"alert":' "$OUT" | wc -l | tr -d ' ')"
echo "   High findings:     $(grep -o '"risk":"High"' "$OUT" | wc -l | tr -d ' ')"
echo "   distinct rule IDs: $(grep -o '"pluginId":"[0-9]*"' "$OUT" | sort -u | wc -l | tr -d ' ')"
echo "Done -> $OUT. Walk a few alerts and map fields to the Block 3 detection record."
```

**Tuning breadth vs. time:**
* **Faster** (targeted, ~5 min): skip the spider and scan only a couple of known-vulnerable endpoints, e.g. replace phase 3 with `ascan/action/scan/?url=http://juice:3000/rest/products/search?q=` and add the login POST. Enough to get varied findings for the fixture.
* **Fuller** (default above, ~20-40 min): spider then active-scan the whole tree; more findings, higher chance of multiple High-severity rules.

**Success criteria (from the Day-1 checklist):** the export contains at least one **High** finding and at least **two distinct rule types** (`pluginId`s). Juice Shop's search/login reliably surface SQL injection and XSS, so the default run satisfies both. If a field you froze in Block 3 (e.g. `payload_family`, `cweid`) is missing or empty on some alerts, that is the discovery moment — feed it back into the contract and re-freeze.

**Do not commit evidence:** the alerts JSON is the fixture and is committed; any HAR/evidence with tokens or cookies must stay out of source control (NFR-3).

# Reproducing `contracts/sample_zap_output.json`

A step-by-step, copy-pasteable guide to regenerate the ZAP fixture from scratch. Anyone with
Docker and this repo should be able to follow it end-to-end and land a fixture that meets the
Day-1 bar: **real ZAP output with ≥1 High finding and ≥2 distinct rule types.**

The whole flow is wrapped in `runner/capture_zap_fixture.sh`; this doc explains what that
script does, how to run it, and every non-obvious thing we hit while building it.

---

## 0. What this produces

`contracts/sample_zap_output.json` — a real, but **representative (capped)** export of ZAP
alerts from a scan of OWASP Juice Shop. It is the fixture Engineer 1 builds the normalizer
and fingerprint against (FR-N1/N2), with zero dependency on the scan runner.

The committed fixture: **38 alerts, 8 distinct `pluginId`s, 1 High (SQL Injection, `40018`).**

---

## 1. Prerequisites

- **Docker** running (we used 29.4.3 on macOS/arm64). Podman works too — swap `docker`→`podman`.
- This repo checked out; run all commands from the repo root.
- Network access to pull two public images from Docker Hub:
  - `bkimminich/juice-shop` (the pilot app)
  - `zaproxy/zap-stable` (the scanner; we used ZAP 2.17.0)
- Python 3 (only needed for the JSON post-processing; the system Python is fine for that).

> **Nationwide note:** on a corporate workstation, pull the same images through the Trusted
> Registry instead — `ntr.nwie.net/docker.io/bkimminich/juice-shop` and
> `ntr.nwie.net/docker.io/zaproxy/zap-stable` — and see `docs/dast_poc_day1_runbook.md`
> Appendix A for the Podman/WSL proxy fixes.

---

## 2. Start the pilot app and ZAP on one network

```bash
# Pull images (first time only)
docker pull bkimminich/juice-shop
docker pull zaproxy/zap-stable

# One shared network so ZAP can reach the app by name
docker network create dast

# Pilot app — reachable from the host at localhost:3000, and from the ZAP
# container as http://juice:3000
docker run -d --name juice --network dast -p 3000:3000 bkimminich/juice-shop

# ZAP daemon — API exposed on the host at localhost:8080
docker run -d --name zap --network dast -p 8080:8080 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true \
  -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true
```

**Why the extra `-config` flags matter (we hit both of these):**

- `api.disablekey=true` + `api.addrs.addr.*` — without the `api.addrs` allow-list, ZAP 2.17
  **rejects API calls that arrive through the Docker port-forward** (they come from the
  container gateway IP, not loopback). Symptom: `curl: (52) Empty reply from server` on the
  host and `Request to API URL ... not permitted` in `docker logs zap`. Quote
  `'api.addrs.addr.name=.*'` so the shell doesn't glob-expand the `.*`.
- `-silent` — stops ZAP from phoning home / checking for add-on updates on a locked-down
  network. (Do **not** use `-addonupdate=false`; it's an invalid flag that aborts ZAP's
  daemon bootstrap, after which every request returns an empty reply.)

---

## 3. Verify ZAP is up and can reach the app

Give the daemon ~30–60s on first boot, then:

```bash
# ZAP API alive?
curl -s "http://localhost:8080/JSON/core/view/version/"      # -> {"version":"2.17.0"}

# Can the ZAP container reach the pilot app? (must print 200)
docker exec zap curl -sS -m 10 -o /dev/null -w "%{http_code}\n" http://juice:3000/
```

If the version curl hangs or returns empty, re-check the `api.addrs` flags in step 2.

---

## 4. Run the capture

```bash
bash runner/capture_zap_fixture.sh
```

That's it. Tunable via env vars (defaults shown):

| Var | Default | Meaning |
|-----|---------|---------|
| `ZAP_API` | `http://localhost:8080` | ZAP API base (host side) |
| `TARGET` | `http://juice:3000` | Pilot app as seen **from the ZAP container** |
| `OUT` | `contracts/sample_zap_output.json` | Output fixture path |
| `MAX_SCAN_MIN` | `4` | Hard cap on total active-scan minutes |
| `MAX_RULE_MIN` | `1` | Hard cap per scan rule |
| `MAX_PER_RULE` | `6` | Max instances kept per rule in the fixture (High/Critical kept in full) |

### What the script does internally (and why)

1. **Bounds & lightens the scan policy.** Sets `MaxScanDurationInMins` / `MaxRuleDurationInMins`
   and **disables scanner `40026` (DOM-based XSS)**. The DOM-XSS scanner launches real
   Chromium instances; with the default policy it saturated ZAP and wedged the API entirely
   (`ZAP-DomXssReaper` + "browser launch" in the logs). Disabling it keeps the run bounded.
2. **Seeds the injectable API endpoints.** Juice Shop is a JavaScript SPA, so ZAP's
   traditional spider never discovers the `/rest/*` endpoints that carry the vulnerable
   parameters. A naive scan therefore finds **zero High-severity issues**. The script feeds
   the key endpoints to ZAP directly via `accessUrl` — most importantly
   `/rest/products/search?q=apple`, which is textbook High SQL injection on param `q`.
3. **Spiders** the target, polling `/JSON/spider/view/status` to 100%.
4. **Runs a bounded active scan** on the pilot host only (honors the scope guardrail, NFR-2),
   polling `/JSON/ascan/view/status` to 100% (or until the time cap).
5. **Exports and caps.** ZAP emits one entry per alert *instance* (per URL/param), so a
   passive rule can fire hundreds of near-identical times — our first raw export was **5.2 MB
   / 2,497 alerts**. The script keeps at most `MAX_PER_RULE` instances per rule (but **never**
   drops High/Critical), producing a small, diffable fixture that still carries every distinct
   rule. This is real ZAP output, just a representative subset.

Polling is resilient (retries + guards against transient empty replies) so a single API
hiccup can't kill a multi-minute run.

Expected tail of the output:

```
-- export alerts (cap 6/rule) -> contracts/sample_zap_output.json --
   alerts=38  distinct pluginIds=8
   by risk: {'Medium': 14, 'Low': 11, 'Informational': 12, 'High': 1}
== done ==
```

---

## 5. Verify the fixture meets the bar

```bash
python3 - contracts/sample_zap_output.json <<'PY'
import json,sys
a=json.load(open(sys.argv[1]))["alerts"]
plugins=sorted({x.get("pluginId") for x in a})
risks={}
for x in a: risks[x.get("risk")]=risks.get(x.get("risk"),0)+1
highs=(risks.get("High",0)+risks.get("Critical",0))
print("total alerts:",len(a),"| distinct pluginIds:",len(plugins),"| by risk:",risks)
print("BAR ->", "PASS" if highs>=1 and len(plugins)>=2 else "FAIL")
PY
```

You want `PASS`: ≥1 High and ≥2 distinct `pluginId`s.

---

## 6. (Optional) Re-derive the fingerprint worked examples

The two worked examples in `contracts/README.md` are computed from this fixture. To reproduce
them, take the real values from the High SQLi alert (`40018`, url `/rest/products/search`,
param `q`) and a passive CSP alert (`10038`, url `/`, no param), then run the frozen
reference implementation from `contracts/README.md`:

```bash
python3 <<'PY'
import hashlib
def fp(rule,ep,param,fam):
    pre="|".join(p.replace("|","") for p in [rule, ep or "/", param or "", fam or "none"])
    return hashlib.sha256(pre.encode()).hexdigest()
print("sqli   :", fp("40018","/rest/products/search","q","sqli"))
print("headers:", fp("10038","/","","headers"))
PY
# -> sqli   : ece130214d0131cf2c0d71334a6719a0442d794cc6dfe9faababed15c7fcf3db
# -> headers: 6c668292549821d6f3742016bf4371a07524016924cae5a57735ba0ca71cf35f
```

These must match the digests written in `contracts/README.md`. If they don't, the formula or
the mapping drifted — treat it as a contract change (reviewed PR).

---

## 7. Cleanup

```bash
docker rm -f zap juice
docker network rm dast
```

---

## Troubleshooting (everything we actually hit)

| Symptom | Cause | Fix |
|---------|-------|-----|
| `curl: (52) Empty reply` on `/JSON/core/view/version/` | ZAP rejecting the forwarded API call | Add `-config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true` (step 2) |
| `Request to API URL ... not permitted` in `docker logs zap` | Same as above | Same as above |
| ZAP API goes unresponsive mid-scan; logs show `ZAP-DomXssReaper` / "browser launch" | DOM-XSS active scanner spawning real browsers | Disable scanner `40026` (the script does this); if already wedged, `docker rm -f zap` and restart |
| Scan finishes but **0 High findings** | Juice Shop SPA — spider never saw `/rest/*` params | Seed injectable endpoints before scanning (the script does this) |
| Fixture is multiple MB / thousands of alerts | ZAP emits one entry per alert instance | Cap per rule on export via `MAX_PER_RULE` (the script does this) |
| Script dies on a transient empty API reply | `curl -f` + `pipefail` on a one-off hiccup | Already handled — the script retries and guards empty responses |

## Safety note

This fixture is a scan of a **deliberately vulnerable app on localhost** — it contains no
real secrets and is safe to commit. Do **not** commit the HAR/evidence from a scan; it can
contain auth tokens and session cookies (NFR-3). `.gitignore` already excludes `*.har` and
`evidence/`.

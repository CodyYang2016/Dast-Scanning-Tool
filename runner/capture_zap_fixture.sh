#!/usr/bin/env bash
# capture_zap_fixture.sh — capture a real ZAP fixture for contracts/sample_zap_output.json
#
# Drives the already-running ZAP daemon (API) to spider + bounded active-scan the pilot
# app, then exports the alerts JSON. Bounded to the pilot host only (honors the scope
# guardrail, NFR-2). Produces the fixture Engineer 1 builds the normalizer against (FR-N1).
#
# The active scan is deliberately BOUNDED and LIGHT (runbook Block 4: "keep it short — this
# is a fixture, not a full scan"):
#   * a hard server-side cap on scan + per-rule duration, and
#   * the browser-launching DOM-XSS scanner (pluginId 40026) is disabled — with the default
#     policy it spawns real Chromium instances, saturates ZAP, and wedges the API.
#
# Prereqs (see docs/dast_poc_day1_runbook.md Appendix A): ZAP daemon reachable on
# $ZAP_API and the pilot app reachable from inside the ZAP container as $TARGET.
#
# Usage:  runner/capture_zap_fixture.sh
set -uo pipefail

ZAP_API="${ZAP_API:-http://localhost:8080}"     # ZAP API base (host-side)
TARGET="${TARGET:-http://juice:3000}"           # pilot app as seen from the ZAP container
OUT="${OUT:-contracts/sample_zap_output.json}"
MAX_SCAN_MIN="${MAX_SCAN_MIN:-4}"               # hard cap on the whole active scan
MAX_RULE_MIN="${MAX_RULE_MIN:-1}"               # hard cap per scan rule
SLOW_SCANNERS="40026"                            # DOM-XSS (browser-based) — too heavy for a fixture
MAX_PER_RULE="${MAX_PER_RULE:-6}"                # keep the fixture small: cap instances per rule
                                                 # (High/Critical are always kept in full)

echo "== ZAP fixture capture =="
echo "   ZAP_API=$ZAP_API  TARGET=$TARGET  OUT=$OUT  cap=${MAX_SCAN_MIN}m"

# zap_json <path+query> : GET the ZAP API resiliently, echo body ("" on failure).
zap_json() { curl -s --retry 5 --retry-delay 2 --retry-all-errors -m 15 "$ZAP_API/$1" 2>/dev/null; }

# jget <json> <python-expr over d> : extract a field, "" on parse failure.
jget() { printf '%s' "$1" | python3 -c "import sys,json
try: d=json.load(sys.stdin); print($2)
except Exception: print('')" 2>/dev/null; }

# 0. Sanity: ZAP up
[ -n "$(zap_json 'JSON/core/view/version/')" ] || { echo "ZAP API not reachable at $ZAP_API"; exit 1; }

# 1. Bound + lighten the active scan policy
zap_json "JSON/ascan/action/setOptionMaxScanDurationInMins/?Integer=$MAX_SCAN_MIN" >/dev/null
zap_json "JSON/ascan/action/setOptionMaxRuleDurationInMins/?Integer=$MAX_RULE_MIN" >/dev/null
zap_json "JSON/ascan/action/disableScanners/?ids=$SLOW_SCANNERS" >/dev/null

# 2. Seed the target + known param-bearing API endpoints through the proxy.
#    Juice Shop is a JS SPA, so the traditional spider never discovers the /rest/* API
#    endpoints that carry the injectable params. We must feed them to ZAP directly, or the
#    active scanner has no high-severity attack points to hit (runbook Block 4). The search
#    endpoint below is textbook High SQL-injection in Juice Shop (param q).
zap_json "JSON/core/action/accessUrl/?url=$TARGET/&followRedirects=true" >/dev/null
SEED_URLS=(
  "$TARGET/rest/products/search?q=apple"
  "$TARGET/rest/user/whoami"
  "$TARGET/rest/products/1/reviews"
  "$TARGET/api/Products/1"
  "$TARGET/api/Feedbacks/"
)
for u in "${SEED_URLS[@]}"; do
  zap_json "JSON/core/action/accessUrl/?url=$u&followRedirects=true" >/dev/null
  echo "   seeded: $u"
done

# 3. Spider, poll to 100% (bounded iterations as a backstop)
echo "-- spider --"
SPIDER_ID=$(jget "$(zap_json "JSON/spider/action/scan/?url=$TARGET&recurse=true")" 'd["scan"]')
for _ in $(seq 1 120); do
  PCT=$(jget "$(zap_json "JSON/spider/view/status/?scanId=$SPIDER_ID")" 'd["status"]')
  echo "   spider ${PCT:-?}%"
  [ "$PCT" = "100" ] && break
  sleep 3
done

# 4. Bounded active scan on the pilot host only, poll to 100% (server cap + loop backstop)
echo "-- active scan (bounded to $TARGET, DOM-XSS disabled, ${MAX_SCAN_MIN}m cap) --"
ASCAN_ID=$(jget "$(zap_json "JSON/ascan/action/scan/?url=$TARGET&recurse=true")" 'd["scan"]')
for _ in $(seq 1 120); do
  PCT=$(jget "$(zap_json "JSON/ascan/view/status/?scanId=$ASCAN_ID")" 'd["status"]')
  echo "   ascan ${PCT:-?}%"
  [ "$PCT" = "100" ] && break
  sleep 5
done

# 5. Export alerts to the fixture. ZAP emits one entry per alert *instance* (per url/param),
#    so a passive rule can fire hundreds of near-identical times. Cap instances per rule to
#    keep the fixture small and diffable while preserving every distinct rule and all
#    High/Critical findings in full. This is real ZAP output, just a representative subset.
echo "-- export alerts (cap ${MAX_PER_RULE}/rule) -> $OUT --"
ALERTS_JSON="$(zap_json "JSON/alert/view/alerts/?baseurl=$TARGET")"
[ -n "$ALERTS_JSON" ] || { echo "ERROR: empty alerts response from ZAP"; exit 1; }
printf '%s' "$ALERTS_JSON" | MAX_PER_RULE="$MAX_PER_RULE" python3 -c '
import sys, json, os
cap = int(os.environ["MAX_PER_RULE"])
alerts = json.load(sys.stdin)["alerts"]
kept, seen = [], {}
for a in alerts:
    if a.get("risk") in ("High", "Critical"):   # never drop the important ones
        kept.append(a); continue
    pid = a.get("pluginId")
    seen[pid] = seen.get(pid, 0) + 1
    if seen[pid] <= cap:
        kept.append(a)
json.dump({"alerts": kept}, open(sys.argv[1], "w"), indent=2)
' "$OUT"

# 6. Report the bar: high-severity count and distinct plugin ids
python3 - "$OUT" <<'PY'
import json, sys
alerts = json.load(open(sys.argv[1]))["alerts"]
plugins = sorted({a.get("pluginId") for a in alerts})
by_risk = {}
for a in alerts:
    by_risk[a.get("risk")] = by_risk.get(a.get("risk"), 0) + 1
print(f"   alerts={len(alerts)}  distinct pluginIds={len(plugins)}")
print(f"   by risk: {by_risk}")
PY
echo "== done =="

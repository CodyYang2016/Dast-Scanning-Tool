#!/usr/bin/env bash
# Capture the Day-1 ZAP fixture: spider -> active scan -> export alerts JSON.
# Prereq: zap + juice containers running on the 'dast' network (see runbook Appendix A).
set -u
ZAP="${ZAP:-http://localhost:8080}"
TARGET="${TARGET:-http://juice:3000}"
OUT="${OUT:-contracts/sample_zap_output.json}"
mkdir -p "$(dirname "$OUT")"

num() { grep -o '[0-9][0-9]*' | head -1; }

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
echo "Done -> $OUT"

#!/usr/bin/env bash
# W8-2: demonstrate the project's definition of done — fix → re-scan → `resolved` — and its
# counter-case, a route the re-scan did not visit, which must stay `not_scanned`.
#
# The "fix" is DVWA's own hardened implementation: security level `impossible` (parameterised
# queries, output encoding) instead of `low`. Scan 2 also excludes /vulnerabilities/xss_r, so its
# findings are absent for a reason that is NOT a fix.
#
# Runs in its own output root, so out/dvwa and its lifecycle state are untouched. app.yaml is
# edited for each scan and restored on exit, whatever happens.
#
#   DVWA_USER=admin DVWA_PASS=password ZAP_API_KEY=... scripts/demo_fix_rescan.sh [out-dir]
set -euo pipefail
cd "$(dirname "$0")/.."
DEMO=${1:-out/demo-fix-rescan}
PY=${PY:-.venv/bin/python}
CFG=security/dast/dvwa/app.yaml
BACKUP=$(mktemp)
cp "$CFG" "$BACKUP"
trap 'cp "$BACKUP" "$CFG"; rm -f "$BACKUP"' EXIT

variant() {   # $1 = security level, $2 = extra exclusion (or "")
  "$PY" - "$BACKUP" "$CFG" "$1" "$2" <<'PYEOF'
import sys, yaml
src, dst, level, exclude = sys.argv[1:]
cfg = yaml.safe_load(open(src))
cfg["auth"].setdefault("cookies", {})["security"] = level
cfg["scan"].pop("dom_xss", None)            # keep each scan to ~10 minutes
if exclude:
    cfg["scope"]["exclude"] = cfg["scope"].get("exclude", []) + [exclude]
yaml.safe_dump(cfg, open(dst, "w"), sort_keys=False)
PYEOF
}

rm -rf "$DEMO"
mkdir -p "$DEMO/dvwa/authoring"
cp -R out/dvwa/authoring/bundle "$DEMO/dvwa/authoring/bundle"
[ -d out/dvwa/authoring/trace ] && cp -R out/dvwa/authoring/trace "$DEMO/dvwa/authoring/trace"

echo "== scan 1: security=low (vulnerable)"
variant low ""
"$PY" dast.py scan dvwa --out "$DEMO"
"$PY" dast.py report dvwa --out "$DEMO" --fail-on none

echo "== scan 2: security=impossible (DVWA's fixed code), /vulnerabilities/xss_r excluded"
variant impossible "/vulnerabilities/xss_r"
"$PY" dast.py scan dvwa --out "$DEMO"
"$PY" dast.py report dvwa --out "$DEMO" --fail-on none
"$PY" dast.py explain dvwa --out "$DEMO" --limit 40 | tee "$DEMO/explain.txt"

"$PY" - "$DEMO" <<'PYEOF'
import json, sys, pathlib, collections
demo = pathlib.Path(sys.argv[1]) / "dvwa" / "scans"
runs = sorted(p for p in demo.iterdir() if (p / "labeled.json").exists())
first, second = runs[-2], runs[-1]
l1 = json.loads((first / "labeled.json").read_text())
l2 = json.loads((second / "labeled.json").read_text())
sarif = json.loads((second / "results.sarif").read_text())
in_sarif = {r["partialFingerprints"]["dastFingerprint/v1"] for r in sarif["runs"][0]["results"]}
status2 = {r["fingerprint"]: r["status"] for r in l2}
highs = [r for r in l1 if r["severity"] == "high"]
out = {
    "scan_1": {"id": first.name, "statuses": dict(collections.Counter(r["status"] for r in l1))},
    "scan_2": {"id": second.name, "statuses": dict(collections.Counter(r["status"] for r in l2))},
    "scan_1_highs_in_scan_2": [
        {"title": r["title"], "endpoint": r["endpoint"], "parameter": r.get("parameter"),
         "fingerprint": r["fingerprint"], "status_after_rescan": status2.get(r["fingerprint"]),
         "in_rescan_sarif": r["fingerprint"] in in_sarif} for r in highs],
}
(demo.parent.parent / "fix_rescan_resolved.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps(out, indent=2))
PYEOF

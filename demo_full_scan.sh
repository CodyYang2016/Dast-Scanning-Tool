#!/usr/bin/env bash
# Run the full scan gate on Podman without foreground podman-compose up, then export SARIF.
# This avoids the Windows Python asyncio signal-handler failure in podman-compose foreground mode.
#
# ZAP requires an API key and admits only the runner's fixed address (172.28.0.10), so the
# runner container is started on that address with the same key. Export ZAP_API_KEY first to
# reuse one key across terminals; otherwise one is generated for this run.
#
# Images: JUICE_IMAGE / ZAP_IMAGE override the digests in compose.yaml, e.g. an NTR mirror:
#   ZAP_IMAGE=ntr.nwie.net/docker.io/zaproxy/zap-stable bash ./demo_full_scan.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

for required_file in compose.yaml compose.demo.yaml Containerfile security/dast/juice-shop/flow.py security/dast/juice-shop/scope.json; do
  if [ ! -f "$required_file" ]; then
    echo "Missing required file: $required_file" >&2
    echo "This script must live at the DAST POC repo root." >&2
    exit 1
  fi
done

if [ -z "${ZAP_API_KEY:-}" ]; then
  ZAP_API_KEY="$(openssl rand -hex 24 2>/dev/null || python -c 'import secrets; print(secrets.token_hex(24))')"
  echo ">> Generated a ZAP_API_KEY for this run (not printed); export your own beforehand to call ZAP from another terminal" >&2
fi
export ZAP_API_KEY

repo_root_win="$(pwd -W 2>/dev/null || cygpath -w "$PWD" 2>/dev/null || pwd)"
network="ssd-dast-poc_dast"
runner_image="localhost/ssd-dast-poc_runner:latest"
runner_ip="${DAST_RUNNER_IP:-172.28.0.10}"
compose_files=(-f compose.yaml -f compose.demo.yaml)
export PIP_INDEX_URL="${PIP_INDEX_URL:-https://art.nwie.net/artifactory/api/pypi/pypi/simple}"

echo ">> Reset full-scan demo containers"
podman-compose "${compose_files[@]}" down -v >/dev/null 2>&1 || true
podman pod rm -f pod_ssd-dast-poc >/dev/null 2>&1 || true
podman rm -f ssd-dast-poc_juice_1 ssd-dast-poc_zap_1 ssd-dast-poc_runner_1 >/dev/null 2>&1 || true
podman network rm "$network" dast >/dev/null 2>&1 || true

echo ">> Build runner image"
bash scripts/stage_ca_bundle.sh
podman-compose "${compose_files[@]}" build runner

rm -f out/records.json out/coverage.json out/labeled.json out/results.sarif out/state.json
mkdir -p out

echo ">> Start Juice Shop target and ZAP scanner in detached mode"
podman-compose "${compose_files[@]}" up -d juice zap

run_runner() {
  MSYS_NO_PATHCONV=1 podman run --rm \
    --network "$network" \
    --ip "$runner_ip" \
    --env RUNNER_CHROMIUM_NO_SANDBOX=1 \
    --env ZAP_API_KEY \
    --volume "${repo_root_win}/out:/app/out" \
    "$@"
}

run_runner_python() {
  run_runner --entrypoint python "$runner_image" "$@"
}

echo ">> Wait for Juice Shop and ZAP readiness"
run_runner_python \
  -c "from runner.main import wait_ready; wait_ready('http://zap:8080', 'http://juice:3000'); print('services ready: zap=http://zap:8080 target=http://juice:3000')"

echo ">> Run full scan gate: replay + ZAP spider + ZAP active scan + normalize"
set +e
run_runner "$runner_image" \
  --scope=security/dast/juice-shop/scope.json \
  --flow=security/dast/juice-shop/flow.py \
  --base-url=http://juice:3000 \
  --zap-api=http://zap:8080 \
  --zap-proxy=http://zap:8080 \
  --records-out=/app/out/records.json \
  --coverage-out=/app/out/coverage.json \
  --evidence-dir=/app/out/evidence \
  --expect-findings
gate=$?
set -e
echo ">> Scan gate exit code: $gate"

if [ ! -f out/records.json ]; then
  echo "No out/records.json was written; nothing to export." >&2
  exit "$gate"
fi

echo ">> Label findings and export SARIF for the GitHub Security tab"
run_runner_python -m detections.lifecycle_diff /app/out/records.json \
  --app-id juice-shop --state /app/out/state.json --coverage /app/out/coverage.json \
  -o /app/out/labeled.json
run_runner_python -m detections.sarif_export /app/out/labeled.json \
  --app-id juice-shop --category dast/juice-shop -o /app/out/results.sarif

echo ">> Full scan evidence"
ls -lh out/records.json out/coverage.json out/results.sarif

echo ">> First normalized findings"
python - <<'PY'
import json
from pathlib import Path

records = json.loads(Path('out/records.json').read_text(encoding='utf-8'))
print(f'normalized detections: {len(records)}')
for record in records[:5]:
    print(f"- {record.get('severity')} | {record.get('rule_id')} | {record.get('title')} | {record.get('endpoint')}")
PY

echo "To publish as GitHub Issues (no Advanced Security needed; drop --dry-run to write):"
echo "  python -m detections.github_issues out/labeled.json --app-id juice-shop \\"
echo "    --owner <owner> --repo <repo> --dry-run"
echo "Or, to a repository with code scanning (needs GitHub Advanced Security):"
echo "  python -m detections.github_upload out/results.sarif --owner <owner> --repo <repo> \\"
echo "    --ref refs/heads/<branch> --commit <full SHA that exists in that repo>"
echo "Browser URLs:"
echo "  Juice Shop app: http://localhost:3000/"
echo "  ZAP API: admits only the runner; restart with ZAP_API_ALLOW='.*' to call it from the host"
exit "$gate"

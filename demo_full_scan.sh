#!/usr/bin/env bash
# Run the Phase 1 full scanner gate without foreground podman-compose up.
# This avoids the Windows Python asyncio signal-handler failure in podman-compose foreground mode.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

for required_file in compose.yaml compose.demo.yaml Containerfile security/dast/juice-shop/flow.py security/dast/juice-shop/scope.json; do
  if [ ! -f "$required_file" ]; then
    echo "Missing required file: $required_file" >&2
    echo "This script must live at the DAST POC repo root." >&2
    exit 1
  fi
done

repo_root_win="$(pwd -W 2>/dev/null || cygpath -w "$PWD" 2>/dev/null || pwd)"
network="ssd-dast-poc_dast"
runner_image="localhost/ssd-dast-poc_runner:latest"
compose_files=(-f compose.yaml -f compose.demo.yaml)

echo ">> Reset full-scan demo containers"
podman-compose "${compose_files[@]}" down -v >/dev/null 2>&1 || true
podman pod rm -f pod_ssd-dast-poc >/dev/null 2>&1 || true
podman rm -f ssd-dast-poc_juice_1 ssd-dast-poc_zap_1 ssd-dast-poc_runner_1 >/dev/null 2>&1 || true
podman network rm "$network" dast >/dev/null 2>&1 || true

echo ">> Build runner image"
podman-compose "${compose_files[@]}" build runner

rm -f out/records.json
mkdir -p out

echo ">> Start Juice Shop target and ZAP scanner in detached mode"
podman-compose "${compose_files[@]}" up -d juice zap

run_runner_python() {
  MSYS_NO_PATHCONV=1 podman run --rm \
    --network "$network" \
    --env RUNNER_CHROMIUM_NO_SANDBOX=1 \
    --volume "${repo_root_win}/out:/app/out" \
    --entrypoint python \
    "$runner_image" "$@"
}

echo ">> Wait for Juice Shop and ZAP readiness"
run_runner_python \
  -c "from runner.main import wait_ready; wait_ready('http://zap:8080', 'http://juice:3000'); print('services ready: zap=http://zap:8080 target=http://juice:3000')"

echo ">> Run full Phase 1 gate: replay + ZAP spider + ZAP active scan + normalize"
MSYS_NO_PATHCONV=1 podman run --rm \
  --network "$network" \
  --env RUNNER_CHROMIUM_NO_SANDBOX=1 \
  --volume "${repo_root_win}/out:/app/out" \
  "$runner_image" \
  --scope=security/dast/juice-shop/scope.json \
  --flow=security/dast/juice-shop/flow.py \
  --base-url=http://juice:3000 \
  --zap-api=http://zap:8080 \
  --zap-proxy=http://zap:8080 \
  --records-out=/app/out/records.json

echo ">> Full scan evidence"
ls -lh out/records.json

echo ">> First normalized findings"
python - <<'PY'
import json
from pathlib import Path

records = json.loads(Path('out/records.json').read_text(encoding='utf-8'))
print(f'normalized detections: {len(records)}')
for record in records[:5]:
    print(f"- {record.get('severity')} | {record.get('rule_id')} | {record.get('title')} | {record.get('endpoint')}")
PY

echo "Browser URLs:"
echo "  Juice Shop app: http://localhost:3000/"
echo "  ZAP API UI:     http://localhost:8080/UI/"
echo "  ZAP alerts API: http://localhost:8080/JSON/core/view/alerts/?baseurl=http://juice:3000&start=0&count=5"
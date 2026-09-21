#!/usr/bin/env bash
# Replay the Phase 1 flow through Playwright and ZAP without running the active scan.
# Safe to call from any current directory; it always runs from this repo root.
# Uses plain Podman, not podman-compose, to avoid Git Bash compose/path issues.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

repo_root_win="$(pwd -W 2>/dev/null || cygpath -w "$PWD" 2>/dev/null || pwd)"
runner_image="localhost/ssd-dast-poc_runner:latest"
runner_network="ssd-dast-poc_dast"
juice_image="bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e"
zap_image="zaproxy/zap-stable@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"

run_runner_python() {
  MSYS_NO_PATHCONV=1 podman run --rm \
    --network "$runner_network" \
    --env RUNNER_CHROMIUM_NO_SANDBOX=1 \
    --volume "${repo_root_win}/out:/app/out" \
    --entrypoint python \
    "$runner_image" "$@"
}

for required_file in Containerfile security/dast/juice-shop/flow.py security/dast/juice-shop/scope.json; do
  if [ ! -f "$required_file" ]; then
    echo "Missing required file: $required_file" >&2
    echo "This script must live at the Dast-Scanning-Tool repo root." >&2
    exit 1
  fi
done

echo ">> Reset replay demo containers"
podman pod rm -f pod_ssd-dast-poc >/dev/null 2>&1 || true
podman rm -f ssd-dast-poc_juice_1 ssd-dast-poc_zap_1 >/dev/null 2>&1 || true
podman network rm "$runner_network" >/dev/null 2>&1 || true

echo ">> Build runner image"
podman build -t "$runner_image" -f Containerfile .

rm -rf out/replay-evidence
mkdir -p out/replay-evidence

echo ">> Create demo network"
podman network create "$runner_network" >/dev/null

echo ">> Start Juice Shop target and ZAP scanner"
podman run -d \
  --name ssd-dast-poc_juice_1 \
  --network "$runner_network" \
  --network-alias juice \
  --publish 127.0.0.1:3000:3000 \
  "$juice_image" >/dev/null

podman run -d \
  --name ssd-dast-poc_zap_1 \
  --network "$runner_network" \
  --network-alias zap \
  --publish 127.0.0.1:8080:8080 \
  "$zap_image" \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true >/dev/null

echo ">> Wait for Juice Shop and ZAP readiness"
run_runner_python \
  -c "from runner.main import wait_ready; wait_ready('http://zap:8080', 'http://juice:3000'); print('services ready: zap=http://zap:8080 target=http://juice:3000')"

echo ">> Replay flow.py through Playwright and the ZAP proxy"
run_runner_python \
  -m runner.replay \
  --scope security/dast/juice-shop/scope.json \
  --flow security/dast/juice-shop/flow.py \
  --base-url http://juice:3000 \
  --zap-proxy http://zap:8080 \
  --evidence-dir /app/out/replay-evidence

echo "Replay evidence written to: out/replay-evidence/"
ls -lh out/replay-evidence/active-scan.har \
  out/replay-evidence/01-login-page.png \
  out/replay-evidence/02-after-login.png \
  out/replay-evidence/03-basket-page.png

echo "Browser URLs:"
echo "  Juice Shop app: http://localhost:3000/"
echo "  ZAP API UI:     http://localhost:8080/UI/"
echo "  ZAP version:    http://localhost:8080/JSON/core/view/version/"
#!/usr/bin/env bash
# Replay the Juice Shop flow through Playwright and ZAP without running the active scan.
# Safe to call from any current directory; it always runs from this repo root.
# Uses plain Podman, not podman-compose, to avoid Git Bash compose/path issues.
#
# ZAP requires an API key (ZAP_API_KEY, generated when unset) and by default admits only the
# runner's fixed address. Set ZAP_API_ALLOW='.*' to open the API to the host as well; the key
# is still required. JUICE_IMAGE / ZAP_IMAGE override the pinned images, e.g. an NTR mirror.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -z "${ZAP_API_KEY:-}" ]; then
  ZAP_API_KEY="$(openssl rand -hex 24 2>/dev/null || python -c 'import secrets; print(secrets.token_hex(24))')"
  echo ">> Generated a ZAP_API_KEY for this run (not printed); export your own beforehand to call ZAP from another terminal" >&2
fi
export ZAP_API_KEY

repo_root_win="$(pwd -W 2>/dev/null || cygpath -w "$PWD" 2>/dev/null || pwd)"
runner_image="localhost/ssd-dast-poc_runner:latest"
runner_network="ssd-dast-poc_dast"
runner_subnet="${DAST_SUBNET:-172.28.0.0/24}"
runner_ip="${DAST_RUNNER_IP:-172.28.0.10}"
zap_api_allow="${ZAP_API_ALLOW:-^(?:172[.]28[.]0[.]10|zap|127[.]0[.]0[.]1|localhost)\$}"
juice_image="${JUICE_IMAGE:-bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e}"
zap_image="${ZAP_IMAGE:-zaproxy/zap-stable@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef}"

run_runner_python() {
  MSYS_NO_PATHCONV=1 podman run --rm \
    --network "$runner_network" \
    --ip "$runner_ip" \
    --env RUNNER_CHROMIUM_NO_SANDBOX=1 \
    --env ZAP_API_KEY \
    --volume "${repo_root_win}/out:/app/out" \
    --entrypoint python \
    "$runner_image" "$@"
}

for required_file in Containerfile security/dast/juice-shop/flow.py security/dast/juice-shop/scope.json; do
  if [ ! -f "$required_file" ]; then
    echo "Missing required file: $required_file" >&2
    echo "This script must live at the DAST POC repo root." >&2
    exit 1
  fi
done

echo ">> Reset replay demo containers"
podman pod rm -f pod_ssd-dast-poc >/dev/null 2>&1 || true
podman rm -f ssd-dast-poc_juice_1 ssd-dast-poc_zap_1 >/dev/null 2>&1 || true
podman network rm "$runner_network" >/dev/null 2>&1 || true

echo ">> Build runner image"
bash scripts/stage_ca_bundle.sh
podman build -t "$runner_image" -f Containerfile .

rm -rf out/replay-evidence
mkdir -p out/replay-evidence

echo ">> Create demo network"
podman network create --subnet "$runner_subnet" "$runner_network" >/dev/null

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
  -config "api.key=${ZAP_API_KEY}" \
  -config "api.addrs.addr.name=${zap_api_allow}" \
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
ls -lh out/replay-evidence/

echo "Browser URLs:"
echo "  Juice Shop app: http://localhost:3000/"
echo "  ZAP API (needs ZAP_API_ALLOW='.*' and the X-ZAP-API-Key header):"
echo "    curl -s -H \"X-ZAP-API-Key: \$ZAP_API_KEY\" http://localhost:8080/JSON/core/view/version/"

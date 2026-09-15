#!/usr/bin/env bash
# Free ports 3000/8080 before the Phase 1 DAST demo.
# This environment uses Podman, not Docker.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

compose() {
  if podman-compose --help >/dev/null 2>&1; then
    podman-compose "$@"
  elif command -v podman-compose >/dev/null 2>&1; then
    podman-compose "$@"
  elif podman compose version >/dev/null 2>&1; then
    podman compose "$@"
  elif [ -x "${COMPOSE_EXE:-}" ]; then
    "$COMPOSE_EXE" "$@"
  elif [ -x "/c/Users/yangq4/AppData/Roaming/Python/Python312/Scripts/podman-compose.exe" ]; then
    /c/Users/yangq4/AppData/Roaming/Python/Python312/Scripts/podman-compose.exe "$@"
  elif python -m podman_compose --help >/dev/null 2>&1; then
    python -m podman_compose "$@"
  elif py -m podman_compose --help >/dev/null 2>&1; then
    py -m podman_compose "$@"
  else
    return 127
  fi
}

echo ">> Tear down compose-managed demo resources"
if ! compose down -v; then
  echo "Skipping compose teardown: podman-compose and podman compose are not available in this shell."
fi

echo ">> Remove manually-started demo containers, if present"
podman rm -f juice zap runner 2>/dev/null || true

echo ">> Remove common leftover compose containers, if present"
podman rm -f ssd-dast-poc_juice_1 ssd-dast-poc_zap_1 ssd-dast-poc_runner_1 2>/dev/null || true

echo ">> Remove common leftover demo networks, if present"
podman network rm dast ssd-dast-poc_dast 2>/dev/null || true

echo ">> Confirm no Podman containers still reference Juice/ZAP or ports 3000/8080"
leftovers="$(podman ps -a --format '{{.Names}} {{.Ports}}' | grep -Ei '3000|8080|juice|zap' || true)"

if [ -n "$leftovers" ]; then
  echo "$leftovers"
  echo "Cleanup incomplete: a Podman container still references 3000/8080, juice, or zap." >&2
  exit 1
fi

echo "OK: no stray Podman containers on 3000/8080."

echo ">> Optional host-level listener check"
if command -v ss >/dev/null 2>&1; then
  ss -ltnp | grep -E ':3000|:8080' || echo "OK: no host listeners on 3000/8080."
elif command -v lsof >/dev/null 2>&1; then
  lsof -iTCP:3000 -iTCP:8080 -sTCP:LISTEN || echo "OK: no host listeners on 3000/8080."
else
  echo "Skipping host-level port check: ss/lsof not available."
fi
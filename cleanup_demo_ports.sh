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

remove_containers() {
  local err
  if ! err="$(podman rm -f --ignore "$@" 2>&1 >/dev/null)"; then
    echo "WARN: could not remove containers $*: $err" >&2
  fi
}

remove_networks() {
  local net err
  for net in "$@"; do
    podman network exists "$net" 2>/dev/null || continue
    if ! err="$(podman network rm "$net" 2>&1 >/dev/null)"; then
      echo "WARN: could not remove network $net: $err" >&2
    fi
  done
}

echo ">> Remove manually-started demo containers, if present"
remove_containers juice zap runner

echo ">> Remove common leftover compose containers, if present"
remove_containers ssd-dast-poc_juice_1 ssd-dast-poc_zap_1 ssd-dast-poc_runner_1

echo ">> Remove common leftover demo networks, if present"
remove_networks dast ssd-dast-poc_dast

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
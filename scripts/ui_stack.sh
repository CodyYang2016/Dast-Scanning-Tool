#!/usr/bin/env bash
# Start what the web UI needs with Podman or Docker, then (optionally) the UI itself.
#
# It uses the same compose project as demo_*.sh and the same overlay, compose.demo.yaml, that the
# Nationwide checklist's replay step uses: ZAP on 127.0.0.1:8080, keyed, with ZAP_API_ALLOW='.*'
# so the host-run browser and the UI may call it. See docs/podman_and_docker.md.
#
#   bash scripts/ui_stack.sh up [juice] [dvwa]   start ZAP (and targets); wait until it answers
#   bash scripts/ui_stack.sh ui [juice] [dvwa]   the same, then run `python -m dast ui`
#   bash scripts/ui_stack.sh status              engine, compose command, what's running
#   bash scripts/ui_stack.sh down                stop and remove this project's containers
#   add --dry-run first to print what would run and change nothing
#
# DAST_CONTAINER_ENGINE=podman|docker picks the engine. Otherwise Docker if `docker info` works,
# else Podman. Podman uses podman-compose (as the checklist does), else `podman compose`.
# DAST_ZAP_PORT / DAST_JUICE_PORT move the host ports (defaults 8080 / 3000). ZAP_IMAGE,
# JUICE_IMAGE and DVWA_IMAGE point at a mirror, e.g. ZAP_IMAGE=ntr.nwie.net/docker.io/zaproxy/zap-stable
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Image names from versions.lock; with DAST_IMAGE_MIRROR=ntr.nwie.net, every one from NTR only.
source scripts/images.sh

dry=0
if [ "${1:-}" = "--dry-run" ]; then dry=1; shift; fi
cmd="${1:-}"
[ $# -gt 0 ] && shift
targets=()
for t in "$@"; do
  case "$t" in
    juice|dvwa) targets+=("$t") ;;
    *) echo "Unknown target: $t (use juice and/or dvwa)" >&2; exit 2 ;;
  esac
done
case "$cmd" in
  up|ui|status|down) ;;
  *) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac

# Overridable so the tests can stand in for each tool.
DOCKER_BIN="${DOCKER_BIN:-docker}"
PODMAN_BIN="${PODMAN_BIN:-podman}"
PODMAN_COMPOSE_BIN="${PODMAN_COMPOSE_BIN:-podman-compose}"
have() { command -v "$1" >/dev/null 2>&1; }

engine="${DAST_CONTAINER_ENGINE:-}"
if [ -z "$engine" ]; then
  if have "$DOCKER_BIN" && "$DOCKER_BIN" info >/dev/null 2>&1; then engine=docker
  elif have "$PODMAN_BIN"; then engine=podman
  elif have "$DOCKER_BIN"; then engine=docker
  else
    echo "Neither Podman nor Docker was found on PATH. Install one, or set DAST_CONTAINER_ENGINE." >&2
    exit 1
  fi
fi
case "$engine" in
  docker) compose=("$DOCKER_BIN" compose) ;;
  podman)
    if have "$PODMAN_COMPOSE_BIN"; then compose=("$PODMAN_COMPOSE_BIN"); else compose=("$PODMAN_BIN" compose); fi ;;
  *) echo "DAST_CONTAINER_ENGINE must be podman or docker, not '$engine'." >&2; exit 2 ;;
esac

export DAST_ZAP_PORT="${DAST_ZAP_PORT:-8080}" DAST_JUICE_PORT="${DAST_JUICE_PORT:-3000}"
export ZAP_API_ALLOW='.*'                      # the host-run browser and the UI call ZAP; still keyed
export DAST_ZAP_API="http://127.0.0.1:${DAST_ZAP_PORT}"
files=(-f compose.yaml -f compose.demo.yaml)
profiles=()
for t in ${targets[@]+"${targets[@]}"}; do [ "$t" = dvwa ] && profiles=(--profile dvwa); done
services=(zap ${targets[@]+"${targets[@]}"})
key_file=".secrets/zap-ui.key"
shown="$(basename "${compose[0]}")${compose[1]:+ ${compose[1]}}"

echo "engine: $engine"
echo "compose: $shown"

run() {                                       # print, and run unless --dry-run
  echo "+ $shown ${*}"
  if [ "$dry" -eq 0 ]; then "${compose[@]}" "$@"; fi
}

zap_answers() {
  curl -s --max-time 5 -H "X-ZAP-API-Key: $ZAP_API_KEY" "$DAST_ZAP_API/JSON/core/view/version/" 2>/dev/null \
    | grep -q '"version"'
}

# compose checks the whole file, including ZAP's required key, even to stop or list containers.
if [ "$cmd" = down ] || [ "$cmd" = status ]; then
  if [ -z "${ZAP_API_KEY:-}" ]; then
    if [ -f "$key_file" ]; then ZAP_API_KEY="$(cat "$key_file")"; else ZAP_API_KEY="not-needed-to-stop"; fi
  fi
  export ZAP_API_KEY
fi
if [ "$cmd" = down ]; then run "${files[@]}" --profile dvwa down; exit 0; fi
if [ "$cmd" = status ]; then
  run "${files[@]}" ps
  if [ "$dry" -eq 0 ] && [ -f "$key_file" ]; then
    ZAP_API_KEY="$(cat "$key_file")"
    zap_answers && echo "ZAP answers at $DAST_ZAP_API" || echo "ZAP isn't answering at $DAST_ZAP_API"
  fi
  exit 0
fi

# A Podman machine (Windows, macOS) must be running before anything can start.
if [ "$engine" = podman ] && [ "$dry" -eq 0 ]; then
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*|Darwin)
      if ! "$PODMAN_BIN" machine list --format '{{.Running}}' 2>/dev/null | grep -q true; then
        echo "The Podman machine isn't running. Start it with \`podman machine start\`, or run" >&2
        echo "\`bash ./prepull_playwright_podman_nationwide.sh\` on a Nationwide laptop (it also repairs the proxy)." >&2
        exit 1
      fi ;;
  esac
fi

# One ZAP key per machine, kept owner-only and never printed. An exported ZAP_API_KEY wins.
key_from_env=0
if [ -n "${ZAP_API_KEY:-}" ]; then
  key_from_env=1; echo "ZAP key: from ZAP_API_KEY"
elif [ -f "$key_file" ]; then
  ZAP_API_KEY="$(cat "$key_file")"; echo "ZAP key: from $key_file"
elif [ "$dry" -eq 1 ]; then
  ZAP_API_KEY="dry-run"; echo "ZAP key: would be created in $key_file"
else
  mkdir -p .secrets
  ZAP_API_KEY="$(openssl rand -hex 24 2>/dev/null || python -c 'import secrets; print(secrets.token_hex(24))')"
  (umask 077 && printf '%s\n' "$ZAP_API_KEY" > "$key_file")
  echo "ZAP key: created in $key_file (not printed)"
fi
export ZAP_API_KEY
echo "DAST_ZAP_API=$DAST_ZAP_API"

if [ "$dry" -eq 0 ] && zap_answers; then
  echo "ZAP already answers at $DAST_ZAP_API with this key."
  run "${files[@]}" ${profiles[@]+"${profiles[@]}"} up -d "${services[@]}"
else
  # Recreate, so a ZAP started earlier with another key (e.g. by demo_*.sh) picks up this one.
  run "${files[@]}" ${profiles[@]+"${profiles[@]}"} up -d --force-recreate "${services[@]}"
fi

if [ "$dry" -eq 0 ]; then
  echo "Waiting for ZAP at $DAST_ZAP_API (it can take a minute)…"
  for _ in $(seq 1 60); do zap_answers && break; sleep 3; done
  if ! zap_answers; then
    echo "ZAP didn't answer at $DAST_ZAP_API. Check \`$shown ${files[*]} logs zap\`." >&2
    exit 1
  fi
  echo "ZAP is ready."
fi

if [ "$cmd" = ui ]; then
  # The project's Python: the active venv, else the repo's .venv (bin/ on macOS and Linux,
  # Scripts/ in Git Bash on Windows), else whatever python is on PATH.
  if [ -n "${VIRTUAL_ENV:-}" ] && have python; then py=python
  elif [ -x .venv/bin/python ]; then py=.venv/bin/python
  elif [ -x .venv/Scripts/python.exe ]; then py=.venv/Scripts/python.exe
  elif have python; then py=python
  else py=python3; fi
  echo "+ $py -m dast ui"
  if [ "$dry" -eq 0 ]; then exec "$py" -m dast ui; fi
else
  echo
  echo "Next, in this terminal:"
  if [ "$key_from_env" -eq 1 ]; then
    echo "  export DAST_ZAP_API=$DAST_ZAP_API"
  else
    echo "  export ZAP_API_KEY=\"\$(cat $key_file)\" DAST_ZAP_API=$DAST_ZAP_API"
  fi
  echo "  python -m dast ui"
  echo "Or run \`bash scripts/ui_stack.sh ui\` to do both."
fi

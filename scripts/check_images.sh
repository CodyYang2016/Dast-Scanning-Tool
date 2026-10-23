#!/usr/bin/env bash
# List every container image the tool can use, and (with --pull) check each one can be pulled.
#
#   bash scripts/check_images.sh --dry-run   list the images, their names and who needs them
#   bash scripts/check_images.sh --pull      also pull each one, with Podman (or Docker)
#
# Inside Nationwide, export DAST_IMAGE_MIRROR=ntr.nwie.net first (the checklist's terminal setup
# does): the names are then the NTR copies, and anything NTR lacks is listed with the exact name
# to ask the NTR team for. Nothing is ever pulled from outside the mirror when it is set.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mode="${1:---dry-run}"
case "$mode" in --dry-run|--pull) ;; *) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;; esac

# shellcheck source=scripts/images.sh
source scripts/images.sh

needs() {
  case "$1" in
    ZAP_IMAGE) echo "web UI, replay, full scan" ;;
    JUICE_IMAGE) echo "web UI demo target, replay, full scan" ;;
    RUNNER_BASE_IMAGE) echo "replay and full scan (runner image), semgate lab" ;;
    DVWA_IMAGE) echo "optional target" ;;
    WEBGOAT_IMAGE) echo "optional target" ;;
  esac
}

if [ -n "${DAST_IMAGE_MIRROR:-}" ]; then
  echo "Images from ${DAST_IMAGE_MIRROR%/} only (DAST_IMAGE_MIRROR)."
else
  echo "DAST_IMAGE_MIRROR isn't set: these are the upstream images. Inside Nationwide, run"
  echo "  export DAST_IMAGE_MIRROR=ntr.nwie.net"
  echo "first, so every image comes from NTR."
fi
echo

engine=""
if [ "$mode" = --pull ]; then
  engine="${DAST_CONTAINER_ENGINE:-}"
  if [ -z "$engine" ]; then
    if command -v podman >/dev/null 2>&1; then engine=podman
    elif command -v docker >/dev/null 2>&1; then engine=docker
    else echo "Neither Podman nor Docker is on PATH." >&2; exit 1; fi
  fi
  echo "Pulling with $engine."
  echo
fi

missing=0
for var in "${DAST_IMAGE_VARS[@]}"; do
  image="$(dast_image "$var")"
  printf '%-18s %s\n' "$var" "$image"
  printf '%-18s needed by: %s\n' "" "$(needs "$var")"
  if [ "$mode" = --pull ]; then
    if out="$("$engine" pull "$image" 2>&1)"; then
      printf '%-18s available\n' ""
    else
      missing=1
      if printf '%s' "$out" | grep -qiE 'unauthori[sz]ed|authentication required|denied'; then
        printf '%-18s UNAUTHORIZED: log in first: %s login %s\n' "" "$engine" "${image%%/*}"
      elif printf '%s' "$out" | grep -qiE 'manifest unknown|not found|does not exist|no such|404'; then
        repo="${image%@*}"; repo="${repo%:*}"
        if [ "$repo" != "${image%@*}" ] || [ "$image" != "${image%@*}" ]; then
          if "$engine" pull "$repo:latest" >/dev/null 2>&1; then
            printf '%-18s NOT FOUND at this pin, though the image exists: ask the NTR team for\n' ""
            printf '%-18s   %s\n' "" "$image"
          else
            printf '%-18s NOT FOUND: ask the NTR team to mirror\n' ""
            printf '%-18s   %s\n' "" "$image"
          fi
        else
          printf '%-18s NOT FOUND: ask the NTR team to mirror %s\n' "" "$image"
        fi
      else
        printf '%-18s FAILED: %s\n' "" "$(printf '%s' "$out" | tail -1)"
      fi
    fi
  fi
  echo
done

if [ "$mode" = --pull ]; then
  if [ "$missing" -eq 0 ]; then echo "All images are available."
  else echo "Some images aren't available yet; the paths that need them won't start until they are."; fi
fi

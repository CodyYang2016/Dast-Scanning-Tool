#!/usr/bin/env bash
# Pre-pull the Playwright image through Podman on a Nationwide Windows/WSL workstation.
# Run from Git Bash. This script repairs the known stale 127.0.0.1:8888 proxy,
# retries the pull, and verifies that the image is cached locally.

set -Eeuo pipefail

MACHINE_NAME="${PODMAN_MACHINE_NAME:-podman-machine-default}"
IMAGE="${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright/python:v1.62.0-jammy}"
ZAP_IMAGE="${ZAP_IMAGE:-ntr.nwie.net/docker.io/zaproxy/zap-stable}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"
RETRY_DELAY_SECONDS="${RETRY_DELAY_SECONDS:-10}"
NO_PROXY_VALUE="nwie.net,localhost,127.0.0.1,.nwie.net,.apps.nwie.net,.docker.internal,kubernetes.docker.internal"

# Prevent stale host-shell proxy variables from being inherited by Podman
# startup. This changes only this script process, not Windows system settings.
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy SOCKS_PROXY socks_proxy || true
export NO_PROXY="${NO_PROXY_VALUE}" no_proxy="${NO_PROXY_VALUE}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

echo "==> Checking Podman"
command -v podman >/dev/null 2>&1 || fail "podman is not installed or is not on PATH"

wait_for_machine_ssh() {
  local max_wait="${1:-30}"
  local attempt
  for attempt in $(seq 1 "${max_wait}"); do
    if podman machine ssh true >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# Start the default machine if SSH cannot reach it. If startup fails with a
# stale WSL/SSH-port state, reset WSL once and retry. This stops all WSL distros.
if ! podman machine ssh true >/dev/null 2>&1; then
  echo "==> Starting Podman machine: ${MACHINE_NAME}"
  if ! podman machine start "${MACHINE_NAME}"; then
    echo "WARN: Podman machine startup failed; resetting WSL and retrying" >&2
    echo "      This stops all WSL distributions." >&2
    wsl.exe --shutdown || true
    sleep 3
    podman machine start "${MACHINE_NAME}" || fail "Podman machine could not start after WSL reset"
  fi
fi
wait_for_machine_ssh 30 || fail "Podman machine is not reachable after startup/recovery"

echo "==> Removing stale 127.0.0.1:8888 proxy sources"
podman machine ssh "set -e; mkdir -p /root/podman-proxy-backups; if test -f /etc/systemd/system.conf.d/default-env.conf; then cp /etc/systemd/system.conf.d/default-env.conf /root/podman-proxy-backups/default-env.conf.bak; sed -i '/127.0.0.1:8888/d' /etc/systemd/system.conf.d/default-env.conf; fi; if test -f /etc/profile.d/default-env.sh; then cp /etc/profile.d/default-env.sh /root/podman-proxy-backups/default-env.sh.bak; sed -i '/127.0.0.1:8888/d' /etc/profile.d/default-env.sh; fi; rm -f /etc/systemd/system.conf.d/default-env.conf.bak; echo 'Remaining 8888 entries:'; grep -Rni '127.0.0.1:8888' /etc/systemd/system.conf.d /etc/profile.d 2>/dev/null || true"

# DefaultEnvironment is loaded when systemd starts. Restart the VM so the
# edited system.conf.d file takes effect; unset-environment alone is not enough.
echo "==> Restarting Podman VM to load the proxy configuration"
podman machine stop "${MACHINE_NAME}" >/dev/null 2>&1 || true
wsl.exe --shutdown || true
sleep 3
if ! podman machine start "${MACHINE_NAME}"; then
  echo "WARN: Podman restart failed; resetting WSL and retrying" >&2
  wsl.exe --shutdown || true
  sleep 3
  podman machine start "${MACHINE_NAME}" || fail "Podman machine could not restart after proxy configuration"
fi
wait_for_machine_ssh 30 || fail "Podman machine is not reachable after proxy configuration restart"

echo "==> Applying Podman VM proxy settings"
podman machine ssh "systemctl unset-environment HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy SOCKS_PROXY socks_proxy && systemctl set-environment NO_PROXY=${NO_PROXY_VALUE} no_proxy=${NO_PROXY_VALUE} && systemctl restart podman.socket"

print_proxy_diagnostics() {
  echo "==> Proxy diagnostics: host environment"
  env | grep -Ei 'proxy=' || true
  echo "==> Proxy diagnostics: Podman machine status"
  podman machine list || true
  echo "==> Proxy diagnostics: files, systemd sources, and service environments inside VM"
  podman machine ssh "echo '--- /etc/systemd/system.conf.d/default-env.conf ---'; if test -f /etc/systemd/system.conf.d/default-env.conf; then nl -ba /etc/systemd/system.conf.d/default-env.conf; else echo MISSING; fi; echo '--- matching configuration sources ---'; grep -RniE '127\.0\.0\.1:8888|DefaultEnvironment|HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy' /etc/systemd /usr/lib/systemd/system /etc/profile.d /etc/environment 2>/dev/null || true; echo '--- systemd manager environment ---'; systemctl show-environment | grep -Ei 'proxy=' || true; echo '--- podman unit properties ---'; systemctl show podman.service podman.socket -p Environment -p EnvironmentFiles -p FragmentPath -p DropInPaths 2>/dev/null || true; echo '--- PID 1 environment ---'; tr '\0' '\n' </proc/1/environ | grep -Ei 'proxy=' || true"
}

proxy_state="$(podman machine ssh "systemctl show-environment | grep -Ei 'proxy=' || true")"
if printf '%s\n' "${proxy_state}" | grep -Eiq '127\.0\.0\.1:8888|^(HTTP|HTTPS|http|https|SOCKS|socks)_PROXY='; then
  printf '%s\n' "${proxy_state}" >&2
  print_proxy_diagnostics
  fail "stale 127.0.0.1:8888 proxy remains in the Podman VM"
fi

echo "==> Podman proxy check passed"

pull_and_verify() {
  local image="$1"
  local label="$2"
  local attempt
  local image_id

  echo "==> Pulling ${label}: ${image}"
  for attempt in $(seq 1 "${MAX_ATTEMPTS}"); do
    echo "    Attempt ${attempt}/${MAX_ATTEMPTS}"
    if podman pull "${image}"; then
      podman image exists "${image}" || fail "pull reported success but ${image} is not cached"
      image_id="$(podman image inspect "${image}" --format '{{.Id}}')"
      echo "SUCCESS: ${label} image is cached in Podman"
      echo "IMAGE: ${image}"
      echo "IMAGE_ID: ${image_id}"
      return 0
    fi

    if [ "${attempt}" -lt "${MAX_ATTEMPTS}" ]; then
      echo "    Pull failed; retrying in ${RETRY_DELAY_SECONDS}s..." >&2
      sleep "${RETRY_DELAY_SECONDS}"
    fi
  done

  if [ "${image}" = "${ZAP_IMAGE}" ]; then
    echo "NTR may require authentication. Run: podman login ntr.nwie.net -u <your-Nationwide-user>" >&2
  fi
  fail "unable to pull ${label} image after ${MAX_ATTEMPTS} attempts: ${image}"
}

pull_and_verify "${IMAGE}" "Playwright"
pull_and_verify "${ZAP_IMAGE}" "ZAP mirror"

echo "SUCCESS: all required demo images are cached in Podman"

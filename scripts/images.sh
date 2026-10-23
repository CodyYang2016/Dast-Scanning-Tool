# Which container image each part of the tool uses. Sourced, not run:
#   source scripts/images.sh
#
# The pinned images are listed once, in versions.lock. Inside Nationwide every image must come
# from NTR, the internal mirror: export DAST_IMAGE_MIRROR=ntr.nwie.net and each image becomes
# ntr.nwie.net/<registry>/<path> with the same digest or tag, e.g.
#   ntr.nwie.net/docker.io/zaproxy/zap-stable@sha256:781a…
#   ntr.nwie.net/mcr.microsoft.com/playwright/python:v1.62.0-jammy
# With the mirror set, nothing may come from anywhere else: an image set by hand outside the
# mirror stops the script that sourced this, naming it. Without the mirror nothing is exported,
# so compose.yaml's own defaults (the same images) apply exactly as before.
#
# An image set explicitly (ZAP_IMAGE=…) always wins, so existing terminal setups keep working.
# See docs/podman_and_docker.md, "NTR only".

_dast_images_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The variable each image is set through, and its key in versions.lock.
DAST_IMAGE_VARS=(ZAP_IMAGE JUICE_IMAGE DVWA_IMAGE WEBGOAT_IMAGE RUNNER_BASE_IMAGE)
dast_image_lock_key() {
  case "$1" in
    ZAP_IMAGE) echo zap_image ;;
    JUICE_IMAGE) echo juice_shop_image ;;
    DVWA_IMAGE) echo dvwa_image ;;
    WEBGOAT_IMAGE) echo webgoat_image ;;
    RUNNER_BASE_IMAGE) echo runner_base_image ;;
  esac
}

# The pinned upstream image for a versions.lock key, with its registry (docker.io/ if none).
dast_upstream_image() {
  local ref first
  ref="$(sed -n "s/^$1:[[:space:]]*//p" "$_dast_images_root/versions.lock" | tr -d '\r')"
  first="${ref%%/*}"
  case "$first" in
    *.*|*:*|localhost) echo "$ref" ;;
    *) echo "docker.io/$ref" ;;
  esac
}

# The image a variable resolves to: its own value, else the mirror's copy, else the upstream image.
dast_image() {
  local var="$1" upstream
  upstream="$(dast_upstream_image "$(dast_image_lock_key "$var")")"
  if [ -n "${!var:-}" ]; then echo "${!var}"
  elif [ -n "${DAST_IMAGE_MIRROR:-}" ]; then echo "${DAST_IMAGE_MIRROR%/}/$upstream"
  else echo "$upstream"; fi
}

if [ -n "${DAST_IMAGE_MIRROR:-}" ]; then
  _dast_images_bad=0
  for _v in "${DAST_IMAGE_VARS[@]}"; do
    _img="$(dast_image "$_v")"
    case "$_img" in
      "${DAST_IMAGE_MIRROR%/}/"*) export "$_v=$_img" ;;
      *)
        echo "$_v=$_img isn't from ${DAST_IMAGE_MIRROR%/}, and DAST_IMAGE_MIRROR allows nothing else." >&2
        echo "  Use ${DAST_IMAGE_MIRROR%/}/$(dast_upstream_image "$(dast_image_lock_key "$_v")"), or unset $_v." >&2
        _dast_images_bad=1 ;;
    esac
  done
  unset _v _img
  if [ "$_dast_images_bad" -ne 0 ]; then unset _dast_images_bad; return 1 2>/dev/null || exit 1; fi
  unset _dast_images_bad
fi

#!/usr/bin/env bash
# Copy the corporate CA bundle (DAST_CA_BUNDLE, default ~/certs/nw-ca-all.pem) into certs/ so the
# runner image build trusts the TLS-intercepting proxy.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

ca="${DAST_CA_BUNDLE:-$HOME/certs/nw-ca-all.pem}"
path="$(cygpath -u "$ca" 2>/dev/null || printf '%s' "$ca")"

if [ ! -f "$path" ]; then
  echo "CA bundle not found: $ca (set DAST_CA_BUNDLE to the Nationwide CA PEM file)" >&2
  exit 1
fi
if ! grep -q 'BEGIN CERTIFICATE' "$path"; then
  echo "CA bundle $ca must be PEM text containing certificates" >&2
  exit 1
fi
cp "$path" certs/corporate-ca.crt

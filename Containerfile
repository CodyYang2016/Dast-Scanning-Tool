# DAST runner image: Playwright + Chromium (pinned) + the runner code (NFR-5).
# Base image pins Playwright 1.62.0 and ships a matching Chromium, so scans are reproducible.
# Inside Nationwide the same tag is pulled through Podman; see prepull_playwright_podman_nationwide.sh.
FROM mcr.microsoft.com/playwright/python:v1.62.0-jammy

WORKDIR /app

# Runtime deps. Playwright is pinned to the base image's version (1.62.0), so its bundled
# Chromium already matches — no browser re-download needed. pip uses the image's configured
# index; behind TLS interception point it at the approved mirror with PIP_INDEX_URL.
# certs/corporate-ca.crt is the corporate CA, staged by scripts/stage_ca_bundle.sh, that lets pip
# verify a TLS-intercepting proxy.
COPY certs/ /usr/local/share/ca-certificates/
RUN update-ca-certificates
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code + contracts + per-app config. runner/ imports authoring.appconfig,
# authoring.seed and authoring.record at run time, so authoring/ ships too.
COPY pyproject.toml dast.py ./
COPY authoring/ authoring/
COPY detections/ detections/
COPY runner/ runner/
COPY contracts/ contracts/
COPY security/ security/

ENV PYTHONPATH=/app

# Args are supplied by compose (or on `podman run`). Exit code is the scan gate.
ENTRYPOINT ["python", "-m", "runner.main"]

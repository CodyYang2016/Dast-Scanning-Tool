# DAST runner image: Playwright + Chromium (pinned) + the runner code (NFR-5).
# Base image pins Playwright 1.62.0 and ships a matching Chromium, so scans are reproducible.
FROM mcr.microsoft.com/playwright/python:v1.62.0-jammy

WORKDIR /app

# Runtime deps. Playwright is pinned to the base image's version (1.62.0), so its bundled
# Chromium already matches — no browser re-download needed.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code + contracts + per-app configuration and bundles.
COPY pyproject.toml .
COPY dast.py .
COPY authoring/ authoring/
COPY detections/ detections/
COPY runner/ runner/
COPY contracts/ contracts/
COPY security/ security/

ENV PYTHONPATH=/app

# `authoring/` ships in the image so the whole loop is available here, not just the scan half
# (W2-8) — `runner.main --seed` also imports it, which used to fail in-container. Headed
# authoring still needs a display, so in practice the container runs scan and report.
#
# Compose passes runner.main's arguments directly, so that stays the entry point; for the CLI:
#   docker run --entrypoint python <image> -m dast scan <app>
ENTRYPOINT ["python", "-m", "runner.main"]

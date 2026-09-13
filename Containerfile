# DAST runner image: Playwright + Chromium (pinned) + the runner code (NFR-5).
# Base image pins Playwright 1.62.0 and ships a matching Chromium, so scans are reproducible.
FROM mcr.microsoft.com/playwright/python:v1.62.0-jammy

WORKDIR /app

# Runtime deps (jsonschema; playwright is already in the base image).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Ensure the Chromium matching our Playwright version is present (no-op on the base image).
RUN python -m playwright install chromium

# Application code + contracts + the pilot flow/scope.
COPY pyproject.toml .
COPY detections/ detections/
COPY runner/ runner/
COPY contracts/ contracts/
COPY security/ security/

ENV PYTHONPATH=/app

# Args are supplied by compose (or on `docker run`). Exit code is the Phase 1 gate.
ENTRYPOINT ["python", "-m", "runner.main"]

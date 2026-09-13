"""Scan runner: safe, authenticated, scope-bounded ZAP scans feeding the detections pipeline.

See docs/junior_engineer/runner_design.md. The runner is built safety-first: preflight
(this package) refuses unsafe configuration before any traffic is sent (FR-S3, NFR-2).
"""

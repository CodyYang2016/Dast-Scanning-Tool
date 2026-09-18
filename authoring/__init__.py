"""Authoring CLIs (Phase 2): record -> generate -> validate.

Turn a recording of the pilot app into the scan config. The LLM (in generate) emits a
constrained JSON journey plan; deterministic code renders it into flow.py — the LLM never
authors executable code (safety boundary). See docs/junior_engineer/authoring_clis_design.md.
"""

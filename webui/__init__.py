"""The local web UI for the DAST tool (docs/ui-docs/ui_requirements.md).

A front end to the `dast` commands, not a second implementation: it reads and writes the same
app.yaml, suppressions.yaml and scan output the CLI does, and starts the CLI itself for anything
that runs. Start it with `python -m dast ui`.
"""

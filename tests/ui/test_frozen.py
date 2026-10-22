"""The acceptance tests are frozen: the implementation must meet them, not reshape them.

FROZEN.sha256 lists every test file written in Stage 0 (the `[red]` commit). Changing one of them
is a "spec change: …" commit approved by the project owner, which updates this manifest in the
same commit. New tests may be added freely; listed ones may not drift.
"""
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def test_frozen_tests_unchanged():
    manifest = (HERE / "FROZEN.sha256").read_text().splitlines()
    assert manifest, "FROZEN.sha256 is empty"
    drift = []
    for line in manifest:
        digest, rel = line.split(maxsplit=1)
        path = ROOT / rel
        if not path.exists():
            drift.append(f"missing: {rel}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            drift.append(f"changed: {rel}")
    assert not drift, "frozen acceptance tests changed without a spec-change commit: " + ", ".join(drift)

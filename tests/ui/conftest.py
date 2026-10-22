"""Fixtures for the UI acceptance tests; the helpers live in harness.py."""
import subprocess

import pytest

from tests.ui.harness import ROOT, api, api_zap, ws, zap_up  # noqa: F401 — re-exported as fixtures

_GUARDED = ("security", "contracts")


def _snapshot():
    out = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all",
                          "--", *_GUARDED], capture_output=True, text=True, check=True).stdout
    return sorted(line for line in out.splitlines() if "__pycache__" not in line)


@pytest.fixture(scope="session", autouse=True)
def repository_untouched():
    """The UI tests work on throwaway copies. If one ever writes into the repository's own app
    configs or contracts — say, because a feature it relies on isn't built yet — fail loudly."""
    before = _snapshot()
    yield
    after = _snapshot()
    assert after == before, f"UI tests changed the repository: {sorted(set(after) - set(before))}"

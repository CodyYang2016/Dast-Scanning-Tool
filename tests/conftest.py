"""Test-wide isolation from the operator's LLM environment.

Every test here pins decision logic, so the suite must give the same answer on a workstation
configured to run the tool for real as it does in a bare checkout. Without this, an exported
LLM_PROVIDER=copilot plus an installed CLI makes `available()` genuinely true and the tests that
assert the deterministic path fail — a suite that only passes where Copilot is absent cannot be
used to verify the Copilot path. Tests that exercise a provider opt in with monkeypatch.setenv.
"""

import pytest

_LLM_ENV = (
    "LLM_PROVIDER",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_MODEL",
    "COPILOT_CLI",
    "COPILOT_FLAGS",
    "COPILOT_MODEL",
    "COPILOT_GITHUB_TOKEN",
    "COPILOT_TIMEOUT",
)


@pytest.fixture(autouse=True)
def _neutral_llm_env(monkeypatch):
    for name in _LLM_ENV:
        monkeypatch.delenv(name, raising=False)

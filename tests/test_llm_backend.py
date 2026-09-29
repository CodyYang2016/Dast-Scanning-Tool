"""Objective tests for the LLM backend adapter (provider selection + Copilot CLI plumbing).

The live Anthropic and Copilot calls are validated by running them with real credentials. Here we
pin the pure decision/plumbing logic: which provider is selected, when it is "available", how the
Copilot command/prompt are built, and how the Copilot output file (or stdout fallback) is read.
Oracle: hand-built env/proc fixtures with known-correct answers.
"""

import subprocess
import types
from pathlib import Path

import pytest

from authoring import llm_backend


# ---- provider() + default_model() -------------------------------------------------------

def test_provider_defaults_to_anthropic(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    assert llm_backend.provider() == "anthropic"


def test_provider_reads_env_case_insensitive(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "Copilot")
    assert llm_backend.provider() == "copilot"


def test_default_model_is_provider_aware(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    assert llm_backend.default_model() == "claude-opus-4-8"
    monkeypatch.setenv("LLM_PROVIDER", "copilot")
    monkeypatch.delenv("COPILOT_MODEL", raising=False)
    assert llm_backend.default_model() == "gpt-5.5"


# ---- available() ------------------------------------------------------------------------

def test_available_anthropic_needs_key(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert llm_backend.available(None) is False
    assert llm_backend.available("sk-x") is True


def test_available_copilot_needs_cli_on_path(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "copilot")
    monkeypatch.setattr(llm_backend.shutil, "which", lambda _bin: None)
    assert llm_backend.available(None) is False
    monkeypatch.setattr(llm_backend.shutil, "which", lambda _bin: "/usr/bin/copilot")
    assert llm_backend.available(None) is True  # a key is irrelevant to copilot


# ---- copilot command + prompt building --------------------------------------------------

def test_copilot_cmd_carries_model_and_prompt(monkeypatch):
    monkeypatch.delenv("COPILOT_FLAGS", raising=False)
    monkeypatch.delenv("COPILOT_CLI", raising=False)
    monkeypatch.setattr(llm_backend.shutil, "which", lambda _bin: None)
    cmd = llm_backend._copilot_cmd("PROMPT", "gpt-5.5")
    assert cmd[0] == "copilot"
    assert "--model=gpt-5.5" in cmd
    assert cmd[-2:] == ["--prompt", "PROMPT"]
    assert "--disable-builtin-mcps" in cmd  # default flags applied


def test_copilot_flags_override(monkeypatch):
    monkeypatch.setenv("COPILOT_FLAGS", "--foo --bar")
    cmd = llm_backend._copilot_cmd("P", "m")
    assert "--foo" in cmd and "--bar" in cmd and "--disable-builtin-mcps" not in cmd


def test_copilot_cmd_uses_the_resolved_executable(monkeypatch):
    """subprocess does not apply PATHEXT, so the bare name fails on Windows where which() found
    `copilot.cmd`. The command must carry whatever which() resolved."""
    monkeypatch.delenv("COPILOT_CLI", raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "copilot")
    monkeypatch.setattr(llm_backend.shutil, "which",
                        lambda name: r"C:\npm\copilot.cmd" if name == "copilot" else None)
    assert llm_backend._copilot_bin() == r"C:\npm\copilot.cmd"
    assert llm_backend.available(None) is True


def test_copilot_cmd_runs_a_windows_shim_through_cmd_with_the_prompt_in_a_file(monkeypatch,
                                                                               tmp_path):
    """A .cmd shim is not executable by CreateProcess, and cmd.exe would re-parse the prompt."""
    monkeypatch.setenv("COPILOT_CLI", r"C:\npm\copilot.cmd")
    monkeypatch.setattr(llm_backend.shutil, "which", lambda name: name)
    prompt_file = tmp_path / "llm_prompt.txt"

    cmd = llm_backend._copilot_cmd("PROMPT with \"quotes\" & %VARS%", "m", prompt_file)

    assert cmd[:3] == ["cmd.exe", "/c", r"C:\npm\copilot.cmd"]
    assert cmd[-2] == "--prompt"
    assert prompt_file.as_posix() in cmd[-1]
    assert "PROMPT with" not in cmd[-1]  # the prompt text never reaches cmd.exe


def test_copilot_cmd_refuses_a_shim_without_a_prompt_file(monkeypatch):
    monkeypatch.setenv("COPILOT_CLI", r"C:\npm\copilot.cmd")
    monkeypatch.setattr(llm_backend.shutil, "which", lambda name: name)
    with pytest.raises(RuntimeError, match="prompt file"):
        llm_backend._copilot_cmd("P", "m")


def test_copilot_prompt_demands_file_only_json():
    prompt = llm_backend._copilot_prompt("SYS", "USER", "/tmp/out.json")
    assert "SYS" in prompt and "USER" in prompt
    assert "/tmp/out.json" in prompt
    assert "ONLY" in prompt and "console" in prompt


# ---- copilot output reading (file preferred, stdout fallback) ---------------------------

def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_read_output_prefers_written_file(tmp_path):
    out = tmp_path / "llm_output.json"
    out.write_text('{"action":"stop"}', encoding="utf-8")
    text = llm_backend._read_copilot_output(out, _proc(stdout="agent chatter"))
    assert text.strip() == '{"action":"stop"}'


def test_read_output_falls_back_to_stdout(tmp_path):
    out = tmp_path / "missing.json"
    text = llm_backend._read_copilot_output(out, _proc(stdout='{"action":"stop"}'))
    assert '"action"' in text


def test_read_output_raises_when_empty(tmp_path):
    out = tmp_path / "missing.json"
    with pytest.raises(RuntimeError):
        llm_backend._read_copilot_output(out, _proc(returncode=1, stderr="blocked"))


# ---- complete() routing -----------------------------------------------------------------

def test_complete_routes_to_copilot(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "copilot")

    def fake_run(prompt, model, timeout, prompt_file=None):
        # Simulate the CLI writing the JSON file the prompt asked for.
        marker = "the file "
        start = prompt.index(marker) + len(marker)
        end = prompt.index(" ", start)
        Path(prompt[start:end]).write_text('{"ok":true}', encoding="utf-8")
        return _proc(stdout="")

    monkeypatch.setattr(llm_backend, "_run_copilot", fake_run)
    out = llm_backend.complete("SYS", "USER", "gpt-5.5")
    assert out.strip() == '{"ok":true}'


def test_complete_routes_to_anthropic(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    called = {}

    def fake_anthropic(system, user, model, *, api_key, max_tokens):
        called["model"] = model
        return '{"ok":true}'

    monkeypatch.setattr(llm_backend, "_complete_anthropic", fake_anthropic)
    out = llm_backend.complete("SYS", "USER", "claude-opus-4-8", api_key="k")
    assert out == '{"ok":true}' and called["model"] == "claude-opus-4-8"


# ---- end-to-end: the two callers work through the Copilot backend -----------------------
# Proves explore/generate need no per-provider code: they call llm_backend.complete() and parse
# the JSON the model wrote. We simulate the CLI by writing the requested output file.

def _fake_copilot_returns(json_text):
    def fake_run(prompt, model, timeout, prompt_file=None):
        marker = "the file "
        start = prompt.index(marker) + len(marker)
        end = prompt.index(" ", start)
        Path(prompt[start:end]).write_text(json_text, encoding="utf-8")
        return _proc(stdout="")
    return fake_run


def test_explore_propose_llm_via_copilot(monkeypatch):
    from authoring import explore

    monkeypatch.setenv("LLM_PROVIDER", "copilot")
    monkeypatch.setattr(
        llm_backend, "_run_copilot",
        _fake_copilot_returns('{"action":"follow_link","target":{"method":"GET","path":"/#/about"}}'))
    obs = {"url": "/#/", "links": ["/#/about"], "forms": [], "api": []}
    action = explore.propose_llm(obs, "gpt-5.5")
    assert action["action"] == "follow_link" and action["target"]["path"] == "/#/about"


def test_generate_plan_from_llm_via_copilot(monkeypatch):
    from authoring import generate

    plan = {
        "app_id": "juice-shop", "base_url": "http://juice:3000",
        "login": {"url": "/#/login", "email_selector": "#email", "password_selector": "#password",
                  "submit_selector": "#loginButton", "token_check": "window.localStorage.getItem('token')"},
        "journey": [{"action": "goto", "target": "/#/basket"}],
    }
    monkeypatch.setenv("LLM_PROVIDER", "copilot")
    monkeypatch.setattr(llm_backend, "_run_copilot", _fake_copilot_returns(__import__("json").dumps(plan)))
    out = generate.plan_from_llm({"app_id": "juice-shop", "base_url": "http://juice:3000",
                                  "hosts": ["juice"], "index": [], "api": []}, "gpt-5.5")
    assert out["journey"][0]["target"] == "/#/basket"


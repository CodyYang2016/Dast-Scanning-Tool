"""LLM backend adapter: Anthropic SDK (direct) or GitHub Copilot CLI.

The provider is selected by the ``LLM_PROVIDER`` env var (``anthropic`` default, or ``copilot``).
Both providers return raw model text for one (system, user) turn; the callers in
``authoring/explore.py`` and ``authoring/generate.py`` parse the constrained JSON themselves and
validate it against the frozen schemas — the LLM never emits executable code (the D8 boundary).

The ``copilot`` path shells out to the ``copilot`` CLI (``@github/copilot``), which authenticates
with ``COPILOT_GITHUB_TOKEN`` and routes through the GitHub Copilot API. That is the approved path
inside Nationwide, where the direct Anthropic API is policy-blocked. The CLI is agentic and streams
status to stdout, so the copilot path asks the model to fence the JSON between markers in its final
message and cuts that block out of stdout.

Pure helpers (provider/command/prompt/output parsing) are unit-tested; the live CLI call is verified
by running it with a token.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ANTHROPIC = "anthropic"
COPILOT = "copilot"


def snippet(text: str, limit: int = 300) -> str:
    """A one-line excerpt of model output, for error messages that must say what came back.

    An unparseable reply is only actionable if the operator can see it: "no JSON object found"
    alone cannot distinguish a refusal, a rate-limit notice and a truncated answer.
    """
    flat = " ".join((text or "").split())
    if not flat:
        return "<empty>"
    return flat[:limit] + ("..." if len(flat) > limit else "")


class LLMRequiredError(RuntimeError):
    """The LLM path was demanded (--require-llm) and could not be taken.

    Without it a wrong model id, an expired token or a missing CLI all surface as
    ``plan_source: fallback`` — indistinguishable from a deliberate ``--no-llm`` run, so a broken
    LLM configuration can run unnoticed. Callers that must not silently degrade raise this.
    """


class StrictLLM:
    """The --require-llm budget for a multi-step run: tolerate a flaky reply, abort a dead provider.

    An exploration makes one call per step, and a model occasionally answers with prose or truncated
    JSON. Failing the run on the first such answer throws away a walk the fallback proposer could
    have finished, so a failure is only fatal once `max_consecutive` of them happen back to back
    (a provider that is actually unusable) or if `finish()` finds the model never drove a step.
    """

    def __init__(self, max_consecutive: int = 3):
        self.max_consecutive = max_consecutive
        self.consecutive = 0
        self.failures: list[str] = []
        self.successes = 0

    def success(self) -> None:
        self.successes += 1
        self.consecutive = 0

    def failure(self, exc: BaseException) -> None:
        """Record a failed step; raise once they are consecutive enough to mean a dead provider."""
        self.failures.append(str(exc))
        self.consecutive += 1
        if self.consecutive >= self.max_consecutive:
            raise LLMRequiredError(
                f"{self.consecutive} consecutive LLM failures, last: {exc}") from exc

    def finish(self) -> None:
        """Raise if the run completed without the model ever producing a usable action."""
        if self.successes == 0 and self.failures:
            raise LLMRequiredError(
                f"the LLM drove no step of this run ({len(self.failures)} failures), "
                f"last: {self.failures[-1]}")


_JSON_START = "<<<DAST_JSON"
_JSON_END = "DAST_JSON>>>"
_DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"
_DEFAULT_COPILOT_MODEL = "gpt-5.5"
# Mirrors the non-interactive flags the Nationwide pen-test-loop uses; override via COPILOT_FLAGS.
_DEFAULT_COPILOT_FLAGS = ("--allow-all-tools --excluded-tools=web_fetch --disable-builtin-mcps "
                          "--no-ask-user -s")  # --no-ask-user: never block a scan waiting on stdin


def provider() -> str:
    """The selected LLM provider (lower-case). Defaults to Anthropic."""
    return (os.environ.get("LLM_PROVIDER") or ANTHROPIC).strip().lower() or ANTHROPIC


def default_model() -> str:
    """Provider-appropriate default model, so callers need not hard-code an Anthropic id."""
    if provider() == COPILOT:
        return os.environ.get("COPILOT_MODEL") or _DEFAULT_COPILOT_MODEL
    return os.environ.get("ANTHROPIC_MODEL") or _DEFAULT_ANTHROPIC_MODEL


def _copilot_bin() -> str:
    """The copilot executable, resolved to a full path where one can be found.

    npm installs the CLI on Windows as `copilot.cmd`, and PATHEXT is applied by the shell, not
    by CreateProcess — so the bare name passes `shutil.which` and then fails `subprocess.run`
    with WinError 2. Resolving here keeps the two agreeing on the same binary.
    """
    name = os.environ.get("COPILOT_CLI") or "copilot"
    return _copilot_resolved() or name


def _copilot_resolved() -> str | None:
    """The copilot executable as found on PATH, or None when it is not installed."""
    return shutil.which(os.environ.get("COPILOT_CLI") or "copilot")


def _copilot_flags() -> list[str]:
    raw = os.environ.get("COPILOT_FLAGS")
    return (raw if raw is not None else _DEFAULT_COPILOT_FLAGS).split()


def _copilot_timeout(default: float) -> float:
    raw = os.environ.get("COPILOT_TIMEOUT_SECONDS")
    if raw and raw.strip().replace(".", "", 1).isdigit():
        return float(raw)
    return default


def available(api_key: str | None = None) -> bool:
    """Whether the selected provider can be attempted now. Never raises; callers fall back.

    Copilot is available when the CLI is on PATH; Anthropic when a key is present.
    """
    if provider() == COPILOT:
        return _copilot_resolved() is not None
    return bool(api_key or os.environ.get("ANTHROPIC_API_KEY"))


def complete(system: str, user: str, model: str, *, api_key: str | None = None,
             max_tokens: int = 4096, timeout: float = 180.0) -> str:
    """Return raw model text for one (system, user) turn. Raises on failure so callers fall back."""
    if provider() == COPILOT:
        return _complete_copilot(system, user, model, timeout=_copilot_timeout(timeout))
    return _complete_anthropic(system, user, model, api_key=api_key, max_tokens=max_tokens)


# ---- Anthropic (direct SDK) --------------------------------------------------------------

def _complete_anthropic(system: str, user: str, model: str, *, api_key: str | None,
                        max_tokens: int) -> str:
    import anthropic  # lazy: keeps the copilot path and tests import-free

    client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
    # Latest models (Opus 4.8, Sonnet 5, ...) reject temperature/top_p/top_k; omit them.
    msg = client.messages.create(
        model=model, max_tokens=max_tokens, system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(getattr(b, "text", "") for b in msg.content)


# ---- Copilot CLI (Nationwide-approved path) ----------------------------------------------

def _copilot_prompt(system: str, user: str) -> str:
    """Build the single-shot prompt: the JSON comes back between markers in the final message.

    Asking the agent to write the JSON to a file puts the answer behind the CLI's tool-permission
    gate, which denies writes in a non-interactive session it cannot ask the operator about -- so
    the reply is lost to "Permission denied" even though the model produced it. Markers keep the
    answer on stdout, which no gate guards, and survive the CLI's own status chatter around it.
    """
    return (
        f"{system}\n\n{user}\n\n"
        f"Reply with ONLY the resulting JSON object, on its own lines between the markers "
        f"{_JSON_START} and {_JSON_END}, as the final message of this session. Use no tools, "
        "write no files, and add no prose or code fences between the markers."
    )


def _is_batch_shim(binary: str) -> bool:
    """npm installs the CLI on Windows as `copilot.cmd`, which CreateProcess cannot execute."""
    return binary.lower().endswith((".cmd", ".bat"))


def _copilot_cmd(prompt: str, model: str, prompt_file: Path | None = None) -> list[str]:
    binary = _copilot_bin()
    args = [f"--model={model}", *_copilot_flags()]
    if not _is_batch_shim(binary):
        return [binary, *args, "--prompt", prompt]
    # A batch shim has to go through cmd.exe, which would also re-parse the prompt's quotes and
    # `%` signs — so the prompt travels as a file the agent reads instead of on the command line.
    if prompt_file is None:
        raise RuntimeError(f"a prompt file is required to run the batch shim {binary}")
    return ["cmd.exe", "/c", binary, *args, "--prompt",
            f"Read the file {prompt_file.as_posix()} and follow the instructions in it exactly."]


def _run_copilot(prompt: str, model: str, timeout: float,
                 prompt_file: Path | None = None) -> subprocess.CompletedProcess:
    # The CLI writes UTF-8 (box-drawing characters, arrows, curly quotes in its own chatter).
    # text=True alone would decode it with the locale codec — cp1252 on a Windows console, which
    # raises UnicodeDecodeError inside subprocess's reader thread and loses the whole reply.
    proc = subprocess.run(_copilot_cmd(prompt, model, prompt_file), capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if os.environ.get("LLM_DEBUG"):
        print(f"llm: copilot exit={proc.returncode}\nllm: stdout={proc.stdout}\n"
              f"llm: stderr={proc.stderr}", file=sys.stderr)
    return proc


def _marked_blocks(text: str) -> list[str]:
    """Every ``_JSON_START``..``_JSON_END`` block, in order; an unterminated one runs to the end."""
    blocks, rest = [], text
    while True:
        start = rest.find(_JSON_START)
        if start == -1:
            return blocks
        rest = rest[start + len(_JSON_START):]
        end = rest.find(_JSON_END)
        if end == -1:
            blocks.append(rest)
            return blocks
        blocks.append(rest[:end])
        rest = rest[end + len(_JSON_END):]


def _read_copilot_output(proc: subprocess.CompletedProcess) -> str:
    """The last marked block of stdout that looks like an object, else all of stdout.

    An agent transcript can carry the markers more than once — it narrates the instruction it was
    given before it answers — so the answer is the *last* block, and a block that holds no ``{`` is
    narration rather than an answer. Anything else is handed over whole: the callers' parsers pull
    the first JSON object out of raw text and quote what came back when there is none, so a reply
    that lost its markers still works and a refusal still reaches the operator verbatim.
    """
    out = proc.stdout or ""
    for block in reversed(_marked_blocks(out)):
        if "{" in block:
            return block
    if not out.strip():
        raise RuntimeError(
            f"copilot CLI produced no JSON (exit {proc.returncode}): "
            f"{(proc.stderr or '').strip()[:400]}")
    return out


def _complete_copilot(system: str, user: str, model: str, *, timeout: float) -> str:
    # Under the working directory: the CLI only trusts paths inside the directory it was started
    # in, so a system temp dir would put the prompt file out of the agent's reach.
    with tempfile.TemporaryDirectory(dir=Path.cwd(), prefix=".dast-copilot-") as td:
        prompt = _copilot_prompt(system, user)
        prompt_path = Path(td) / "llm_prompt.txt"
        prompt_path.write_text(prompt, encoding="utf-8")
        proc = _run_copilot(prompt, model, timeout, prompt_path)
        return _read_copilot_output(proc)

"""Text I/O is UTF-8 everywhere, not the operator's locale.

JSON is UTF-8 by specification, but Python's text mode defaults to the platform's preferred
encoding -- cp1252 on a Windows operator's machine. A ZAP HAR carrying one non-ASCII byte from the
application under test therefore crashed the scan *after* ZAP had finished, losing the run.
"""
import ast
import json
from pathlib import Path

from runner import evidence

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [p for d in ("runner", "authoring", "detections") for p in (ROOT / d).rglob("*.py")]
SOURCES.append(ROOT / "dast.py")


def _callee(node: ast.Call) -> str:
    func = node.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def _opens_in_binary_mode(node: ast.Call) -> bool:
    mode = node.args[1] if len(node.args) > 1 else None
    return isinstance(mode, ast.Constant) and "b" in str(mode.value)


def test_no_locale_dependent_text_io_in_the_tool():
    """Every text read/write in the tool names its encoding, so no run depends on the locale."""
    offenders = []
    for path in SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _callee(node) not in (
                    "open", "read_text", "write_text"):
                continue
            if any(kw.arg == "encoding" for kw in node.keywords):
                continue
            if _callee(node) == "open" and _opens_in_binary_mode(node):
                continue
            offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}: {_callee(node)}()")
    assert not offenders, 'text I/O without encoding="utf-8":\n' + "\n".join(offenders)


def test_redact_har_file_handles_a_non_ascii_body(tmp_path):
    """A right double quote (U+201D) is 0x9d in UTF-8's trail byte -- undefined in cp1252."""
    har = {"log": {"entries": [{"request": {"url": "http://app/\u201dx", "headers": []},
                                "response": {"headers": []}}]}}
    p = tmp_path / "active-scan.har"
    p.write_text(json.dumps(har), encoding="utf-8")

    evidence.redact_har_file(str(p))

    assert json.loads(p.read_text(encoding="utf-8"))["log"]["entries"][0]["request"]["url"] \
        == "http://app/\u201dx"

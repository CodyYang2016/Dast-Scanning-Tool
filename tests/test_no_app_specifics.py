"""The core must not know any application by name (W2-13).

Onboarding an application is adding `security/dast/<app>/app.yaml` — never a diff to
`authoring/` or `runner/`. That rule is only real if something enforces it, so this suite walks
every core module's AST and fails when an app-identifying string appears in executable code.

Docstrings and comments are exempt: explaining *why* the pilot's topology is
`http://juice:3000` is documentation, and comments never reach the AST at all. A selector, a
URL, a hostname or a credential belonging to one application, sitting in a string the code
actually evaluates, is the failure this catches.

Oracle: the app-identifying tokens themselves, listed below. When a new application is
onboarded, add its markers here — not to the modules.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORE_DIRS = ("authoring", "runner")

# Substrings that name a specific application: its hostname, its selectors, its endpoints, its
# session mechanics, its credentials. Case-insensitive.
APP_MARKERS = (
    "juice",            # the pilot's hostname, image and app id
    "dvwa",             # the second app — must not leak in either
    "#loginbutton",
    "#email",
    "#password",
    "welcome banner",
    "dismiss cookie message",
    "cc-btn",
    "/api/users/",
    "phpsessid",
    "localstorage.getitem",
    "securityquestion",
)


def _core_modules():
    for d in CORE_DIRS:
        yield from sorted((ROOT / d).glob("*.py"))


def _docstring_nodes(tree):
    """Constant nodes that are docstrings, which are documentation rather than behaviour."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                out.add(id(body[0].value))
    return out


def _offending_strings(path: Path):
    """(lineno, value, marker) for every executable string constant naming an application."""
    tree = ast.parse(path.read_text())
    skip = _docstring_nodes(tree)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            low = node.value.lower()
            for marker in APP_MARKERS:
                if marker in low:
                    hits.append((node.lineno, node.value, marker))
                    break
    return hits


@pytest.mark.parametrize("module", list(_core_modules()), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_core_module_names_no_application(module):
    hits = _offending_strings(module)
    assert not hits, (
        f"{module.relative_to(ROOT)} contains app-specific strings — move them to "
        f"security/dast/<app>/app.yaml: "
        + "; ".join(f"line {ln}: {val!r} (matched {m!r})" for ln, val, m in hits)
    )


def test_the_guard_itself_bites():
    """A module with an app-specific selector in executable code must fail the check."""
    src = 'def run(page):\n    """Dismiss the juice shop banner."""\n    page.click("#loginButton")\n'
    tmp = ROOT / "tests" / "_guard_probe.py"
    tmp.write_text(src)
    try:
        hits = _offending_strings(tmp)
        assert [h[2] for h in hits] == ["#loginbutton"]  # the docstring's "juice" is exempt
    finally:
        tmp.unlink()


def test_core_modules_were_actually_scanned():
    """Guard against the parametrisation silently collecting nothing."""
    assert len(list(_core_modules())) >= 10

"""Read and edit an app's app.yaml (UI-1, UI-6, UI-N3).

Edits go through ruamel.yaml's round-trip mode, so a save changes the edited value and nothing
else: comments, alignment and ordering survive. Every edit is checked three ways before anything
is written: the file hasn't changed since it was read (etag), each changed setting's tier allows
editing it, and the result passes the core's own validation (appconfig.validate_app_config).
"""
from __future__ import annotations

import difflib
import hashlib
import io
import os
import tempfile
from pathlib import Path

import yaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from authoring import appconfig
from webui.tiers import TierMap

SECRET_FIELDS = ("auth.credentials.email_env", "auth.credentials.password_env")


class ConfigError(Exception):
    """A refused edit. `status` is the HTTP status; message and fix are shown as they are."""

    def __init__(self, status: int, message: str, fix: str | None = None):
        super().__init__(message)
        self.status, self.message, self.fix = status, message, fix


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def _mode_of(path: Path) -> int:
    """The permission bits a rewrite of `path` should have: its own, or a new file's default."""
    try:
        return path.stat().st_mode & 0o777
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        return 0o666 & ~umask


def etag_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def plain(node):
    """ruamel's round-trip types as plain JSON-able values."""
    if isinstance(node, dict):
        return {str(k): plain(v) for k, v in node.items()}
    if isinstance(node, list):
        return [plain(v) for v in node]
    if node is None or isinstance(node, (bool, int, float)):
        return node
    return str(node)


def _set(doc: CommentedMap, dotted: str, value) -> None:
    keys = dotted.split(".")
    node = doc
    for k in keys[:-1]:
        if k not in node or not isinstance(node[k], dict):
            node[k] = CommentedMap()
        node = node[k]
    last = keys[-1]
    current = node.get(last)
    if isinstance(current, CommentedSeq) and isinstance(value, list):
        current[:] = value          # keep the list's flow/block style and comments
    else:
        node[last] = value


class ConfigStore:
    def __init__(self, apps_dir: Path, tiers: TierMap, secrets):
        self.apps_dir = Path(apps_dir)
        self.tiers = tiers
        self.secrets = secrets

    def path(self, app: str) -> Path:
        return self.apps_dir / app / "app.yaml"

    def exists(self, app: str) -> bool:
        return self.path(app).is_file()

    def apps(self) -> list[str]:
        if not self.apps_dir.is_dir():
            return []
        return sorted(p.name for p in self.apps_dir.iterdir() if (p / "app.yaml").is_file())

    def read(self, app: str) -> tuple[bytes, dict]:
        p = self.path(app)
        if not p.is_file():
            raise ConfigError(404, f"There is no application called {app}.",
                              "Onboard it first, or check the name.")
        raw = p.read_bytes()
        return raw, yaml.safe_load(raw.decode("utf-8")) or {}

    def settings(self, app: str) -> dict:
        raw, cfg = self.read(app)
        fields = []
        for dotted, value in self.tiers.fields(cfg):
            entry = {"path": dotted, "value": value, **self.tiers.resolve(dotted, cfg).as_dict()}
            if dotted in SECRET_FIELDS and isinstance(value, str):
                entry["secret"] = self.secrets.status(value)
            fields.append(entry)
        return {"app_id": app, "etag": etag_of(raw), "fields": fields,
                "command": f"python -m dast scan {app}"}

    def _apply(self, app: str, etag: str, changes: dict) -> tuple[str, str]:
        raw, cfg = self.read(app)
        if etag != etag_of(raw):
            raise ConfigError(409, f"{app}'s settings changed since you opened them.",
                              "Reload the page to see the current settings, then make your change again.")
        if not changes:
            raise ConfigError(422, "Nothing to change.", None)
        for dotted, _ in changes.items():
            tier = self.tiers.resolve(dotted, cfg)
            if not tier.editable:
                kind = {"C": "needs approval", "D": "isn't a setting you change here"}.get(tier.tier,
                                                                                         "can't be changed")
                raise ConfigError(403, f"'{dotted}' {kind}.",
                                  "Propose the change as a pull request on this app's app.yaml."
                                  if tier.tier == "C" else None)
        y = _yaml()
        doc = y.load(raw.decode("utf-8"))
        for dotted, value in changes.items():
            _set(doc, dotted, value)
        out = io.StringIO()
        y.dump(doc, out)
        new_text = out.getvalue()
        try:
            appconfig.validate_app_config(yaml.safe_load(new_text), source=f"{app}'s app.yaml")
        except Exception as exc:                       # jsonschema.ValidationError or ValueError
            message = getattr(exc, "message", None) or str(exc).splitlines()[0]
            raise ConfigError(422, f"That change isn't valid: {message}",
                              "Check the value's type and allowed choices.") from None
        old_text = raw.decode("utf-8")
        diff = "".join(difflib.unified_diff(old_text.splitlines(keepends=True),
                                            new_text.splitlines(keepends=True),
                                            fromfile=f"{app}/app.yaml", tofile=f"{app}/app.yaml"))
        return new_text, diff

    def preview(self, app: str, etag: str, changes: dict) -> dict:
        _, diff = self._apply(app, etag, changes)
        return {"diff": diff}

    def save(self, app: str, etag: str, changes: dict) -> dict:
        new_text, diff = self._apply(app, etag, changes)
        target = self.path(app)
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".app.yaml.")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(new_text)
        # mkstemp creates the file owner-only; keep the permissions the file had (QA-9).
        os.chmod(tmp, _mode_of(target))
        os.replace(tmp, target)
        return {"etag": etag_of(target.read_bytes()), "diff": diff}

    def line_of(self, app: str, dotted: str) -> int | None:
        """1-based line where a setting's key sits, for git blame."""
        y = _yaml()
        node = y.load(self.path(app).read_text(encoding="utf-8"))
        keys = dotted.split(".")
        for k in keys[:-1]:
            if not isinstance(node, dict) or k not in node:
                return None
            node = node[k]
        if not isinstance(node, CommentedMap) or keys[-1] not in node:
            return None
        return node.lc.key(keys[-1])[0] + 1

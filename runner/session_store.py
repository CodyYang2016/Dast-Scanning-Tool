"""Where the stored browser session comes from, and how long it may be trusted (W5-3).

A Playwright storageState file is a working login: whoever holds it is the scan's identity. It
used to sit in `.secrets/` with no expiry, readable by any user on the machine. Two forms now:

- `env:VAR` — the storageState JSON (raw or base64) in an environment variable. This is how CI
  secret stores (GitHub secrets, a Vault agent) deliver a secret. It is written to a private
  temporary file for the run and deleted afterwards, whatever happens.
- a file path — used in place, but refused when older than its TTL (re-seed it), readable by
  other users, or inside this repository without being git-ignored.

Playwright itself drops cookies past their own expiry when it loads the state.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import os
import stat
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Windows has no POSIX mode bits: st_mode reports 0o666 for every writable file, and the user's
# profile and %TEMP% are private through ACLs instead.
POSIX_PERMISSIONS = os.name != "nt"


class SessionStoreError(RuntimeError):
    """The stored session cannot be used. `stale` errors can fall back to a fresh login;
    the others are a handling problem and must stop the run."""

    def __init__(self, message: str, stale: bool = False):
        super().__init__(message)
        self.stale = stale


def _unignored_in_repo(path: Path) -> bool:
    """True when `path` is inside this repository and git would track it."""
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        return False
    try:
        r = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", str(path.resolve())],
                           capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False                     # no git: nothing could commit it by accident either
    return r.returncode == 1             # 0 ignored, 1 not ignored, 128 not a repository


def _check_file(path: Path, ttl_hours: float) -> None:
    if not path.exists():
        raise SessionStoreError(f"stored session {path} does not exist — seed one: "
                                f"`dast author <app> --explore`", stale=True)
    mode = stat.S_IMODE(path.stat().st_mode)
    if POSIX_PERMISSIONS and mode & 0o077:
        raise SessionStoreError(
            f"stored session {path} is readable by other users (mode {oct(mode)}). It is a "
            f"working login: chmod 600 {path}")
    if _unignored_in_repo(path):
        raise SessionStoreError(
            f"stored session {path} is inside the repository and not git-ignored, so it could "
            f"be committed. Move it under .secrets/ (ignored) or outside the repository")
    age_h = (time.time() - path.stat().st_mtime) / 3600
    if age_h > ttl_hours:
        raise SessionStoreError(
            f"stored session {path} is {age_h:.0f} h old, past its {ttl_hours:g} h limit "
            f"(auth.storage_state_ttl_hours). re-seed: `dast author <app> --explore`",
            stale=True)


def _from_env(var: str) -> str:
    raw = os.environ.get(var)
    if not raw:
        raise SessionStoreError(f"auth.storage_state is env:{var}, but {var} is not set")
    text = raw.strip()
    if not text.startswith("{"):
        try:
            text = base64.b64decode(text, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            pass
    try:
        state = json.loads(text)
    except json.JSONDecodeError:
        state = None
    if not isinstance(state, dict) or "cookies" not in state:
        raise SessionStoreError(f"{var} does not hold a Playwright storageState (JSON with "
                                f"`cookies`), raw or base64")
    return text


@contextlib.contextmanager
def open_storage_state(ref: str | None, ttl_hours: float):
    """Yield a usable storageState path for the duration of the block, or None if none is
    configured. Raises SessionStoreError when the configured one must not be used."""
    if not ref:
        yield None
        return
    if str(ref).startswith("env:"):
        text = _from_env(str(ref)[4:])
        fd, tmp = tempfile.mkstemp(prefix="dast-session-", suffix=".json")
        try:
            if POSIX_PERMISSIONS:
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(text)
            yield tmp
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
        return
    path = Path(ref)
    if not path.is_absolute():
        path = ROOT / path
    _check_file(path, ttl_hours)
    yield str(path)

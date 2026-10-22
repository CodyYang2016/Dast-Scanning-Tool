"""Secrets by reference only (UI-4).

The UI handles the *names* of secrets. Values are read only on the server, only to hand them to a
`dast` job's environment, and are masked out of anything the UI shows or logs. A shared deployment
swaps EnvSecrets for a secret store behind the same interface.
"""
from __future__ import annotations

import os
import re

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MASK = "••••"


class EnvSecrets:
    """Secrets are environment variables of the process that started `dast ui`."""

    @staticmethod
    def valid_name(name: str) -> bool:
        return bool(name) and bool(_NAME.match(name))

    def is_set(self, name: str) -> bool:
        return self.valid_name(name) and bool(os.environ.get(name))

    def value(self, name: str) -> str | None:
        """Server-side only: for a job's environment. Never returned to a client."""
        return os.environ.get(name) if self.valid_name(name) else None

    def status(self, name: str) -> dict:
        return {"name": name, "set": self.is_set(name)}


def mask(text: str, values) -> str:
    """Replace every secret value (longest first, so overlapping values can't leak) with MASK."""
    for v in sorted({v for v in values if v and len(v) >= 3}, key=len, reverse=True):
        text = text.replace(v, MASK)
    return text

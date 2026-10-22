"""Who is acting (UI-N4, UI-N6).

Locally that is the person who started `dast ui`. A shared deployment replaces this with the
signed-in user from single sign-on; nothing else in the UI asks the operating system.
"""
from __future__ import annotations

from webui.config import UIConfig


class Identity:
    def __init__(self, config: UIConfig):
        self._actor = config.actor

    def current(self, request=None) -> str:
        return self._actor

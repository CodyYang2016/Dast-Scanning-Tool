"""The UI's own audit trail (UI-N4): one JSON line per write, with who made it."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

EVENTS = {"settings.save", "suppression.propose", "suppression.approve", "job.start", "job.stop",
          "publish", "onboard.start", "onboard.confirm"}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AuditLog:
    def __init__(self, path: Path, mask=lambda s: s):
        self.path = Path(path)
        self._mask = mask
        self._lock = threading.Lock()

    def record(self, actor: str, event: str, app_id: str | None = None, **detail) -> dict:
        assert event in EVENTS, event
        entry = {"ts": now(), "actor": actor, "app_id": app_id, "event": event, "detail": detail}
        line = self._mask(json.dumps(entry, default=str))
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

"""Structured scan events (W3-3, NFR-4).

Before this, only the scope guard logged and everything else was `print()`: no timestamps, no
scan id, and an unattended run left no answer to "what did you touch, what did you refuse, and
when?". Each event is one JSON line in the run's `events.jsonl`, carrying `ts`, `scan_id`,
`app_id` and `event`, written beside the scan's other artifacts so it travels with them (and with
the CI artifact). `DAST_LOG_FORMAT=json` also mirrors them to stderr for a log shipper.

Two rules: strings are redacted before they are written (an event may quote a URL), and logging
NEVER fails a scan. Events emitted before the run directory exists (preflight runs first) are
held and flushed when it is attached.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone


def _clean(value):
    from runner.redact import redact_text
    if isinstance(value, str):
        return redact_text(value)[:2000]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value][:200]
    return value


class EventLog:
    def __init__(self, app_id: str = "", scan_id: str = ""):
        self.context = {"scan_id": scan_id, "app_id": app_id}
        self.path = None
        self._pending: list[dict] = []
        self.count = 0

    def bind(self, **context) -> None:
        self.context.update(context)

    def attach(self, path) -> None:
        """Start writing to `path`, flushing anything emitted before it existed."""
        self.path = path
        pending, self._pending = self._pending, []
        for record in pending:
            # Emitted before the scan had an id (preflight runs first): stamp it now.
            for key, value in self.context.items():
                if not record.get(key):
                    record[key] = value
            self._write(json.dumps(record, default=str))

    def emit(self, event: str, **fields) -> None:
        try:
            record = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                      **self.context, "event": event, **_clean(fields)}
            line = json.dumps(record, default=str)
            self.count += 1
            if os.environ.get("DAST_LOG_FORMAT") == "json":
                print(line, file=sys.stderr)
            if self.path is None:
                self._pending.append(record)
            else:
                self._write(line)
        except Exception:
            pass                       # an audit log that breaks the scan is worse than none

    def _write(self, line: str) -> None:
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass


class _Null(EventLog):
    def emit(self, event: str, **fields) -> None:
        pass


_current: EventLog = _Null()


def start(app_id: str = "", scan_id: str = "") -> EventLog:
    """Begin a run's event log; modules emit through `emit()` without plumbing it through."""
    global _current
    _current = EventLog(app_id=app_id, scan_id=scan_id)
    return _current


def get() -> EventLog:
    return _current


def emit(event: str, **fields) -> None:
    _current.emit(event, **fields)


def reset() -> None:
    global _current
    _current = _Null()

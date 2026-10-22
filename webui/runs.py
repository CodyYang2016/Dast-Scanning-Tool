"""Scan runs as the CLI leaves them on disk (UI-7, UI-9).

Each run is a directory out/<app>/scans/<scan_id>/ written by `dast scan` and `dast report`. This
module only reads them; the layout comes from dast.Paths so the two can't drift apart.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import shlex
import time
from collections import Counter
from pathlib import Path

from dast import Paths

SEVERITIES = ("high", "medium", "low", "info")
LIFECYCLE = ("new", "open", "resolved", "not_scanned", "suppressed")
STOP_MARKER = "ui-stopped.json"


def _json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def started_at(scan_id: str) -> str | None:
    try:
        return dt.datetime.strptime(scan_id, "%Y%m%dT%H%M%SZ").replace(
            tzinfo=dt.timezone.utc).isoformat()
    except ValueError:
        return None


def read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


class Runs:
    def __init__(self, out_dir: Path, jobs):
        self.out_dir = Path(out_dir)
        self.jobs = jobs

    def paths(self, app: str) -> Paths:
        return Paths(self.out_dir, app)

    def run_dir(self, app: str, scan_id: str) -> Path:
        return self.paths(app).scans / scan_id

    def status(self, app: str, scan_id: str) -> str:
        d = self.run_dir(app, scan_id)
        if self.jobs.running_scan(app) == scan_id:
            return "running"
        if (d / STOP_MARKER).exists() or any(e.get("event") == "stop"
                                             for e in read_events(d / "events.jsonl")):
            return "stopped"
        if (d / "records.json").exists():
            return "complete"
        return "aborted"

    def list(self, app: str) -> list[dict]:
        scans = self.paths(app).scans
        if not scans.is_dir():
            return []
        ids = sorted((p.name for p in scans.iterdir() if p.is_dir()), reverse=True)
        return [{"scan_id": s, "status": self.status(app, s), "started_at": started_at(s)} for s in ids]

    def latest_with_records(self, app: str) -> Path | None:
        return self.paths(app).latest_scan()

    def records(self, app: str, scan_id: str) -> list[dict]:
        d = self.run_dir(app, scan_id)
        labeled = d / "labeled.json"
        return _json(labeled if labeled.exists() else d / "records.json", [])

    def detail(self, app: str, scan_id: str) -> dict | None:
        d = self.run_dir(app, scan_id)
        if not d.is_dir():
            return None
        records = self.records(app, scan_id)
        sev = Counter(r.get("severity") for r in records)
        life = Counter(r.get("status") for r in records)
        cov = _json(d / "coverage.json", {})
        return {
            "scan_id": scan_id, "status": self.status(app, scan_id),
            "started_at": started_at(scan_id),
            "counts": {s: sev.get(s, 0) for s in SEVERITIES},
            "lifecycle": {s: life.get(s, 0) for s in LIFECYCLE},
            "coverage": {
                "routes_tested": len(cov.get("routes") or []),
                "rules": len(cov.get("rules") or []),
                "truncated_rules": cov.get("truncated_rules") or [],
                "excluded": cov.get("excluded") or [],
                "declared": None, "exercised": None,
                "session": cov.get("session"),
            },
            "has_events": (d / "events.jsonl").exists(),
        }

    def mark_stopped(self, app: str, scan_id: str, actor: str) -> None:
        d = self.run_dir(app, scan_id)
        if d.is_dir():
            (d / STOP_MARKER).write_text(json.dumps({"by": actor, "at": time.time()}),
                                         encoding="utf-8")

    async def stream_events(self, app: str, scan_id: str, request, idle_s: float = 10.0):
        """Server-sent events: every line of events.jsonl, then new lines as they're appended.
        Ends when the client goes, or when the run is over and the file has been quiet a while."""
        path = self.run_dir(app, scan_id) / "events.jsonl"
        pos, last_change = 0, time.monotonic()
        while True:
            if await request.is_disconnected():
                return
            if path.exists():
                with open(path, encoding="utf-8") as fh:
                    fh.seek(pos)
                    chunk = fh.read()
                    complete = chunk[: chunk.rfind("\n") + 1] if "\n" in chunk else ""
                    pos += len(complete.encode("utf-8"))
                for line in complete.splitlines():
                    if line.strip():
                        last_change = time.monotonic()
                        yield f"data: {line}\n\n"
            running = self.jobs.running_scan(app) == scan_id
            if not running and time.monotonic() - last_change > idle_s:
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(0.2)


def replay_line(rec: dict, base_url: str) -> str:
    """How to send the request yourself: the record's own request line, as a curl command."""
    request_line = rec.get("request_line") or ""
    method, _, target = request_line.partition(" ")
    target = target or rec.get("endpoint") or "/"
    method = method if target and method else "GET"
    url = target if target.startswith("http") else base_url.rstrip("/") + target
    return f"curl -s -X {method} {shlex.quote(url)}"

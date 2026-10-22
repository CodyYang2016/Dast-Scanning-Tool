"""Everything the UI needs to know about where it runs. Built once by `dast ui` (or a test)."""
from __future__ import annotations

import getpass
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUNDLED_TIERS = Path(__file__).resolve().parent / "tiers.yaml"


@dataclass
class UIConfig:
    repo_root: Path = ROOT
    apps_dir: Path = ROOT / "security" / "dast"
    out_dir: Path = ROOT / "out"
    registry_path: Path = ROOT / "security" / "dast" / "environments.yaml"
    dist_dir: Path = ROOT / "webui" / "frontend" / "dist"
    audit_log: Path = ROOT / "out" / "ui-audit.jsonl"
    port: int = 8765
    launch_token: str = ""
    actor: str = field(default_factory=getpass.getuser)
    python: str = sys.executable            # the interpreter jobs run `-m dast` with
    zap_api: str = "http://localhost:8080"
    tiers_path: Path | None = None           # None: the mapping bundled with the UI

    def __post_init__(self):
        for name in ("repo_root", "apps_dir", "out_dir", "registry_path", "dist_dir", "audit_log"):
            setattr(self, name, Path(getattr(self, name)))
        if self.tiers_path is not None:
            self.tiers_path = Path(self.tiers_path)

    @property
    def tiers_file(self) -> Path:
        return self.tiers_path or BUNDLED_TIERS

    def job_env(self) -> dict[str, str]:
        """The environment every `dast` job runs with: the UI's own locations and its user."""
        env = dict(os.environ)
        env.update(DAST_APPS_DIR=str(self.apps_dir), DAST_OUT=str(self.out_dir),
                   DAST_ENV_REGISTRY=str(self.registry_path), DAST_ACTOR=self.actor,
                   DAST_ZAP_API=self.zap_api, PYTHONUNBUFFERED="1")
        return env

"""`python -m dast ui`: build the config from the environment and serve on loopback (UI-N1, UI-N2)."""
from __future__ import annotations

import os
import secrets
import sys
import threading
import webbrowser
from pathlib import Path

from webui.config import ROOT, UIConfig

DEFAULT_DIST = ROOT / "webui" / "frontend" / "dist"


def config_from_env(port: int, token: str) -> UIConfig:
    env = os.environ
    apps_dir = Path(env.get("DAST_APPS_DIR") or ROOT / "security" / "dast")
    out_dir = Path(env.get("DAST_OUT") or ROOT / "out")
    return UIConfig(
        repo_root=ROOT, apps_dir=apps_dir, out_dir=out_dir,
        registry_path=Path(env.get("DAST_ENV_REGISTRY") or apps_dir / "environments.yaml"),
        dist_dir=Path(env.get("DAST_UI_DIST") or DEFAULT_DIST),
        audit_log=out_dir / "ui-audit.jsonl", port=port, launch_token=token,
        python=sys.executable, zap_api=env.get("DAST_ZAP_API") or "http://localhost:8080")


def main(port: int, open_browser: bool) -> int:
    dist = Path(os.environ.get("DAST_UI_DIST") or DEFAULT_DIST)
    if not (dist / "index.html").is_file():
        print(f"The UI hasn't been built (no {dist / 'index.html'}). Build it once with:\n"
              f"  cd {ROOT / 'webui' / 'frontend'} && npm ci && npm run build", file=sys.stderr)
        return 2
    try:
        import uvicorn

        from webui.app import create_app
    except ImportError as exc:
        print(f"The UI's Python packages are missing ({exc.name}). Install them with:\n"
              f"  pip install -r {ROOT / 'requirements-ui.txt'}", file=sys.stderr)
        return 2
    token = secrets.token_urlsafe(32)
    config = config_from_env(port, token)
    app = create_app(config)
    url = f"http://127.0.0.1:{port}/auth?token={token}"
    print(f"DAST UI for {config.actor}, on this machine only.\n"
          f"Open this link (it works once): {url}\n"
          f"Stop with Ctrl+C.", flush=True)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0

"""Stand-in for `python -m dast …` in the UI tests.

The UI is configured to run jobs with an interpreter that is really this script. It records the
exact command line and the environment variables a test asks about, then acts out what the real
command would leave behind, steered by FAKE_DAST_* variables. It is test scaffolding: it never
imports the UI, so a test that reads its log is checking what the UI actually ran.
"""
import json
import os
import signal
import sys
import time
from pathlib import Path


def record(argv):
    log = os.environ.get("FAKE_DAST_LOG")
    if not log:
        return
    watched = [v for v in os.environ.get("FAKE_DAST_WATCH", "").split(",") if v]
    entry = {"argv": argv, "env": {k: os.environ.get(k) for k in
                                   ["DAST_ACTOR", "DAST_APPS_DIR", "DAST_OUT", "DAST_ENV_REGISTRY",
                                    "GITHUB_TOKEN", *watched]}}
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def event(path: Path, scan_id: str, app: str, name: str, **fields):
    line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime()), "scan_id": scan_id,
            "app_id": app, "event": name, **fields}
    actor = os.environ.get("DAST_ACTOR")
    if actor:
        line["actor"] = actor
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(line) + "\n")


def scan(app: str) -> int:
    scan_id = os.environ.get("FAKE_DAST_SCAN_ID", time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    run = Path(os.environ["DAST_OUT"]) / app / "scans" / scan_id
    run.mkdir(parents=True, exist_ok=True)
    events = run / "events.jsonl"
    mode = os.environ.get("FAKE_DAST_SCAN", "ok")
    event(events, scan_id, app, "preflight", outcome="ok", environment_class="dev")
    if mode == "abort":
        event(events, scan_id, app, "abort", kind="PreflightError",
              reason="host 'billing.test.example.internal' is not in the environment registry")
        print("RUNNER ABORT: host 'billing.test.example.internal' is not in the environment "
              "registry", file=sys.stderr)
        return 2
    if mode == "slow":
        def stopped(*_):
            event(events, scan_id, app, "stop", reason="operator interrupt; ZAP told to stop")
            sys.exit(130)
        signal.signal(signal.SIGINT, stopped)
        signal.signal(signal.SIGTERM, stopped)
        event(events, scan_id, app, "auth", outcome="ok")
        for _ in range(600):
            time.sleep(0.1)
        return 0
    event(events, scan_id, app, "auth", outcome="ok")
    (run / "records.json").write_text("[]", encoding="utf-8")
    return 0


def onboard(argv) -> int:
    out = argv[argv.index("--config-out") + 1]
    app = argv[1]
    base = argv[argv.index("--base-url") + 1]
    login = argv[argv.index("--login-url") + 1] if "--login-url" in argv else "/login"
    env = app.replace("-", "_").upper()
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(
        f"app_id: {app}\nenvironment_class: {argv[argv.index('--environment-class') + 1]}\n"
        f"base_url: {base}\nscope:\n  allow: [{base.split('://')[-1].split('/')[0].split(':')[0]}]\n"
        f"auth:\n  mode: {argv[argv.index('--auth') + 1]}\n  login_url: {login}\n"
        "  steps:\n    - {action: fill, selector: \"input#username\", value: identifier}\n"
        "    - {action: fill, selector: \"input#password\", value: secret}\n"
        "    - {action: click, selector: \"button[type=submit]\"}\n"
        "  proof:\n    route:\n      path: /account\n      forbid_redirect_to: /login\n"
        f"  credentials:\n    email_env: {env}_USER\n    password_env: {env}_PASS\n"
        "record:\n  authenticated_routes: [/account]\n", encoding="utf-8")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if argv[:2] == ["-m", "dast"]:
        argv = argv[2:]
    record(argv)
    printed = os.environ.get("FAKE_DAST_PRINT_ENV")
    if printed:                       # a job that echoes a secret: the UI must mask it
        print(f"debug: {printed}={os.environ.get(printed, '')}", flush=True)
    cmd = argv[0] if argv else ""
    if cmd == "scan":
        return scan(argv[1])
    if cmd == "onboard":
        return onboard(argv)
    if cmd == "author":
        print(json.dumps({"app_id": argv[1], "pages": 6, "steps_by_source": {"llm": 7}}))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

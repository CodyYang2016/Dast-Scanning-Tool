# Podman and Docker

The tool and its web UI run on either container engine. The person this was built for runs Podman
on a Nationwide Windows workstation (Git Bash, `podman-compose`, NTR images, Artifactory and the
corporate CA: [`nationwide_test_checklist.md`](nationwide_test_checklist.md)). Docker is what
GitHub's hosted CI and most other workstations use. Both get the same files and the same flow; only
the compose command differs.

## What uses which engine

| Path | Engine | How |
|---|---|---|
| Nationwide demo scripts (`demo_replay_flow.sh`, `demo_full_scan.sh`, `cleanup_demo_ports.sh`, `prepull_playwright_podman_nationwide.sh`) | Podman | Unchanged; they call `podman` and `podman-compose` directly |
| The web UI's ZAP and targets | Either | `bash scripts/ui_stack.sh`, which picks the engine (below) |
| The CI self-test (`.github/workflows/dast-selftest.yml`) | Docker | `docker compose up --build`, unchanged |
| CI check of the Podman path (`.github/workflows/podman.yml`) | Podman | `scripts/ui_stack.sh` on Ubuntu with `podman-compose`, then `dast author` and `dast scan` |
| The workflow the UI exports (Automation) | Either | `${{ vars.DAST_COMPOSE \|\| 'docker compose' }}`; a Podman runner sets the repository variable `DAST_COMPOSE=podman-compose` |

## `scripts/ui_stack.sh`

```bash
bash scripts/ui_stack.sh ui juice          # start ZAP and Juice Shop, wait for ZAP, start the UI
bash scripts/ui_stack.sh up juice dvwa     # just the containers; prints the next commands
bash scripts/ui_stack.sh status            # engine, compose command, what's running
bash scripts/ui_stack.sh down              # stop and remove this project's containers
bash scripts/ui_stack.sh --dry-run up      # print what would run; change nothing
```

**Choosing the engine:**
- `DAST_CONTAINER_ENGINE=podman` or `docker`, if set.
- Otherwise Docker, if `docker info` works.
- Otherwise Podman.

**The compose command:**
- Podman: `podman-compose`, as the checklist uses, or else `podman compose`.
- Docker: `docker compose`.

**What it starts:**
- It starts `compose.yaml` plus `compose.demo.yaml`: the same compose project (`ssd-dast-poc`) and
  overlay the checklist's replay step uses.
- ZAP is published on `127.0.0.1`, keyed, with `ZAP_API_ALLOW='.*'`, so the browser and the UI on
  this machine may call it. The key is still required.

**The ZAP key:**
- An exported `ZAP_API_KEY` wins: the checklist's terminal setup exports one.
- Otherwise one key per machine is kept in `.secrets/zap-ui.key`: owner-only, git-ignored and
  never printed.

**A Podman machine:** on Windows or macOS it must be running. If it isn't, the script says so and
points at `prepull_playwright_podman_nationwide.sh`, which also repairs the VM's proxy.

## Variables

| Variable | Default | What it does |
|---|---|---|
| `DAST_CONTAINER_ENGINE` | detected | `podman` or `docker` |
| `DAST_ZAP_PORT` | `8080` | ZAP's port, the same inside and outside the container: ZAP only answers API calls addressed to the port it listens on |
| `DAST_JUICE_PORT` | `3000` | Juice Shop's host port |
| `ZAP_IMAGE`, `JUICE_IMAGE`, `DVWA_IMAGE` | pinned `docker.io/...` digests | A mirror, e.g. `ntr.nwie.net/docker.io/zaproxy/zap-stable` |

Leave `DAST_ZAP_PORT` and `DAST_JUICE_PORT` unset with the `demo_*.sh` scripts, which expect 8080
and 3000. Set them only where those ports are taken, e.g. a workstation already running its own ZAP
on 8080: `DAST_ZAP_PORT=18080 DAST_JUICE_PORT=13000 bash scripts/ui_stack.sh ui juice`.

## What differs between the engines, and what doesn't

**The same on both:** the compose files, image digests, network and fixed runner address, the
keyed ZAP, the scope and preflight checks, and every `dast` command.

**Different:**
- **The compose command**, chosen as above.
- **Image names:** Podman needs fully qualified names unless its `registries.conf` searches Docker
  Hub, which is why the defaults are `docker.io/...`. Docker reads those exactly as before (same
  image ID).
- **Windows** (the Nationwide workstation):
  - The UI stops a job with a new process group, Ctrl+Break, then `taskkill /T`, where macOS and
    Linux use process-group signals. That's handled in `webui/jobs.py`.
  - The UI's front end is committed to the repo (`webui/frontend/dist`), so no Node is needed;
    CI fails if it's stale.
- **CI:** Python tests run on Linux and Windows; the container path runs on Docker
  (`dast-selftest.yml`) and Podman (`podman.yml`).

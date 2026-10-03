# Nationwide test checklist

This checklist takes a Nationwide Windows workstation from nothing to a full DAST run against the
bundled Juice Shop target. At the end the findings are published as GitHub Issues. Each step
shows the result that counts as a pass. If a step does not pass, stop and look up the symptom in
[Troubleshooting](#troubleshooting).

- **Time:** about 45 minutes the first time, and about 10 minutes after that.
- **What success looks like:** step 4 prints `>> Scan gate exit code: 0`, and step 6 creates one
  issue per finding type in your sandbox repository.

## Ground rules

- Use **Git Bash**, not PowerShell or `cmd`.
- Run every command from the **repository root**, `~/poc-work/ssd-dast-tool-poc`. Do not run them
  from inside a `.git` folder or a bare clone, or Python cannot find the code.
- Stay in **one terminal** from start to finish, because each `export` applies only to the
  terminal you run it in. If you open a new terminal, paste [Terminal setup](#terminal-setup)
  again.
- Paste commands exactly as written. For example, `python -m pytest -q` has no trailing `.`.
- Never paste a token on the command line or into a file. Step 6 shows how to enter it safely.

## Prerequisites (check once)

| Need | Check | Pass |
|---|---|---|
| Nationwide network or VPN. GitHub's IP allow list blocks the repository from anywhere else. | `git ls-remote https://github.com/NationwideDevin/ssd-dast-tool-poc.git HEAD` | Prints a 40-character SHA |
| Git Bash | `git --version` | Prints a version |
| Python 3.10 or newer on `PATH` | `python --version` | `Python 3.10` or newer |
| Podman, with a machine created | `podman --version && podman machine list` | Lists `podman-machine-default`. If the list is empty, run `podman machine init` once. |
| The Nationwide CA bundle, as PEM text | `grep -c "BEGIN CERTIFICATE" "$HOME/certs/nw-ca-all.pem"` | A number of 1 or more. On disk this is `C:\Users\<you>\certs\nw-ca-all.pem`. If yours is elsewhere, set `DAST_CA_BUNDLE` to its path in Terminal setup. |
| Your Nationwide user ID and password for NTR (`ntr.nwie.net`) | — | — |
| For step 6: a **sandbox** GitHub repository where you are allowed to create issues | Open its **Issues** tab in a browser | The tab exists. If it doesn't, Issues are disabled; enable them under Settings → General → Features. |

Use a sandbox repository, not a real application's repository. Juice Shop findings are demo data.

## 0. Get the code

```bash
mkdir -p ~/poc-work && cd ~/poc-work
git clone https://github.com/NationwideDevin/ssd-dast-tool-poc.git
cd ssd-dast-tool-poc
git checkout parallel-poc-branch
git pull origin parallel-poc-branch
git log -1 --oneline
```

**Pass:** `git log` shows the newest commit on `parallel-poc-branch` at
https://github.com/NationwideDevin/ssd-dast-tool-poc/commits/parallel-poc-branch.

If you already have a clone whose `origin` points at the upstream `Nationwide` repository, pull
from the fork by name instead:
`git remote add downstream https://github.com/NationwideDevin/ssd-dast-tool-poc.git` (once),
then `git pull downstream parallel-poc-branch`. A plain `git pull` would fetch from the wrong
remote and quietly leave you on old code.

## Terminal setup

Paste this block into every new terminal. In the very first terminal, `.venv` does not exist yet;
the `source` line prints an error that you can ignore, because step 1 creates `.venv`.

```bash
cd ~/poc-work/ssd-dast-tool-poc
source .venv/Scripts/activate
export DAST_CA_BUNDLE="$HOME/certs/nw-ca-all.pem"                 # trusted inside the runner image
export PIP_INDEX_URL=https://art.nwie.net/artifactory/api/pypi/pypi/simple
export ZAP_IMAGE=ntr.nwie.net/docker.io/zaproxy/zap-stable
export JUICE_IMAGE=ntr.nwie.net/docker.io/bkimminich/juice-shop
export ZAP_API_KEY=$(openssl rand -hex 24)                        # ZAP refuses API calls without it
```

## 1. Python environment and offline checks (no Podman yet)

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements-dev.txt
podman-compose --version || python -m pip install podman-compose
ruff check .
python -m pytest -q
```

**Pass:**
- `pip` finishes with `Successfully installed ...` and no errors.
- `podman-compose --version` prints a version. If it doesn't, run it again after the install.
- `ruff` prints `All checks passed!`
- `pytest` ends with `... passed, 3 skipped`, with **0 failed**. The 3 skipped tests check POSIX
  file permissions, which Windows doesn't have.

## 2. Podman VM proxy repair, NTR login, and image pull

Before you start: this script restarts the Podman VM and runs `wsl --shutdown`, which stops
**every** WSL distribution. Save any work you have open in WSL first.

```bash
podman login ntr.nwie.net -u <your-nwie-userid>
bash ./prepull_playwright_podman_nationwide.sh
```

**Pass:**
- `podman login` prints `Login Succeeded!`
- The script ends with `SUCCESS: all required demo images are cached in Podman`

## 3. Replay: log in through Playwright and ZAP

```bash
ZAP_API_ALLOW='.*' bash ./demo_replay_flow.sh
```

The first run builds the runner image, which takes a few minutes. Later runs print
`Using cache` for most steps.

**Pass:**
- The build shows `STEP 1/16` through `STEP 16/16`. If it builds anything, it prints
  `Looking in indexes: https://art.nwie.net/artifactory/api/pypi/pypi/simple`.
- `services ready: zap=http://zap:8080 target=http://juice:3000`
- The result JSON shows `"authenticated": true`, `"whoami_status": 200`, and `"blocked": 0`.
- `out/replay-evidence/` lists `01-login-page.png`, `02-after-login.png`, `03-basket-page.png`,
  and `active-scan.har`.

Next, check that ZAP enforces the API key:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/JSON/core/view/version/   # no key
curl -s -H "X-ZAP-API-Key: $ZAP_API_KEY" http://localhost:8080/JSON/core/view/version/    # with key
```

**Pass:** the first command prints a code other than `200`, because ZAP refuses the call without a
key. The second prints `{"version":"..."}`.

You can also open http://localhost:3000/ to see the Juice Shop app.

## 4. Full scan: replay, spider, active scan, findings, SARIF

Do **not** set `ZAP_API_ALLOW` here. In the full scan, only the runner, at `172.28.0.10`, may call
ZAP.

```bash
bash ./demo_full_scan.sh
```

This takes about 5 minutes.

**Pass:**
- The `gate` JSON shows `"authenticated": true`, `"scope_ok": true`, `"session_alive": true`, and
  `"passed": true`.
- `>> Scan gate exit code: 0`
- `out/coverage.json`, `out/records.json`, and `out/results.sarif` are listed.
- `normalized detections: N`, with N above 0. It was 1349 on 2026-10-02.

Optionally, validate the SARIF file:

```bash
python -c "import json,jsonschema; s=json.load(open('contracts/sarif-2.1.0.schema.json',encoding='utf-8')); d=json.load(open('out/results.sarif',encoding='utf-8')); jsonschema.validate(d,s); print('valid SARIF, results:', sum(len(r['results']) for r in d['runs']))"
```

**Pass:** `valid SARIF, results: N`.

Each run of this script starts the finding lifecycle fresh, so every finding is labelled `new`.

## 5. Clean up the containers

```bash
bash ./cleanup_demo_ports.sh
```

**Pass:** `OK: no stray Podman containers on 3000/8080.`

Step 6 reads only `out/labeled.json`, so publishing still works after cleanup.

## 6. Publish the findings as GitHub Issues

This step does not need GitHub Advanced Security.

### 6a. Create a token (once)

1. Open https://github.com/settings/personal-access-tokens/new (a fine-grained token).
2. **Resource owner:** the organization that owns your sandbox repository, for example
   `NationwideSandbox`.
3. **Expiration:** short, for example 7 or 30 days.
4. **Repository access:** "Only select repositories", then pick the sandbox repository.
5. **Repository permissions:** set **Issues** to **Read and write**. GitHub adds
   **Metadata: Read-only** automatically. Nothing else is needed.
6. Click **Generate token** and keep the page open; you paste the token in 6b.

If the organization has to approve fine-grained tokens, the token stays "pending" until an org
owner approves it, and step 6b returns a 403 until then. If fine-grained tokens aren't allowed at
all, use a classic token with the `repo` scope. If the org uses SSO, click
**Configure SSO → Authorize** next to the token.

### 6b. Plan, publish, and check

```bash
export SSL_CERT_FILE="$HOME/certs/nw-ca-all.pem"   # lets host Python trust the proxy for api.github.com
read -rs GITHUB_TOKEN && export GITHUB_TOKEN        # paste the token and press Enter; nothing is shown
OWNER=<sandbox-owner>; REPO=<sandbox-repo>

# 1. Plan only: reads the repo's issues and changes nothing
python -m detections.github_issues out/labeled.json --app-id juice-shop \
  --owner "$OWNER" --repo "$REPO" --dry-run
```

`read -rs` waits silently. After you paste and press Enter, the prompt comes back with nothing
printed. That is expected.

**Pass:** `issues (<owner>/<repo>): would create N`, followed by one line per issue. N was 10 for
Juice Shop on 2026-10-02.

```bash
# 2. Publish: takes about 1 second per issue
python -m detections.github_issues out/labeled.json --app-id juice-shop \
  --owner "$OWNER" --repo "$REPO"

# 3. Run it again: matches the issues it just created, so creates no duplicates
python -m detections.github_issues out/labeled.json --app-id juice-shop \
  --owner "$OWNER" --repo "$REPO"
```

**Pass:**
- The first run prints `create N`.
- `https://github.com/<owner>/<repo>/issues?q=label%3Adast` shows N issues. Each one lists its
  affected locations and how to fix them.
- The second run prints `nothing to change`.

Optional: after another `bash ./demo_full_scan.sh`, the same command prints `update N`. That means
it rewrote the same issues for the new scan rather than creating new ones.

Add `--min-severity medium` to leave out low and informational findings.

## 7. Optional: upload to the GitHub Security tab (needs Advanced Security)

Code scanning on private and internal repositories requires GitHub Advanced Security. Without it,
this step fails with `403: Advanced Security must be enabled for this repository`, which is the
expected result on `NationwideSandbox`. To upload to a repository that does have it, the token
needs **Code scanning alerts: Read and write**:

```bash
BRANCH=main
SHA=$(git ls-remote "https://github.com/$OWNER/$REPO" "refs/heads/$BRANCH" | cut -f1)
python -m detections.github_upload out/results.sarif \
  --owner "$OWNER" --repo "$REPO" --ref "refs/heads/$BRANCH" --commit "$SHA"
```

**Pass:** `uploaded: id=...`. A few minutes later, the alerts appear under
**Security → Code scanning** in the `dast/juice-shop` category.

## 8. Optional: show where the LLM helps (semantic-gate lab)

This compares exploration with and without the LLM on `labs/semgate`, a small lab app. Its
`/gate` page asks a new arithmetic question on every load, and three `/vault/*` pages return 403
until the question is answered. No value in `app.yaml` can pass it, so only an explorer that reads
the question gets through. On ordinary apps such as Juice Shop the two runs tie or the
deterministic run is ahead, because their forms accept any input.

The lab is plain Python and runs on your workstation. This step needs no Podman, ZAP or image
build. It does need the Playwright browser on the workstation and the Copilot CLI:

```bash
export NODE_EXTRA_CA_CERTS="$HOME/certs/nw-ca-all.pem"   # lets the Playwright download trust the proxy
python -m playwright install chromium
export LLM_PROVIDER=copilot
read -rs COPILOT_GITHUB_TOKEN && export COPILOT_GITHUB_TOKEN   # paste the token; it is not echoed
python -c "from authoring import llm_backend; print(llm_backend.provider(), llm_backend.available())"
```

**Pass:** the last command prints `copilot True`. If it prints `False`, `copilot` is not on `PATH`;
see `docs/dast_poc_phase2_demo_runbook.md` §1.7.

Pick any test account name and password for the lab. They exist only in the lab process:

```bash
export SEMGATE_USER=lab-user
read -rs SEMGATE_PASS && export SEMGATE_PASS
python -m labs.semgate.server --port 8084 &       # prints: semgate listening on http://0.0.0.0:8084
```

Run both arms. `--zap-proxy ""` explores directly, without ZAP, and `--no-replay` skips the replay
check, which needs ZAP:

```bash
python -m dast author semgate --explore --no-llm --zap-proxy "" --no-replay
python -m dast author semgate --explore --require-llm --zap-proxy "" --no-replay
kill %1                                            # stop the lab
```

**Pass:** compare the first JSON block each run prints:

| Field | `--no-llm` | `--require-llm` |
|---|---|---|
| `pages` | 3 | 6 |
| `submits` / `inferred_submits` / `accepted_submits` | 0 / 0 / 0 | 1 / 1 / 1 |
| `steps_by_source` | only `fallback` | mostly `llm` |

The deterministic run reaches `/gate` and stops there. The LLM run reads the question, enters an
answer, and the lab accepts it (`accepted_submits: 1`), so the three `/vault/*` pages are walked.
The field the model may fill is declared in `security/dast/semgate/app.yaml` under
`explore.inferred_fields` with the shape `^[0-9]{1,3}$`. A value outside that shape, or for any
other field, is refused before anything is sent. `--require-llm` stops with an error if Copilot is
unreachable, so a `--require-llm` run that completes did use the model.

This is a lab result. It shows the capability, not a benefit on a Nationwide application; that
depends on whether the application has forms a fixed test value cannot pass.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `git pull` says "Already up to date", but your code is old | You pulled from the upstream remote, not the fork | `git remote -v`, then pull from the remote that points at `NationwideDevin` (step 0) |
| `The repository owner has an IP allow list enabled` | You are off the Nationwide network | Connect to the network or VPN |
| `ERROR: file or directory not found: .` from pytest | You ran `pytest -q.` with a trailing dot | `python -m pytest -q` |
| Tests fail with `UnicodeDecodeError` or `environment variable is longer than 32767 characters` | Old code | Pull again (step 0) |
| `CA bundle not found` or `must be PEM text` | `DAST_CA_BUNDLE` is wrong | Point it at the Nationwide PEM file (see Prerequisites) |
| `CERTIFICATE_VERIFY_FAILED` during `pip install` in the image build | The CA was not staged | Check `DAST_CA_BUNDLE` and rerun. `certs/corporate-ca.crt` should exist after the build starts. |
| `403 ... files.pythonhosted.org` in the image build, or the build shows `STEP x/15` | Old code, or `PIP_INDEX_URL` points at pypi.org | Pull again, and `export PIP_INDEX_URL=https://art.nwie.net/artifactory/api/pypi/pypi/simple` |
| `CERTIFICATE_VERIFY_FAILED` from `pip` on the host (step 1) | Host pip doesn't trust the proxy | Add `--cert "$DAST_CA_BUNDLE"` to the `pip install` command |
| NTR pull says `unauthorized` | Not logged in to NTR | `podman login ntr.nwie.net -u <your-nwie-userid>` |
| Juice Shop pull fails with `manifest unknown` or `not found` on `ntr.nwie.net` | NTR has no Juice Shop mirror | `unset JUICE_IMAGE` and rerun. The script falls back to the pinned Docker Hub digest. |
| `stale 127.0.0.1:8888 proxy remains in the Podman VM` | The proxy repair didn't stick | Rerun step 2. If it still fails, send the diagnostics the script prints. |
| `podman-compose: command not found` | Not installed in this terminal's venv | `source .venv/Scripts/activate && python -m pip install podman-compose` |
| `address already in use` on 3000 or 8080 | A previous run is still up | `bash ./cleanup_demo_ports.sh` |
| `cannot reach ZAP`, or a 403 from ZAP during the full scan | The runner didn't get `172.28.0.10` | Run `bash ./cleanup_demo_ports.sh`, then retry. If it fails again, send `podman network inspect ssd-dast-poc_dast`. |
| `ModuleNotFoundError: No module named 'detections'` | You are not in the repo root, for example inside `*.git` | `cd ~/poc-work/ssd-dast-tool-poc` |
| `SSL: CERTIFICATE_VERIFY_FAILED` when calling `api.github.com` | Host Python doesn't trust the proxy | `export SSL_CERT_FILE="$HOME/certs/nw-ca-all.pem"` |
| `403: Resource not accessible by personal access token` | The token lacks **Issues: Read and write**, is still pending approval, or has a different resource owner | Fix the token (6a) and run `read -rs GITHUB_TOKEN && export GITHUB_TOKEN` again |
| `401: Bad credentials` | Token expired, revoked, or mistyped | Create a new token and enter it again |
| `404` from the Issues API | `OWNER` or `REPO` is wrong, or the token can't see the repo | Check the spelling and the token's repository access |
| `410: Issues has been disabled` | Issues are turned off in the repo | Settings → General → Features → Issues |
| `403: Advanced Security must be enabled` | Expected without GitHub Advanced Security | Use step 6 instead |

## If you need help

Send all of the following:

- the full output of the step that failed;
- `git log -1 --oneline`;
- `python --version`;
- `podman version`.

Never include a token.

## What the steps prove

- **Steps 1–5:** the scanner builds and runs inside Nationwide. That covers Podman, the proxy, NTR,
  the corporate CA, and Artifactory. ZAP enforces its API key, and the scan logs in, stays in
  scope, and produces findings and valid SARIF.
- **Step 6:** developers can see and track the findings in GitHub without Advanced Security.
  Reruns update the same issues instead of duplicating them.
- **Step 8:** the LLM is the only arm that gets past a form needing a reasoned answer, within the
  bounds set in `app.yaml`. The scan itself never uses the model.
- **Next:** onboarding a real lower-environment application. That needs the app's `app.yaml`, its
  host in `environments.yaml`, approvals, and a test account. See
  `docs/onboarding_a_new_application.md`.

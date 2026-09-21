# Playwright `record` — Demo & Screen-Recording Runbook

A focused runbook for demoing the **Playwright-driven `record` step** (the Phase 2 canonical
authoring beat) and capturing it on video. A real Chromium browser registers + logs into OWASP
Juice Shop and walks an authenticated page, while the tool captures every navigation, form, and
API call into `trace.json`.

**The point to land:** the login journey that later drives the scan is captured by *automation*,
not hand-typed — and no credentials or tokens ever land in the recorded trace.

Companion docs: `dast_poc_phase2_demo_script.md` (the full Phase 2 flow this is a slice of),
and `dast_poc_requirements.md` (requirements). Everything here is verified against the
`ssd-dast-tool-poc` repository.

---

## 0. One-time prep (10 min before, off-camera)

Run the image and Podman-machine preparation from **Git Bash**. The supplied
`prepull_playwright_podman_nationwide.sh` script removes stale `127.0.0.1:8888`
proxy configuration from the Podman VM, restarts the machine, and verifies that the
Playwright and Nationwide ZAP images are cached.

Use Git Bash only for the following block. After it completes, switch to a PowerShell
terminal for the remaining commands; do not paste the PowerShell commands into Git Bash.

```bash
cd /c/Users/yangq4/poc-work/ssd-dast-tool-poc
bash ./prepull_playwright_podman_nationwide.sh
```

The script may run `wsl.exe --shutdown` while repairing the Podman machine. This stops
all WSL distributions, so run it before the demo rather than during a recording.

The recording command runs on the Windows host, so create the repository virtualenv and
install the actual runtime requirements separately:

```powershell
cd C:\Users\yangq4\poc-work\ssd-dast-tool-poc

# Create the venv only when it does not already exist. Do not delete an active .venv;
# VS Code's Python language server may have its interpreter open.
if (-not (Test-Path .venv\Scripts\python.exe)) { py -3.12 -m venv .venv }

# Clear stale proxy variables for this process; do not use --trusted-host.
Remove-Item Env:HTTP_PROXY,Env:HTTPS_PROXY,Env:http_proxy,Env:https_proxy,Env:ALL_PROXY,Env:all_proxy,Env:SOCKS_PROXY,Env:socks_proxy -ErrorAction SilentlyContinue

# Use the approved public PyPI fallback when the configured Artifactory index reports
# SSLEOF/TLS errors. Certificate verification remains enabled.
.venv\Scripts\python.exe -m pip install -r requirements.txt

# Playwright's Node-based browser downloader needs the Nationwide CA bundle when the
# corporate TLS inspection chain is not in Node's default trust store. The bundle must
# be PEM text containing the corporate CA certificates (not a Java/.NET truststore).
# Obtain nw-ca-all.pem through the approved internal certificate process first.
$env:NODE_EXTRA_CA_CERTS = $null
$env:NODE_EXTRA_CA_CERTS = "C:\Users\yangq4\nw-ca-all.pem"
if (-not (Test-Path $env:NODE_EXTRA_CA_CERTS)) { throw "Missing PEM bundle: $env:NODE_EXTRA_CA_CERTS" }
if ((Select-String -Path $env:NODE_EXTRA_CA_CERTS -Pattern "BEGIN CERTIFICATE" | Measure-Object).Count -lt 1) {
  throw "NODE_EXTRA_CA_CERTS must point to a PEM bundle containing certificates"
}
.venv\Scripts\python.exe -m playwright install chromium
```

The explicit `--index-url` is needed when the user-level pip configuration points to
`https://art.nwie.net/artifactory/api/pypi/pypi/simple` but that endpoint cannot complete
TLS. It leaves pip certificate verification enabled and does not modify the user-level pip
configuration. `NODE_EXTRA_CA_CERTS` applies to the current PowerShell process and fixes the
Playwright download; it must be set **before** the install command. A malformed value, such as
a path copied with literal quote characters or a non-PEM truststore, produces warnings like
`Ignoring extra certs ... no protocol option` and the download falls back to
`UNABLE_TO_GET_ISSUER_CERT_LOCALLY`. If a previous failed setup left `.venv` locked, reload the
VS Code window or close the Python language server before recreating the environment; never
remove an active `.venv` from a running workspace.

After image preparation finishes, start Juice Shop and ZAP with **Podman Compose**:

```powershell
cd C:\Users\yangq4\poc-work\ssd-dast-tool-poc

podman machine start podman-machine-default
podman-compose -f compose.yaml -f compose.demo.yaml up -d juice zap

# Services must be up. Confirm (want 200 from each):
(Invoke-WebRequest -UseBasicParsing http://localhost:3000).StatusCode
(Invoke-WebRequest -UseBasicParsing http://localhost:8080/JSON/core/view/version/).StatusCode

# venv + Chromium ready:
.venv\Scripts\python.exe -c "from playwright.sync_api import sync_playwright as s; b=s().start().chromium.launch(); b.close(); print('chromium ok')"
```

If `podman-compose` is unavailable, install or enable the Podman Compose provider supplied
by your Podman Desktop setup. Do not use `docker compose` for this runbook.

The `compose.demo.yaml` overlay is required here: the base `compose.yaml` keeps the services
on the internal network but does not publish ports to the Windows host.

The prep script pulls the Nationwide ZAP mirror as
`ntr.nwie.net/docker.io/zaproxy/zap-stable`. The checked-in `compose.yaml` still references
the pinned public ZAP digest for reproducibility, so Podman Compose will use that exact
compose image unless your environment maps or overrides it. The prep script's cached
Playwright image is not used by the host-side `authoring.record` command; that command uses
the `.venv` and Chromium installed above. Confirm both services are running before continuing.

Wait for the services to become ready, then re-run the two HTTP checks above if needed.

Do one **throwaway headed run** before you record, so Chromium is warm and the real take is snappy:

```powershell
$env:AUTH_EMAIL = "warmup@juice-sh.op"
$env:AUTH_PASSWORD = "Dast-Demo-passw0rd!"
.venv\Scripts\python.exe -m authoring.record --app-id juice-shop --base-url http://localhost:3000 `
  --out-dir out/pw-demo/warmup --headed --slow-mo 700
```

---

## 1. What to open (screen layout)

- **One Terminal window**, large font — this is what you type in.
- **Do NOT open Chrome yourself.** Playwright launches its own Chromium when you pass `--headed`;
  that window is the star of the recording.
- *(Optional opening beat)* a normal browser tab at `http://localhost:3000` to say "here's the
  target app," then close it so it isn't confused with the Playwright window.
- Position the Terminal and the center of the screen (where Chromium pops up) so both are visible.

---

## 2. Start the screen recording (Windows)

1. Press **Win+G** to open Xbox Game Bar.
2. Open the **Capture** widget and choose **Record**. Enable the microphone if you want to
  narrate live.
3. Keep the terminal and Playwright Chromium window visible while recording.
4. To stop, press **Win+Alt+R**. The recording is saved under `Videos\Captures` by default.

Alternative: use the Windows Snipping Tool screen recorder.

---

## 3. The command to run (the recorded moment)

With the recording rolling, in the Terminal:

```powershell
cd C:\Users\yangq4\poc-work\ssd-dast-tool-poc

# 1) Credentials = your "login". Fresh email each take so the register step visibly succeeds,
#    and a policy-compliant password (weak ones fail — see Gotchas).
$env:AUTH_EMAIL = "dast-demo-$((Get-Date).ToString('HHmmss'))@juice-sh.op"
$env:AUTH_PASSWORD = "Dast-Demo-passw0rd!"

# 2) Clean the output folder so the "files created" beat is convincing
Remove-Item -Recurse -Force out/pw-demo/trace -ErrorAction SilentlyContinue

# 3) THE demo command — headed + slowed down so the audience can follow each action
.venv\Scripts\python.exe -m authoring.record `
  --app-id juice-shop `
  --base-url http://localhost:3000 `
  --out-dir out/pw-demo/trace `
  --headed --slow-mo 700
```

`--slow-mo 700` delays each browser action by 700 ms so the login is watchable; it does **not**
change the captured trace. Bump to `1000`+ for an even slower walkthrough, drop it for full speed.

**What appears on screen (in order):** a Chromium window opens → Juice Shop landing page (welcome
banner) → navigates to the **login** page → the **email/password fields fill themselves** → clicks
Login → briefly lands on the **basket** page → the window closes. With `--slow-mo 700` this is a
comfortable ~15–20s.

**Success line in the Terminal:**

```text
recorded: 6 interactions, 22 api calls, hosts=['localhost'] -> out/pw-demo/trace/trace.json
```

---

## 4. Show the artifact it produced (still recording)

```powershell
Get-ChildItem out/pw-demo/trace                                # -> index.json  trace.json
.venv\Scripts\python.exe -m json.tool out/pw-demo/trace/trace.json | Select-Object -First 40
```

**Say:** "Every page, form field name, and `/rest/`·`/api/` call is captured — and notice there
are **no passwords or tokens** in this file; credentials came from environment variables, never the
trace." Then **stop the recording** (Win+Alt+R).

---

## 5. Folder layout (what lives where)

```text
 C:\Users\yangq4\poc-work\ssd-dast-tool-poc\
├─ out/pw-demo/
│  ├─ trace/            <- record output: trace.json, index.json  (regenerated each take)
│  ├─ warmup/           <- throwaway warm-up run
│  └─ recordings/       <- your .mov screen recordings (if you saved here)
└─ .venv\               <- the Python you must call as .venv\Scripts\python.exe
```

`out/` is gitignored, so traces and recordings are never committed.

---

## 6. Reset between takes

```powershell
Remove-Item -Recurse -Force out/pw-demo/trace -ErrorAction SilentlyContinue
$env:AUTH_EMAIL = "dast-demo-$((Get-Date).ToString('HHmmss'))@juice-sh.op"   # fresh email => register visibly succeeds
```

Reusing the same email still works (register no-ops, login proceeds) — a new email just makes the
"new user registered" beat clean.

---

## 7. Gotchas (all verified)

- **Password policy is real.** `Passw0rd!` **times out at the login step** (`wait_for_function`
  never sees a token) because Juice Shop rejects it / it mismatches an existing account. Use a
  strong password like `Dast-Demo-passw0rd!`. This is the #1 thing that sinks a live take.
- **Use `.venv\Scripts\python.exe`, not bare `python`.** The project dependencies must be installed in
  the repository's `.venv`.
- **Headed browser needs a real display** — fine on the laptop; it will **not** work from inside a
  container.
- **`--base-url http://localhost:3000` is correct here** because `record` talks to Juice Shop
  **directly** (no ZAP proxy). Only the later scan steps use `http://juice:3000` through ZAP.
- **First launch can lag** a second or two while Chromium warms — that's what the §0 warm-up run is
  for.

---

## 8. One-line talking track (if you need it)

> "This is the same Playwright runtime the scanner uses. Watch it register a user, log in, and land
> on an authenticated page — all driven by code. What it writes out is `trace.json`: the pages,
> forms, and API calls it saw, with zero secrets in it. That trace is what `generate` turns into the
> `flow.py` the scanner replays — so the authenticated journey is captured by automation, not typed
> by an engineer."

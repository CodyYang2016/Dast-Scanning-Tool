# Phase 2 — Complete Step-by-Step Demo Runbook (macOS + Windows)

This is the **operator's runbook** for the whole Phase 2 demo: every window to open, every
command to run, every click, what appears on screen, and what to say — in order. It merges the
Phase 2 script (`dast_poc_phase2_demo_script.md`, which has the talking points and Q&A) with
the Playwright screen-recording runbook (`dast_poc_playwright_demo_runbook.md`) and works on
**both** demo machines: the **macOS laptop** (Docker Desktop, `$PY`) and the
**Windows workstation** (Git Bash + Podman in WSL, `.venv/Scripts/python`, images via the
Nationwide Trusted Registry). Every command below is bash — on Windows run them in **Git Bash
(MINGW64), never PowerShell or cmd**.

**Story to land:** Phase 1 proved the scanner is safe. Phase 2 proves (a) the `flow.py` that
drives it can be *recorded and generated* — with an LLM that only ever emits data, never code —
and (b) findings flow deterministically out of our JSON into SARIF and GitHub's Security tab.

**Total on-stage time:** ~18–22 min (the live scan in Part G is ~3–4 min of that).

**Verification status:** the whole chain in this runbook (§1.3 health checks → record through ZAP →
generate → idempotency → validate live replay → runner gate → SARIF) was executed end-to-end on
the mac on 2026-09-19 with the commands exactly as written; every SEE block shows that run's
output. Windows-specific lines come from the day-1 runbook's Podman appendix and have not been
re-run there — do the §1 pre-flight on the Windows box the day before.

Legend used below:
**OPEN** = a window/tab/file to have on screen · **RUN** = type this in the named Terminal ·
**CLICK** = a mouse action · **SEE** = what success looks like · **SAY** = the talking line.

---

## Platform card — paste this FIRST in every terminal you open

The commands in this runbook use three shell variables so the same line works on both
machines. Paste the block for your OS as the **first thing in Terminal A and Terminal B**
(they are per-shell; a new tab needs it again).

**macOS (Docker Desktop):**
```bash
cd /Users/codyyang/Dast-Scanning-Tool
PY=.venv/bin/python
CT=docker                                   # container tool
JUICE_IMG=bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e
ZAP_IMG=zaproxy/zap-stable@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef
```

**Windows (Git Bash + Podman):**
```bash
cd /c/Users/yangq4/playground/Warbler-Tech/Dast-Scanning-Tool     # adjust if your checkout differs
PY=.venv/Scripts/python
CT=podman
JUICE_IMG=ntr.nwie.net/docker.io/bkimminich/juice-shop           # NTR mirror (day-1 runbook, Appendix A)
ZAP_IMG=ntr.nwie.net/docker.io/zaproxy/zap-stable
```

| Differs by OS | macOS | Windows |
|---|---|---|
| Container runtime | Docker Desktop (`open -a Docker`) | Podman machine (`podman machine start`); corporate proxy fix in `dast_poc_day1_runbook.md` App. A2 |
| Python | `.venv/bin/python` (3.12 via Homebrew) | `.venv/Scripts/python` (3.11+; create with `py -3.12 -m venv .venv` if missing) |
| Images | Docker Hub, pinned by digest (`versions.lock`) | `ntr.nwie.net/docker.io/...` by tag (`podman login ntr.nwie.net` first) |
| Switch windows | ⌘Tab | Alt+Tab |
| VS Code Markdown preview | ⇧⌘V | Ctrl+Shift+V |
| Screen recording | ⌘⇧5 (built-in), stop with ⌘⌃Esc | Win+Alt+R (Xbox Game Bar) or Snipping Tool → *Record* (Win+Shift+S → Record); stop with Win+Alt+R again |
| Terminal font | Terminal/iTerm → ⌘+ to enlarge | Git Bash window → right-click title bar → Options → Text |
| Chromium headed window | appears center-screen | same; if it doesn't, check `$PY -m playwright install chromium` ran on **this** machine |

---

## 0. The day before — one-time environment facts (macOS rows verified 2026-09-19; Windows rows from the day-1 runbook)

| Fact | Detail | Why it matters |
|---|---|---|
| Python | `$PY` = the repo venv (mac: 3.12.14; win: 3.11+) with playwright 1.62.0, anthropic, jsonschema, pytest | bare `python`/`python3` is the wrong interpreter on both machines (mac ships 3.9; Windows may pick the Store stub) — **always** use `$PY` |
| Tests | `$PY -m pytest -q` → **188 passed** in <1s | your fallback evidence (§9) |
| Container tool (mac) | Docker Desktop is at `/Applications/Docker.app`, **but** `/usr/local/bin/docker` is a broken symlink (→ `/Volumes/Docker 1/…`), so `docker` is **not on PATH** in a fresh shell | fix once, see below |
| Container tool (win) | Podman runs in a WSL VM; the VM ships a dead `127.0.0.1:8888` proxy that breaks pulls | one-time fix: `dast_poc_day1_runbook.md` Appendix A2; pull images the day before |
| Compose file | `compose.yaml` (project `ssd-dast-poc`) does **not publish ports** for `juice`/`zap` — it's for the all-in-container runner | for a host-side demo you need `localhost:3000` / `localhost:8080`, so start juice+zap with `$CT run -p …` (README "Option B"), not compose |
| GitHub | mac: `gh` is logged in as `CodyYang2016`; remote = `github.com/CodyYang2016/Dast-Scanning-Tool`; Security tab already has 38 alerts from the fixture upload on 2026-09-12. win: run `gh auth status` the day before | live SARIF upload works from the mac; on Windows only if `gh` is authenticated and the enterprise repo has code scanning enabled |
| LLM key | `ANTHROPIC_API_KEY` is **not** set in the shell | fallback path is the default; export the key only if you choose to demo the LLM path (§5b) |
| Old script drift | The Phase 2 script mentions `podman-compose`, `compose.demo.yaml`, `cleanup_demo_ports.sh`, `demo_full_scan.sh`, `/c/Users/yangq4/…` — **none of these exist here** | ignore them; this runbook has the real commands |

### macOS only — fix the `docker` command once

```bash
sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker
docker --version        # should print a client version now
```

(If you'd rather not touch `/usr/local/bin`, put `alias docker=/Applications/Docker.app/Contents/Resources/bin/docker` in `~/.zshrc`.)

### Windows only — Podman + venv once

```bash
podman machine start                        # then: podman ps must answer
podman login ntr.nwie.net -u <your-nwie-userid>
py -3.12 -m venv .venv 2>/dev/null || python -m venv .venv      # skip if .venv exists
.venv/Scripts/python -m pip install -r requirements-dev.txt
.venv/Scripts/python -m playwright install chromium
```

If a pull fails with `proxyconnect tcp: dial tcp 127.0.0.1:8888`, do the one-time WSL proxy
fix in `dast_poc_day1_runbook.md` Appendix A2 — it costs hours if discovered on demo day.

### Both — pull images ahead of time (slow on a cold network — don't do this live)

```bash
$CT pull $JUICE_IMG
$CT pull $ZAP_IMG
```

On macOS these are the digests pinned in `versions.lock` (NFR-1); on Windows the NTR mirror
serves the same upstream images by tag.

---

## 1. T-15 minutes — pre-flight (off camera)

### 1.1 Start the container runtime

**macOS — OPEN Docker Desktop:** **CLICK** Launchpad → **Docker** (or `open -a Docker`). Wait
for the whale icon in the menu bar to stop animating. If Docker Desktop shows an **error
dialog** on launch (it did once on 2026-09-18), click **Restart** / quit and relaunch it.

**Windows — RUN** `podman machine start` in Git Bash (`podman machine list` shows `Currently
running`).

Don't proceed until this answers:
```bash
$CT ps      # must NOT say "Cannot connect to the Docker daemon" / "unable to connect to Podman"
```

**If the containers already exist from a previous session** (`$CT ps -a` shows `juice` and `zap`
on network `dast`, Exited), you can just `$CT start juice zap` and skip to 1.3 — that's what was
done for the 2026-09-19 verification run.

### 1.2 RUN — start Juice Shop + ZAP with ports published (Terminal A)

```bash
# (platform card already pasted)
# clean slate: remove anything left from a previous session
$CT rm -f juice zap 2>/dev/null; $CT network rm dast 2>/dev/null

$CT network create dast
$CT run -d --name juice --network dast -p 3000:3000 $JUICE_IMG
$CT run -d --name zap --network dast -p 8080:8080 $ZAP_IMG \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true
```

Keep the single quotes around `'api.addrs.addr.name=.*'` — Git Bash globs `.*` otherwise, and
without that flag ZAP answers every host call with `curl: (52) Empty reply`.

Why these exact names: `runner`, `validate`, and the app `scope.json` all address the target as
**`juice:3000`** — the container name is the DNS name ZAP resolves on the `dast` network (D7).

### 1.3 RUN — confirm all three health checks (want `200 200 200`)

ZAP takes ~20–40 s to come up. Re-run until all three are 200:

```bash
curl -s -o /dev/null -w "juice-from-host %{http_code}\n" http://localhost:3000
curl -s -o /dev/null -w "zap-api        %{http_code}\n" http://localhost:8080/JSON/core/view/version/
$CT exec zap curl -sS -m10 -o /dev/null -w "juice-from-zap %{http_code}\n" http://juice:3000/
```

The third one is the important one: it proves ZAP can reach `juice` on the docker network,
which is exactly what `wait_ready()` in `runner/main.py` checks before scanning.

### 1.4 RUN — venv + Chromium + tests

```bash
$PY -c "from playwright.sync_api import sync_playwright as s; b=s().start().chromium.launch(); b.close(); print('chromium ok')"
$PY -m pytest -q          # SEE: 188 passed
```

### 1.5 RUN — clean scratch dir + pick demo credentials

```bash
rm -rf out/phase2-demo && mkdir -p out/phase2-demo

# One identity for the WHOLE demo. record registers this user; validate + runner only LOG IN
# (the generated flow.py has no register step), so never change these mid-demo.
export AUTH_EMAIL="dast-demo-$(date +%H%M%S)@juice-sh.op"
export AUTH_PASSWORD="Dast-Demo-passw0rd!"
echo "$AUTH_EMAIL"                      # note it down; you'll re-export it in Terminal B
```

**Do NOT** use `dast-poc@juice-sh.op` + `Passw0rd!` from the old script: that email already
exists in Juice Shop with a *different* password (the hand-authored Phase 1 flow registers it
with `Dast-POC-passw0rd!`), so login times out at `wait_for_function` — the #1 thing that sinks
a live take. A fresh timestamped email sidesteps it.

### 1.6 RUN — warm-up headed record (throwaway, so Chromium is snappy on camera)

```bash
$PY -m authoring.record --app-id juice-shop \
  --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --out-dir out/phase2-demo/warmup --headed --slow-mo 300
```

**SEE** a Chromium window open, log in, land on the basket, close; Terminal prints
`recorded: 6 interactions, 22 api calls, hosts=['juice'] -> out/phase2-demo/warmup/trace.json`.

> **`hosts=['juice']` is required.** If you record with `--base-url http://localhost:3000` and
> no `--zap-proxy` (as the Playwright-only runbook does), the trace says `hosts=['localhost']`,
> `generate` seeds `scope.json`'s allow-list with `localhost`, and then `validate`/`runner`
> (which go through ZAP to `juice:3000`) get **blocked by the scope guard**. The Phase 2 demo
> must record *through ZAP* so the generated scope matches the runner topology.

### 1.7 Decide: fallback or LLM path for `generate`

- **Fallback (recommended for a live audience):** do nothing; `--no-llm` is used in §5.
- **LLM path:** `export ANTHROPIC_API_KEY=sk-ant-…` in Terminal A now, and do a dry run of §5b
  before the audience arrives so you know the network is fine.

---

## 2. Screen layout — what to have open

| Window | Where | Used in |
|---|---|---|
| **Terminal A** (mac: Terminal/iTerm; win: **Git Bash**; large font, platform card pasted, `AUTH_EMAIL`/`AUTH_PASSWORD` exported) | left half | the pipeline: record → generate → validate → runner |
| **Terminal B** (same kind of shell, platform card pasted, same two exports) | right half, or a second tab | inspection: `cat`/`diff`/`curl` ZAP, fixture pipeline |
| **Browser tab 1** — the Phase 2 script rendered with its Mermaid diagrams: open `docs/dast_poc_phase2_demo_script.md` in VS Code and press **⇧⌘V** (mac) / **Ctrl+Shift+V** (win) for Markdown preview, or use `https://github.com/CodyYang2016/Dast-Scanning-Tool/blob/main/docs/dast_poc_phase2_demo_script.md` | full-screen for Part A, then hidden | Part A |
| **Browser tab 2** — `https://github.com/CodyYang2016/Dast-Scanning-Tool/security/code-scanning` | hidden until Part B / H | Part B, H |
| **Browser tab 3** — `http://localhost:3000` (Juice Shop, just to show "the target") | shown once, then **closed** so it isn't confused with Playwright's window | Part D opener |
| **Playwright's own Chromium window** | pops up center-screen during `record --headed`; **do not open Chrome yourself for this** | Part D |

If screen-recording — **mac:** **⌘⇧5** → Options → Save to `out/pw-demo/recordings`
(gitignored), Show Mouse Clicks on → *Record Selected Portion* around Terminal A + the center of
the screen → **Record**; stop with **⌘⌃Esc**. **win:** **Win+Alt+R** starts/stops an Xbox Game
Bar recording of the active window (saved to `Videos\Captures`), or Snipping Tool → *Record* →
drag a region → Start. Turn the microphone on in either if you narrate live.

Export the credentials in Terminal B too (so the inspection commands and §6a work there):

```bash
# (platform card already pasted)
export AUTH_EMAIL="<the email you noted in 1.5>" AUTH_PASSWORD="Dast-Demo-passw0rd!"
```

---

## Part A — Big picture (2 min, no commands)

**OPEN** Browser tab 1 (the rendered Phase 2 script). Scroll to the two Mermaid diagrams under
"Big picture".

**SAY** (diagram 1 — the three phases): "Phase 1 proved the runner can safely authenticate,
stay in scope, and detect a real finding — but its `flow.py` was hand-typed. Today's question:
can we replace that hand-authored file with something recorded and generated, get findings into
SARIF in GitHub's Security tab, and do it without an LLM ever weakening the Phase 1 guarantees?
The answer has to be no-by-construction, not by promise."

**SAY** (diagram 2 — the chain): "The yellow boxes are the only new risk surface — the LLM.
Everything downstream of `validate` — runner, scope guard, normalizer, SARIF — is the exact,
unchanged Phase 1 code. The LLM only emits **data**: a schema-constrained JSON journey plan.
A deterministic renderer turns that into `flow.py`. If the model is unavailable or invalid, a
deterministic fallback builds the plan straight from the recorded trace."

Then switch to the Terminals (⌘Tab / Alt+Tab).

---

## Part B — Deterministic results pipeline first: fixture → SARIF → GitHub (3 min, Terminal B)

Deliberate order: prove the downstream half against a committed fixture *before* anything LLM.

**RUN**
```bash
sed -n '1,40p' contracts/sample_zap_output.json
```
**SAY** "A real, committed ZAP fixture — 38 alerts: 1 High (SQL injection), 14 Medium, 11 Low,
12 Informational. The results pipeline was built and tested against this file before a single
live scan ran."

**RUN**
```bash
$PY -m detections.normalizer contracts/sample_zap_output.json --app-id juice-shop \
  --scan-id demo-fixture-1 -o out/phase2-demo/records.json
head -30 out/phase2-demo/records.json
```
**SEE** a JSON array of records with `rule_id`, `severity`, `endpoint_pattern`, `fingerprint`.
**SAY** "Each record has a rule id, severity, endpoint, parameter, and a stable fingerprint —
the same shape whether alerts came from this fixture or a live scan."

**RUN**
```bash
$PY -m detections.sarif_export out/phase2-demo/records.json --app-id juice-shop \
  --driver-version "ZAP 2.17.0" -o out/phase2-demo/results.sarif
sed -n '1,25p' out/phase2-demo/results.sarif
```
**SEE** `"version": "2.1.0"`, `"$schema": …sarif-schema-2.1.0…`, a `tool.driver` block.
**SAY** "SARIF 2.1.0 — the standard GitHub Code Scanning consumes."

**Upload — choose one:**

- *Narrate only (safest):* show the command, don't run it:
  ```bash
  $PY -m detections.github_upload out/phase2-demo/results.sarif \
    --owner CodyYang2016 --repo Dast-Scanning-Tool --ref refs/heads/main
  ```
  **SAY** "This is a one-way door — it publishes to a real Security tab — so today I'm showing
  the already-uploaded result rather than re-uploading."
- *Live (this repo, `gh` is authenticated):* run the command above. It uses `git rev-parse
  HEAD` as the commit, which **must already be pushed** (`git status` clean, `git push` done).
  **SEE** `uploaded: id=…` and `status url: …`. Processing takes ~30–60 s.

**OPEN** Browser tab 2 (Security tab). **CLICK** *Code scanning* in the left rail if not
already there. **SEE** the alert list; **CLICK** the **High** "SQL Injection" alert to show
severity/CWE and the endpoint as location.
**SAY** "DAST locations are endpoints, not source lines — expected. `partialFingerprints` is
what lets GitHub track the same alert across uploads, which is what makes Phase 3's lifecycle
diff line up with the Security tab."

Switch back to the Terminals.

---

## Part C — The safety architecture (1 min, Terminal B)

**RUN**
```bash
sed -n '1,30p' docs/junior_engineer/authoring_clis_design.md
```
**SAY** "The one design decision that matters most today: `generate` asks the LLM for a
constrained **JSON journey plan**, not Python. The plan is validated against
`journey.schema.json`; only then does deterministic code render `flow.py`, which is
AST-compiled before use. A malformed plan fails loudly here, not inside a live browser."

**RUN**
```bash
cat contracts/journey.schema.json
```
**SAY** "Notice what's *not* here: no code, no shell, no file paths. A login block of selectors
plus a list of `goto` / `click` / `api_get` steps — that's the entire vocabulary the model may
use. `additionalProperties: false` everywhere."

---

## Part D — `record`: a real browser captures the trace (3 min, Terminal A + Playwright window)

*(Optional 10-second opener)* **OPEN** Browser tab 3 (`http://localhost:3000`), **SAY** "Here's
the target — OWASP Juice Shop, an Angular SPA," then **close that tab**.

**RUN** (Terminal A)
```bash
rm -rf out/phase2-demo/trace

$PY -m authoring.record \
  --app-id juice-shop \
  --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --out-dir out/phase2-demo/trace \
  --headed --slow-mo 700
```

**SEE** (in order, ~15–20 s): a Chromium window opens → Juice Shop landing page (welcome
banner) → navigates to **#/login** → **email/password fields fill themselves** → Login click →
lands on **#/basket** → window closes. Terminal prints:
```
recorded: 6 interactions, 22 api calls, hosts=['juice'] -> out/phase2-demo/trace/trace.json
```

**SAY** (while it runs) "This is the same Playwright runtime the scanner uses, proxied through
ZAP exactly like the runner. It registers a test user, logs in via the real form, and visits an
authenticated page. Every navigation, form field, and `/rest/`·`/api/` XHR is captured as a raw
event; `build_trace` — a pure, unit-tested function — turns those into a schema-valid trace.
`--slow-mo 700` only slows the browser so you can watch; it doesn't change the trace."

**RUN**
```bash
ls -1 out/phase2-demo/trace/                       # SEE: index.json  trace.json
$PY -m json.tool out/phase2-demo/trace/trace.json | sed -n '1,40p'
grep -n -i "password" out/phase2-demo/trace/trace.json          # SEE: only "#password" / "field": "password"
grep -c "$AUTH_PASSWORD" out/phase2-demo/trace/trace.json || echo "password VALUE not in trace"
```
**SAY** "Hosts, page index, interactions, forms, API calls. The word `password` appears only as
a **field name** and a selector — the value never does, and there's no token. Credentials came
from environment variables; the trace only knows what to fill, not what with."

---

## Part E — `generate`: trace → plan → `flow.py` + scan config (3 min, Terminal A/B)

### 5. Deterministic fallback path (run this one live)

**RUN** (Terminal A)
```bash
$PY -m authoring.generate --trace out/phase2-demo/trace/trace.json \
  --out-dir out/phase2-demo/gen --no-llm
```
**SEE**
```json
{ "plan_source": "fallback", "journey_steps": <n>, "out_dir": "out/phase2-demo/gen" }
```
**SAY** "`--no-llm` forces the deterministic fallback, `journey_from_trace`: it builds a valid
plan from the trace's routes and GET calls. This is what keeps the pipeline runnable with zero
external dependencies."

**RUN** (Terminal B) — show the plan and all six artifacts:
```bash
cat out/phase2-demo/gen/journey.json
ls out/phase2-demo/gen/            # SEE: auth.json flow.py journey.json lock manifest.json scope.json zap-policy.yaml
cat out/phase2-demo/gen/scope.json
cat out/phase2-demo/gen/auth.json
cat out/phase2-demo/gen/zap-policy.yaml
cat out/phase2-demo/gen/manifest.json
```
**SEE** `scope.json` → `"fqdn_allow_list": ["juice"]`, `"environment_class": "dev"`;
`auth.json` → only `"email_env": "AUTH_EMAIL"`, `"password_env": "AUTH_PASSWORD"`.
**SAY** "Six artifacts from one trace: the plan, the rendered `flow.py`, a `scope.json` whose
allow-list is seeded from hosts *actually seen* in the trace, `auth.json` holding only env-var
**names**, a ZAP policy, a manifest and a lock."

**SAY (known gap — say it, don't hide it):** "Only `flow.py` and `scope.json` drive the scan
today. `runner/scan.py`'s `configure_policy()` takes a time budget only — it doesn't read
`zap-policy.yaml` yet. `auth.json`, `manifest.json`, `lock` are scaffolding for a future runner
change. Tracked gap, not a demo simplification."

**RUN**
```bash
cat out/phase2-demo/gen/flow.py
```
**SAY** "Same `run(page, base_url)` contract as the hand-authored Phase 1 flow — but every line
was templated from the plan. Credentials are read from env at line 1 of `run`; nothing is
baked in."

### 5a. Idempotency proof (FR-G4) — 20 seconds

**RUN** (Terminal A)
```bash
$PY -m authoring.generate --trace out/phase2-demo/trace/trace.json \
  --out-dir out/phase2-demo/gen2 --no-llm
diff out/phase2-demo/gen/flow.py out/phase2-demo/gen2/flow.py && echo "IDENTICAL"
```
**SEE** no diff output, then `IDENTICAL`.
**SAY** "Same trace, two separate runs, byte-identical `flow.py`. That determinism is what makes
Phase 3's lifecycle diffing trustworthy."

### 5b. (Optional) LLM path — only if `ANTHROPIC_API_KEY` is exported and you dry-ran it in §1.7

**RUN**
```bash
$PY -m authoring.generate --trace out/phase2-demo/trace/trace.json \
  --out-dir out/phase2-demo/gen-llm
cat out/phase2-demo/gen-llm/journey.json
```
**SEE** `"plan_source": "llm"` (default model `claude-opus-4-8`; override with `--model`).
**SAY** "Same command, no `--no-llm`. Claude returns a plan; the exact same schema validation
and AST-compile check apply. If its output doesn't validate, `generate` warns on stderr and
falls back — the demo never hard-fails because a model call had a bad day."

If it prints `generate: LLM path failed (…); using deterministic fallback` — that *is* the
resilience story; say so and move on.

---

## Part F — `validate`: allow-list + live auth replay (2 min, Terminal A)

The replay here is **headless** — no browser window will appear; that's expected.

**RUN** (Terminal A — `AUTH_EMAIL`/`AUTH_PASSWORD` must be the same ones `record` used)
```bash
$PY -m authoring.validate \
  --plan  out/phase2-demo/gen/journey.json \
  --scope out/phase2-demo/gen/scope.json \
  --flow  out/phase2-demo/gen/flow.py \
  --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --report out/phase2-demo/validation-report.json; echo "exit=$?"
```
**SEE**
```json
{ "checks": [ {"name":"allowlist","passed":true,"detail":"all hosts in allow-list"},
              {"name":"auth","passed":true,"detail":"authenticated=True"} ],
  "passed": true }
exit=0
```
**SAY** "Two checks. `check_allowlist` — pure, no network — confirms every host the plan touches
is covered by the generated scope. Then a **live replay**: the generated `flow.py` is executed
through Playwright, through ZAP, against the running app, and we confirm auth succeeded. Exit
code mirrors the report — a bad bundle never silently reaches the scanner (FR-V3)."

> Why `http://juice:3000` here but the record step also used it: anything proxied through ZAP
> must name the host **as ZAP resolves it**. `localhost` from inside the ZAP container is ZAP
> itself.

### 6a. Fail-closed on an out-of-scope plan (30 s, Terminal B, no browser)

**RUN**
```bash
$PY - <<'EOF'
import json
plan = json.load(open('out/phase2-demo/gen/journey.json'))
plan['journey'].append({'action': 'goto', 'target': 'http://evil.example.com/'})
json.dump(plan, open('out/phase2-demo/bad_plan.json', 'w'), indent=2)
EOF

$PY -m authoring.validate --plan out/phase2-demo/bad_plan.json \
  --scope out/phase2-demo/gen/scope.json --no-replay \
  --report out/phase2-demo/bad-validation-report.json; echo "exit=$?"
```
**SEE** `"passed": false`, `"detail": "out-of-scope hosts: ['evil.example.com']"`, `exit=2`.
**SAY** "Same scope, but the plan now names a host never seen in the trace. The allow-list check
fails immediately, `--no-replay` skips the browser, non-zero exit — the Phase 1 fail-closed
posture, one stage earlier."

---

## Part G — The unchanged Phase 1 runner, fed the generated bundle (~4–5 min, Terminal A)

**RUN** (Terminal A)
```bash
time $PY -m runner.main \
  --flow  out/phase2-demo/gen/flow.py \
  --scope out/phase2-demo/gen/scope.json \
  --base-url http://juice:3000 --zap-api http://localhost:8080 --zap-proxy http://localhost:8080 \
  --records-out out/phase2-demo/live-records.json \
  --coverage-out out/phase2-demo/live-coverage.json; echo "exit=$?"
```
**SAY** (as it starts) "Nothing in `runner/`, `scope_guard.py`, or the normalizer changed. Same
preflight, same guard, same bounded scan — just a generated `flow.py` and `scope.json` instead
of hand-authored ones. Preflight runs first, offline: it would abort here if the scope were
`prod` or had no allow-list, before any traffic."

**While the scan runs (~3–4 min; `--max-scan-min` defaults to 4)** — switch to **Terminal B**:

```bash
# 1) ZAP saw the *generated* flow authenticate: count Bearer requests
curl -s "http://localhost:8080/JSON/search/view/messagesByRequestRegex/?regex=Authorization:%20Bearer" \
  | $PY -c 'import sys,json;print(len(json.load(sys.stdin)["messagesByRequestRegex"]),"authenticated requests seen by ZAP")'

# 2) active-scan progress
curl -s "http://localhost:8080/JSON/ascan/view/scans/" | $PY -m json.tool

# 3) evidence is being captured next to the *generated* scope (redacted HAR)
ls -R out/phase2-demo/gen/evidence/
grep -A1 '"name": "Authorization"' out/phase2-demo/gen/evidence/*/active-scan.har | grep -c REDACTED
```
**SEE** `active-scan.har` (≈2.6 MB) and a count of redacted `Authorization` headers (>0).
**SAY** "Evidence lands under the app dir — here, next to the generated scope — and the HAR is
redacted at capture: auth headers, cookies, tokens, passwords." (Only a HAR here: the
*generated* flow doesn't take screenshots; the hand-authored Phase 1 flow does its own.)

Optionally show Phase-1 guardrails still bite (safe, offline, ~1 s each):
```bash
$PY - <<'EOF'
import json; s=json.load(open('out/phase2-demo/gen/scope.json')); s['environment_class']='prod'
json.dump(s, open('out/phase2-demo/prod_scope.json','w'))
EOF
$PY -m runner.main --flow out/phase2-demo/gen/flow.py \
  --scope out/phase2-demo/prod_scope.json --no-wait; echo "exit=$?"
```
**SEE** `RUNNER ABORT: …prod…`, `exit=2`, and **no** browser/ZAP traffic.

**Back in Terminal A, SEE** the gate:
```json
{ "scan_id": "2026…Z", "app_id": "juice-shop", "requests_seen": <n>, "blocked": 0,
  "gate": { "authenticated": true, "scope_ok": true, "has_high_or_medium": true,
            "detections": <hundreds+>, "passed": true } }
exit=0
```
(Verified on the mac 2026-09-19 with this exact command: `requests_seen: 37, blocked: 0, detections: 1214`, wall-clock **2m39s**; ZAP had seen 16 `Authorization: Bearer` requests from the generated flow.)
**SAY** "Authenticated, in scope, high/medium found, gate passed, exit 0 — the exact Phase 1
gate, driven by a generated bundle. That's the Week-2 checkpoint."

---

## Part H — Close the loop: live records → SARIF (→ GitHub) (1 min, Terminal A)

**RUN**
```bash
$PY -m detections.sarif_export out/phase2-demo/live-records.json --app-id juice-shop \
  --driver-version "ZAP 2.17.0" -o out/phase2-demo/live-results.sarif
$PY -c "import json;s=json.load(open('out/phase2-demo/live-results.sarif'));print(len(s['runs'][0]['results']),'SARIF results')"
```
**SEE** `1214 SARIF results` (or whatever the gate printed under `detections`).
**SAY** "`record → generate → validate → runner → normalizer → SARIF`, end to end. The only
difference from Phase 1's output is that everything upstream of the runner was generated."

*Optional live upload* (same one-way-door caveat as Part B; HEAD must be pushed):
```bash
$PY -m detections.github_upload out/phase2-demo/live-results.sarif \
  --owner CodyYang2016 --repo Dast-Scanning-Tool --ref refs/heads/main
```
Then **OPEN** Browser tab 2 and **CLICK** refresh after ~60 s.

---

## Part I — Wrap-up (30 s, no commands)

- Results pipeline proven on a fixture **before** any live generation — external-integration
  risk retired early.
- `record → generate → validate` yields a bundle that satisfies the exact same contract as the
  hand-authored flow — the **unchanged runner** is the proof.
- The LLM only emits a schema-validated JSON **plan**; deterministic code renders and
  AST-checks `flow.py`. Fallback means zero hard dependency on the model.
- Idempotency shown live (§5a); fail-closed shown live (§6a + the `prod` abort).
- Next: Phase 3 — two-scan lifecycle (open/new/resolved), evidence hardening, final recording.

Q&A cheat-sheet: bottom of `docs/dast_poc_phase2_demo_script.md`.

---

## 9. If something breaks live — don't debug on stage

**SAY** "Let's not burn demo time on infra — here's the deterministic path verified earlier
today, and the suite that backs every piece." Then:

```bash
$PY -m pytest -q                          # 188 passed
sed -n '/## Verification/,/## Out of scope/p' docs/junior_engineer/authoring_clis_design.md
ls out/phase2-demo/warmup/                             # the trace you recorded in §1.6
```

Then, off camera, the usual fixes (§11).

---

## 10. Reset between takes / rehearsals

```bash
rm -rf out/phase2-demo/trace out/phase2-demo/gen out/phase2-demo/gen2 out/phase2-demo/gen-llm \
       out/phase2-demo/live-* out/phase2-demo/*report.json out/phase2-demo/bad_plan.json
export AUTH_EMAIL="dast-demo-$(date +%H%M%S)@juice-sh.op"      # fresh user => clean register beat
# re-export the same AUTH_EMAIL in Terminal B
```

Keep `out/phase2-demo/records.json` / `results.sarif` (Part B) — they're fixture-derived and
regenerate identically anyway. Everything under `out/` is gitignored.

Full teardown at the end of the day: `$CT rm -f juice zap; $CT network rm dast`
(Windows: then `podman machine stop` if you like).

---

## 11. Gotchas (all hit on this machine or documented in the repo)

| Symptom | Cause | Fix |
|---|---|---|
| mac: `zsh: command not found: docker` | broken `/usr/local/bin/docker` symlink | §0 "Fix the docker command once" |
| win: `podman pull` → `proxyconnect tcp: dial tcp 127.0.0.1:8888` | dead proxy baked into the WSL VM | `dast_poc_day1_runbook.md` Appendix A2 (edit the systemd file, `daemon-reexec`) |
| win: `$PY: No such file or directory` | venv was created on the other OS / not created | `py -3.12 -m venv .venv` + installs (§0 Windows block) |
| win: commands with `$(…)`, heredocs or `time` misbehave | you're in PowerShell/cmd | use Git Bash |
| `Cannot connect to the Docker daemon` / `unable to connect to Podman` | runtime not running (mac: Docker Desktop error dialog on launch; win: machine stopped) | mac: open Docker Desktop, dismiss/restart, wait for the whale; win: `podman machine start` |
| `curl localhost:3000` → `000` but containers are "Up" | you started them with `compose` (no ports published) | `$CT rm -f …` and use the `$CT run -p` commands in §1.2 |
| `validate`/`runner`: `net::ERR_FAILED` on first `goto`, or `blocked: 1`, `scope_ok: false` | trace was recorded against `localhost` → generated allow-list is `localhost`, but the runner targets `juice` | re-record with `--base-url http://juice:3000 --zap-proxy http://localhost:8080` (§1.6 note) |
| `validate` auth check: `replay failed: … wait_for_function … Timeout` | login failed: wrong password for an existing email, **or** Juice Shop was restarted after `record` (users live in-memory, and the generated flow doesn't register) | use a fresh `AUTH_EMAIL` and re-run `record`; keep the same creds through validate/runner |
| `Passw0rd!` / `dast-poc@juice-sh.op` login times out | that email already exists with `Dast-POC-passw0rd!` | don't use it; timestamped email (§1.5) |
| `services not ready within 120s` from `runner.main` | ZAP can't reach `juice:3000` (different networks / juice exited 133 — KI3 / stale container IPs on Podman) | `$CT exec zap curl … http://juice:3000/`; do the full §1.2 reset (rm both, rm+create network, run both) |
| `curl: (52) Empty reply` from ZAP API | ZAP started without `api.addrs.addr.name=.*` | restart ZAP with the exact §1.2 command (note the quotes) |
| `github_upload` rejected | HEAD commit not on the remote, or token lacks `security_events`/`repo` | `git push` first; `gh auth status` |
| Bare `python` → `ModuleNotFoundError` | wrong interpreter (mac 3.9 / Windows Store stub) | `$PY` everywhere |
| Chromium window never appears in Part D | forgot `--headed`, or running inside a container | add `--headed`; run on the host |
| `generate` prints `LLM path failed … using deterministic fallback` | no/invalid key, network, or off-schema output | that's the designed behavior — say so; or add `--no-llm` to avoid the wait |

---

## 12. One-page command card (copy/paste order)

```bash
# ---- pre-flight (Terminal A) — paste the Platform card for your OS FIRST ----
$CT rm -f juice zap 2>/dev/null; $CT network rm dast 2>/dev/null; $CT network create dast
$CT run -d --name juice --network dast -p 3000:3000 $JUICE_IMG
$CT run -d --name zap --network dast -p 8080:8080 $ZAP_IMG zap.sh -daemon -host 0.0.0.0 -port 8080 -silent -config api.disablekey=true -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true
curl -s -o /dev/null -w "juice %{http_code}\n" http://localhost:3000; curl -s -o /dev/null -w "zap %{http_code}\n" http://localhost:8080/JSON/core/view/version/; $CT exec zap curl -sS -m10 -o /dev/null -w "juice-from-zap %{http_code}\n" http://juice:3000/
$PY -m pytest -q
rm -rf out/phase2-demo && mkdir -p out/phase2-demo
export AUTH_EMAIL="dast-demo-$(date +%H%M%S)@juice-sh.op" AUTH_PASSWORD="Dast-Demo-passw0rd!"; echo $AUTH_EMAIL
$PY -m authoring.record --app-id juice-shop --base-url http://juice:3000 --zap-proxy http://localhost:8080 --out-dir out/phase2-demo/warmup --headed --slow-mo 300

# ---- Part B (Terminal B) ----
$PY -m detections.normalizer contracts/sample_zap_output.json --app-id juice-shop --scan-id demo-fixture-1 -o out/phase2-demo/records.json
$PY -m detections.sarif_export out/phase2-demo/records.json --app-id juice-shop --driver-version "ZAP 2.17.0" -o out/phase2-demo/results.sarif
# (optional) $PY -m detections.github_upload out/phase2-demo/results.sarif --owner CodyYang2016 --repo Dast-Scanning-Tool --ref refs/heads/main

# ---- Part D (Terminal A) ----
$PY -m authoring.record --app-id juice-shop --base-url http://juice:3000 --zap-proxy http://localhost:8080 --out-dir out/phase2-demo/trace --headed --slow-mo 700

# ---- Part E ----
$PY -m authoring.generate --trace out/phase2-demo/trace/trace.json --out-dir out/phase2-demo/gen --no-llm
$PY -m authoring.generate --trace out/phase2-demo/trace/trace.json --out-dir out/phase2-demo/gen2 --no-llm && diff out/phase2-demo/gen/flow.py out/phase2-demo/gen2/flow.py && echo IDENTICAL

# ---- Part F ----
$PY -m authoring.validate --plan out/phase2-demo/gen/journey.json --scope out/phase2-demo/gen/scope.json --flow out/phase2-demo/gen/flow.py --base-url http://juice:3000 --zap-proxy http://localhost:8080 --report out/phase2-demo/validation-report.json; echo exit=$?

# ---- Part G ----
time $PY -m runner.main --flow out/phase2-demo/gen/flow.py --scope out/phase2-demo/gen/scope.json --base-url http://juice:3000 --zap-api http://localhost:8080 --zap-proxy http://localhost:8080 --records-out out/phase2-demo/live-records.json --coverage-out out/phase2-demo/live-coverage.json; echo exit=$?

# ---- Part H ----
$PY -m detections.sarif_export out/phase2-demo/live-records.json --app-id juice-shop --driver-version "ZAP 2.17.0" -o out/phase2-demo/live-results.sarif
```

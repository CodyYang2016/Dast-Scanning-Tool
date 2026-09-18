# Playwright `record` — Demo & Screen-Recording Runbook

A focused runbook for demoing the **Playwright-driven `record` step** (the Phase 2 canonical
authoring beat) and capturing it on video. A real Chromium browser registers + logs into OWASP
Juice Shop and walks an authenticated page, while the tool captures every navigation, form, and
API call into `trace.json`.

**The point to land:** the login journey that later drives the scan is captured by *automation*,
not hand-typed — and no credentials or tokens ever land in the recorded trace.

Companion docs: `dast_poc_phase2_demo_script.md` (the full Phase 2 flow this is a slice of),
`docs/junior_engineer/authoring_clis_design.md` (design). Everything here is verified on the
current dev machine (macOS, Docker, host `.venv`).

---

## 0. One-time prep (10 min before, off-camera)

```bash
cd /Users/codyyang/Dast-Scanning-Tool

# Services must be up. Confirm (want 200 from each):
curl -s -o /dev/null -w "juice %{http_code}\n" http://localhost:3000
curl -s -o /dev/null -w "zap   %{http_code}\n" http://localhost:8080/JSON/core/view/version/

# venv + Chromium ready:
.venv/bin/python -c "from playwright.sync_api import sync_playwright as s; b=s().start().chromium.launch(); b.close(); print('chromium ok')"
```

If juice/zap are down: `docker compose up -d juice zap` (uses `compose.yaml`), wait ~20s, re-curl.

Do one **throwaway headed run** before you record, so Chromium is warm and the real take is snappy:

```bash
export AUTH_EMAIL="warmup@juice-sh.op" AUTH_PASSWORD="Dast-Demo-passw0rd!"
.venv/bin/python -m authoring.record --app-id juice-shop --base-url http://localhost:3000 \
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

## 2. Start the screen recording (macOS built-in)

1. Press **⌘⇧5** → the capture toolbar appears.
2. Click **Options**:
   - **Save to:** `out/pw-demo/recordings` (create it: `mkdir -p out/pw-demo/recordings`) or Desktop.
   - **Microphone:** on, if you want to narrate live.
   - **Show Mouse Clicks:** on.
3. Choose **Record Selected Portion** (drag a box around Terminal + browser area) or **Record
   Entire Screen**.
4. Click **Record**.
5. **To stop:** click the ◼ in the top-right menu bar, or press **⌘⌃Esc**. The `.mov` saves to the
   folder you chose.

*(Alternative: QuickTime → File → New Screen Recording.)*

---

## 3. The command to run (the recorded moment)

With the recording rolling, in the Terminal:

```bash
cd /Users/codyyang/Dast-Scanning-Tool

# 1) Credentials = your "login". Fresh email each take so the register step visibly succeeds,
#    and a policy-compliant password (weak ones fail — see Gotchas).
export AUTH_EMAIL="dast-demo-$(date +%H%M%S)@juice-sh.op"
export AUTH_PASSWORD="Dast-Demo-passw0rd!"

# 2) Clean the output folder so the "files created" beat is convincing
rm -rf out/pw-demo/trace

# 3) THE demo command — headed + slowed down so the audience can follow each action
.venv/bin/python -m authoring.record \
  --app-id juice-shop \
  --base-url http://localhost:3000 \
  --out-dir out/pw-demo/trace \
  --headed --slow-mo 700
```

`--slow-mo 700` delays each browser action by 700 ms so the login is watchable; it does **not**
change the captured trace. Bump to `1000`+ for an even slower walkthrough, drop it for full speed.

**What appears on screen (in order):** a Chromium window opens → Juice Shop landing page (welcome
banner) → navigates to the **login** page → the **email/password fields fill themselves** → clicks
Login → briefly lands on the **basket** page → the window closes. With `--slow-mo 700` this is a
comfortable ~15–20s.

**Success line in the Terminal:**
```
recorded: 6 interactions, 22 api calls, hosts=['localhost'] -> out/pw-demo/trace/trace.json
```

---

## 4. Show the artifact it produced (still recording)

```bash
ls -1 out/pw-demo/trace/                                   # -> index.json  trace.json
.venv/bin/python -m json.tool out/pw-demo/trace/trace.json | sed -n '1,40p'
```

**Say:** "Every page, form field name, and `/rest/`·`/api/` call is captured — and notice there
are **no passwords or tokens** in this file; credentials came from environment variables, never the
trace." Then **stop the recording** (⌘⌃Esc).

---

## 5. Folder layout (what lives where)

```
/Users/codyyang/Dast-Scanning-Tool/
├─ out/pw-demo/
│  ├─ trace/            <- record output: trace.json, index.json  (regenerated each take)
│  ├─ warmup/           <- throwaway warm-up run
│  └─ recordings/       <- your .mov screen recordings (if you saved here)
└─ .venv/               <- the Python you must call as .venv/bin/python
```

`out/` is gitignored, so traces and recordings are never committed.

---

## 6. Reset between takes

```bash
rm -rf out/pw-demo/trace
export AUTH_EMAIL="dast-demo-$(date +%H%M%S)@juice-sh.op"   # fresh email => register visibly succeeds
```

Reusing the same email still works (register no-ops, login proceeds) — a new email just makes the
"new user registered" beat clean.

---

## 7. Gotchas (all verified)

- **Password policy is real.** `Passw0rd!` **times out at the login step** (`wait_for_function`
  never sees a token) because Juice Shop rejects it / it mismatches an existing account. Use a
  strong password like `Dast-Demo-passw0rd!`. This is the #1 thing that sinks a live take.
- **Use `.venv/bin/python`, not `python`.** Bare `python`/`python3` on this Mac is 3.9 without the
  deps.
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

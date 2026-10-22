# DAST web UI — live demonstration

*A path for showing the web UI end to end in about 15 minutes: setup in a terminal once, then the
demo itself entirely in the UI. It was dry-run from start to finish on 2026-10-22; the times and results quoted below are from
that run. Recording the login from the UI (D4) was checked live on the same setup after QA-12
was fixed.*

The demo runs against its **own** copy of the app configs, its own ZAP and its own Juice Shop,
on **Podman or Docker** (`scripts/ui_stack.sh` picks; see [`../podman_and_docker.md`](../podman_and_docker.md)).
Nothing in the repository is edited. ZAP and Juice Shop are published only on `127.0.0.1`, on
8080 and 3000, or on other ports where those are taken (step 4).

**Why the scan is faster than a real one:** it uses a lighter attack. Attack strength goes from
medium to **low**, the scan is capped at **2 minutes**, and each rule at **1 minute**. The slow
DOM-XSS pass stays off. There's no "passive only" mode: the attack phase always runs, just
lighter.

---

## Part 1 — Before the demo (terminal, once, about 5 minutes)

Use one terminal, from the repository root, for every step. Keep it open: step 7 runs the UI in
it.

### 1. The code and the project's Python

```bash
cd ~/Dast-Scanning-Tool
git checkout main && git pull
source .venv/bin/activate            # Git Bash on Windows: source .venv/Scripts/activate
```

On a Nationwide workstation, paste the checklist's terminal setup instead
([`../nationwide_test_checklist.md`](../nationwide_test_checklist.md)): it sets the NTR images, the
CA bundle and `ZAP_API_KEY`, and step 9 there covers the UI's extra packages.

### 2. A demo workspace: a copy of the real configs

```bash
export DEMO=$(mktemp -d /tmp/dast-demo.XXXXXX)
cp -r security/dast "$DEMO/apps" && mkdir "$DEMO/out"
export DAST_APPS_DIR="$DEMO/apps" DAST_OUT="$DEMO/out" DAST_ENV_REGISTRY="$DEMO/apps/environments.yaml"
```

### 3. Scan settings to turn down during the demo

The settings page edits settings that are in an app's `app.yaml`, and Juice Shop's has no scan
limits. Add them to the copy, at their usual values, so you can lower them live:

```bash
cat >> "$DEMO/apps/juice-shop/app.yaml" <<'EOF'
  policy:
    attack_strength: medium
  budgets:
    max_scan_min: 8
    max_rule_min: 3
EOF
cp "$DEMO/apps/juice-shop/app.yaml" "$DEMO/juice-shop.app.yaml.start"   # for a reset (Part 3)
```

(This works because `scan:` is the last section of Juice Shop's `app.yaml`.)

### 4. ZAP and Juice Shop, on Podman or Docker

```bash
# Only where 8080 or 3000 is already taken (e.g. your own ZAP or Juice Shop); otherwise skip:
export DAST_ZAP_PORT=18080 DAST_JUICE_PORT=13000
bash scripts/ui_stack.sh up juice
```

- [ ] **Expect:** `engine: podman` (or `docker`), then `ZAP is ready.` ZAP can take up to a minute.
  Then run the `export` line it prints, which sets `DAST_ZAP_API` (and `ZAP_API_KEY`, unless you
  had already exported one).

### 5. The test account, the AI provider and a placeholder GitHub token

```bash
export AUTH_EMAIL=demo-$(openssl rand -hex 3)@juice-sh.op AUTH_PASSWORD=$(openssl rand -hex 10)
export ANTHROPIC_API_KEY=$(cat .secrets/anthropic.key)
export GITHUB_TOKEN=placeholder-for-preview-only
```

- The test account is made up here; Juice Shop registers it itself the first time the login is
  recorded (D4).
- The UI never takes an API key: it reads `ANTHROPIC_API_KEY` from the shell that starts it, so
  the key never passes through a web page. Read it from the file as above; don't paste or echo it.
- **Publish → Preview** only checks that the token variable is set; it reads files and never
  contacts GitHub. The placeholder makes Preview work. **Don't click Publish** in the demo: a
  real publish would be rejected by GitHub with this token.

### 6. Check the starting point

```bash
ls "$DEMO/out"                     # empty: no recorded login and no scans yet
```

### 7. Start the demo UI

```bash
python -m dast ui --port 8796
```

It opens your browser, signed in. Leave the terminal running. If the browser didn't open, use
`python -m dast ui --port 8796 --no-open` and open the link it prints; the link works once, after
which `http://127.0.0.1:8796/` is enough in the same browser.

---

## Part 2 — The demo (all in the UI, about 10 minutes)

| # | Do | What the audience sees (from the dry run) |
|---|---|---|
| D1 | Open **Overview** | ZAP **Reachable** at `http://127.0.0.1:8080` (or the port from step 4); AI provider **Available · anthropic**; 4 applications |
| D2 | **Onboard**: `prod-shop`, `https://shop.prod.example.com`, Test → **Continue** | Refused at once: *"shop.prod.example.com looks like a production system, so it can't be scanned. Scan a dev, test or staging copy instead."* |
| D3 | **Onboard** again: `demo-app`, `http://demo-app.dev.local`, Development → **Continue** | Step 2, with **Hosts in scope** already filled in as `demo-app.dev.local` and a **Never touched** list to answer. The tool asks only what it can't work out. Stop here and leave the page: `demo-app` doesn't exist, so its login can't be checked (see "Known gaps") |
| D4 | **Apps → juice-shop → Settings** | A yellow banner: *"This app's login hasn't been recorded yet."* Click **Record the login**: "Recording the login…", then **"Login recorded. You can run a scan now."** after about 10 seconds, and the banner goes. The tool signed in with the test account and saved the steps |
| D5 | Still on juice-shop's settings, open **Advanced**. Set **How hard to test** to **Low**, **Time limit for the scan** to `2`, **Time limit per rule** to `1`. Click **Preview**, then **Save** | The exact change to `app.yaml` before it's saved (below). "Needs approval" settings are read-only on the same page |
| D6 | Click **Run a scan** | The progress page within a second. **Safety checks ✓**, **Sign in ✓**, then the scan with live activity. Finished in **about 3 minutes** in the dry run, with all five stages ✓ |
| D7 | Click **See results** | 1,212 findings (2 high) in 862 distinct problems; 314 routes and 113 rules tested. "Compared with last time": **1,212 new**, marked *"Not recorded yet: publishing records this comparison."* Copies are grouped as ×N, and **Show** filters the list |
| D8 | Open **SQL Injection** on `/rest/user/login` | The vulnerable input (`email`), what was sent (`'`), what came back (`HTTP/1.1 500 Internal Server Error`), how to fix it, and a `curl` to reproduce it. Then **Set this finding aside**: Reason *Accepted risk*, a why, a review date, **Propose**, then **Approve** → status **approved** |
| D9 | Back to the results, **Publish to GitHub…**. Fill in an owner, repository, `refs/heads/main` and a 40-character commit. Click **Preview** only | How many results would be sent, from which run, under which category. **Don't click Publish** |
| D10 | Open **Governance** | Every action you just took in the audit trail, the settings that need approval, and the known gaps in testing |

The D5 preview, as it appeared:

```diff
   policy:
-    attack_strength: medium
+    attack_strength: low
   budgets:
-    max_scan_min: 8
-    max_rule_min: 3
+    max_scan_min: 2
+    max_rule_min: 1
```

**Optional:** start a second scan and click **Stop scan** while it's scanning. It ends as
**stopped**, not failed, and the second run's results then compare with the first.

---

## Part 3 — After the demo

**To run the demo again** from the same starting point, keep ZAP and Juice Shop up. Stop the UI
(Ctrl+C), then:

```bash
cp "$DEMO/juice-shop.app.yaml.start" "$DEMO/apps/juice-shop/app.yaml"
rm -rf "$DEMO/out/juice-shop" "$DEMO/out/ui-audit.jsonl" "$DEMO/apps/juice-shop/suppressions.yaml"
python -m dast ui --port 8796
```

This also removes the recorded login, so D4 shows the banner and records it again. To skip D4
next time, keep it: remove `"$DEMO/out/juice-shop/scans"` instead of `"$DEMO/out/juice-shop"`.

**To clean up:** stop the UI (Ctrl+C), then:

```bash
bash scripts/ui_stack.sh down
rm -rf "$DEMO"
```

- [ ] **Expect:** the `ssd-dast-poc-*` containers are gone; your own `zap` and `juice` are still
  running.

---

## Known gaps to keep in mind

| Gap | Effect on the demo | Tracked as |
|---|---|---|
| AI discovery can't always verify a signed-in check (ONB-8). On the semgate lab it falls back to a starting point | Finishing onboarding with AI live hasn't been rehearsed against this setup, so D3 stops at step 2. To show onboard → record → scan for a new app, rehearse it first against a real app with a test account | ONB-8 (status doc) |
| The lighter scan still takes 2½–3 minutes | Talk through the Activity list while it runs, or show the Stop scan option | — |
| Governance shows "not committed yet" for approvals | Expected here: the demo workspace isn't a git repository. Against the real configs it shows the author and date from git (QA step G7) | — |

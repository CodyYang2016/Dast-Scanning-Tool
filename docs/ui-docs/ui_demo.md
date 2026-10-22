# DAST web UI — live demonstration

*A path for showing the web UI end to end in about 15 minutes: setup in a terminal once, then the
demo itself entirely in the UI. It was dry-run from start to finish on 2026-10-22 on branch
`fix/ui-qa-run1`; the times and results quoted below are from that run.*

The demo runs against its **own** copy of the app configs, its own ZAP and its own Juice Shop.
Nothing in the repository is edited, and containers you already run (a `zap` on 8080, a `juice`
on 3000) are not touched. ZAP is published only on `127.0.0.1:18080`; Juice Shop is not
published at all and is reached only through ZAP.

**Why the scan is faster than a real one:** it uses a lighter attack. Attack strength goes from
medium to **low**, the scan is capped at **2 minutes**, and each rule at **1 minute**. The slow
DOM-XSS pass stays off. There's no "passive only" mode: the attack phase always runs, just
lighter.

---

## Part 1 — Before the demo (terminal, once, about 5 minutes)

Use one terminal, from the repository root, for every step. Keep it open: step 8 runs the UI in
it.

### 1. The code and the project's Python

```bash
cd ~/Dast-Scanning-Tool
git checkout fix/ui-qa-run1        # main, once the QA fixes are merged
source .venv/bin/activate
```

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

### 4. A separate ZAP and Juice Shop

```bash
export ZAP_API_KEY=$(openssl rand -hex 24) DAST_ZAP_API=http://127.0.0.1:18080
cat > "$DEMO/zap-override.yaml" <<'EOF'
services:
  zap:
    ports: ["127.0.0.1:18080:18080"]
    command: [zap.sh, -daemon, -host, 0.0.0.0, -port, "18080", -silent,
              -config, "api.key=${ZAP_API_KEY}", -config, "api.addrs.addr.name=.*",
              -config, api.addrs.addr.regex=true]
EOF
docker compose -f compose.yaml -f "$DEMO/zap-override.yaml" up -d zap juice
curl -s -H "X-ZAP-API-Key: $ZAP_API_KEY" http://127.0.0.1:18080/JSON/core/view/version/
```

- [ ] **Expect:** `{"version":"2.17.0"}`. ZAP can take up to a minute to answer; repeat the
  `curl` until it does.

### 5. The test account, the AI provider and a placeholder GitHub token

```bash
export AUTH_EMAIL=demo-$(openssl rand -hex 3)@juice-sh.op AUTH_PASSWORD=$(openssl rand -hex 10)
export ANTHROPIC_API_KEY=$(cat .secrets/anthropic.key)
export GITHUB_TOKEN=placeholder-for-preview-only
```

- The test account is made up here; Juice Shop registers it itself on first sign-in.
- The UI never takes an API key: it reads `ANTHROPIC_API_KEY` from the shell that starts it, so
  the key never passes through a web page. Read it from the file as above; don't paste or echo it.
- **Publish → Preview** only checks that the token variable is set; it reads files and never
  contacts GitHub. The placeholder makes Preview work. **Don't click Publish** in the demo: a
  real publish would be rejected by GitHub with this token.

### 6. Record Juice Shop's login

```bash
python -m dast author juice-shop
```

- [ ] **Expect:** it ends with `bundle ready: … — next: dast scan juice-shop` (11 seconds in the
  dry run).

This is the one step the UI can't do yet for an app that signs in with a form (see "Known gaps"
below).

### 7. Check the starting point

```bash
ls "$DEMO/out/juice-shop"          # authoring only: no scans yet
```

### 8. Start the demo UI

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
| D1 | Open **Overview** | ZAP **Reachable** at `http://127.0.0.1:18080`; AI provider **Available · anthropic**; 4 applications |
| D2 | **Onboard**: `prod-shop`, `https://shop.prod.example.com`, Test → **Continue** | Refused at once: *"shop.prod.example.com looks like a production system, so it can't be scanned. Scan a dev, test or staging copy instead."* |
| D3 | **Onboard** again: `demo-app`, `http://demo-app.dev.local`, Development → **Continue** | Step 2, with **Hosts in scope** already filled in as `demo-app.dev.local` and a **Never touched** list to answer. The tool asks only what it can't work out. Stop here and leave the page (see "Known gaps") |
| D4 | **Apps → juice-shop → Settings**, open **Advanced**. Set **How hard to test** to **Low**, **Time limit for the scan** to `2`, **Time limit per rule** to `1`. Click **Preview**, then **Save** | The exact change to `app.yaml` before it's saved (below). "Needs approval" settings are read-only on the same page |
| D5 | Click **Run a scan** | The progress page within a second. **Safety checks ✓**, **Sign in ✓**, then the scan with live activity. Finished in **about 3 minutes** in the dry run, with all five stages ✓ |
| D6 | Click **See results** | 1,212 findings (2 high) in 862 distinct problems; 314 routes and 113 rules tested. "Compared with last time": **1,212 new**, marked *"Not recorded yet: publishing records this comparison."* Copies are grouped as ×N, and **Show** filters the list |
| D7 | Open **SQL Injection** on `/rest/user/login` | The vulnerable input (`email`), what was sent (`'`), what came back (`HTTP/1.1 500 Internal Server Error`), how to fix it, and a `curl` to reproduce it. Then **Set this finding aside**: Reason *Accepted risk*, a why, a review date, **Propose**, then **Approve** → status **approved** |
| D8 | Back to the results, **Publish to GitHub…**. Fill in an owner, repository, `refs/heads/main` and a 40-character commit. Click **Preview** only | How many results would be sent, from which run, under which category. **Don't click Publish** |
| D9 | Open **Governance** | Every action you just took in the audit trail, the settings that need approval, and the known gaps in testing |

The D4 preview, as it appeared:

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
rm -rf "$DEMO/out/juice-shop/scans" "$DEMO/out/ui-audit.jsonl" "$DEMO/apps/juice-shop/suppressions.yaml"
python -m dast ui --port 8796
```

This keeps the recorded login (`$DEMO/out/juice-shop/authoring`), so step 6 isn't repeated.

**To clean up:** stop the UI (Ctrl+C), then:

```bash
docker compose -f compose.yaml -f "$DEMO/zap-override.yaml" down
rm -rf "$DEMO"
```

- [ ] **Expect:** the `ssd-dast-poc-*` containers are gone; your own `zap` and `juice` are still
  running.

---

## Known gaps to keep in mind

| Gap | Effect on the demo | Tracked as |
|---|---|---|
| The UI can't record the login for an app that signs in with a form (`dast author`). Only SSO/MFA apps have a button (**Sign in (SSO)**) | Step 6 is done in the terminal. A newly onboarded form-login app can't be scanned from the UI alone, which is why D3 stops at step 2 | QA-12 |
| AI discovery can't always verify a signed-in check (ONB-8). On the semgate lab it falls back to a starting point | Finishing onboarding with AI live hasn't been rehearsed against this setup. Rehearse it before showing it | ONB-8 (status doc) |
| The finding header shows "CWE-CWE-89": real records already hold `CWE-89`, and the page adds the prefix again | Cosmetic; visible in D7 | QA-13 |
| The lighter scan still takes about 3 minutes | Talk through the Activity list while it runs, or show the Stop scan option | — |
| Governance shows "not committed yet" for approvals | Expected here: the demo workspace isn't a git repository. Against the real configs it shows the author and date from git (QA step G7) | — |

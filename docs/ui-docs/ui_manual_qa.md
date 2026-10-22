# DAST web UI — manual QA script

A step-by-step pass through `python -m dast ui`, written so anyone can run it and record what
they see. Every step says what to do, what you should see, and has a box to tick. It complements
the automated tests (`docs/ui-docs/ui_acceptance_criteria.md`): those prove the contract; this
checks the experience.

**Time:** about 60–90 minutes for Parts A–H (no scanner needed); add 30–45 minutes for Part I
(a real scan).

**Safe by default.** Parts A–H run against a throwaway copy of the test fixtures, so nothing you
do touches `security/dast/` or `out/` in the repository. Part I starts its own isolated ZAP and
Juice Shop on a separate port.

**How to record a problem:** note the step number, what you expected, what happened, and a
screenshot. There's a table at the end.

---

## Part A — Set up

### A1. Prerequisites

- [x] Python virtual environment active, with the UI's packages:
  `pip install -r requirements-ui.txt`
- [x] Node.js 22 or newer: `node --version`
- [x] The front end built (once, and again after any front-end change):
  ```bash
  cd webui/frontend && npm ci && npm run build && cd ../..
  ```
  **Expect:** `✓ built in …` and a `webui/frontend/dist/index.html`.

### A2. Make a throwaway QA workspace

From the repository root:

```bash
export QA=$(mktemp -d)
cp -r tests/ui/fixtures/apps "$QA/apps"
cp -r tests/ui/fixtures/out  "$QA/out"
export DAST_APPS_DIR="$QA/apps" DAST_OUT="$QA/out" DAST_ENV_REGISTRY="$QA/apps/environments.yaml"
export DAST_ZAP_API=http://127.0.0.1:9          # nothing listens here: Parts A–H need no scanner
unset ANTHROPIC_API_KEY LLM_PROVIDER             # no AI, so onboarding is predictable
echo "$QA"
```

- [x] **Expect:** a path is printed. Keep this terminal; every command below runs in it.

The workspace holds four apps (`dvwa`, `intranet-sso`, `juice-shop`, `orders-portal`) and three
Juice Shop runs from a real self-test.

### A3. Start the UI

```bash
python -m dast ui
```

- [x] **Expect:** a line `Open this link (it works once): http://127.0.0.1:8765/auth?token=…`,
  and a browser tab opens on the Overview.
- [x] **Expect:** the top right says `Signed in as <your user> · this machine only`.

---

## Part B — Security (it controls an attack tool, so check these first)

| # | Do | Expect | Pass |
|---|---|---|---|
| B1 | Copy the launch link from the terminal and open it again in a **new private/incognito window** | The message "That link has already been used or isn't valid." (shown as plain JSON) — it works once | ✅ |
| B2 | In that private window, open `http://127.0.0.1:8765/` | A short page saying to open the link printed by `python -m dast ui`; no app | ✅ |
| B3 | In a second terminal: `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8765/api/apps` | `401` (no session) | ✅ |
| B4 | `curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' http://127.0.0.1:8765/api/apps` | `400` (only its own address is answered) | ✅ |
| B5 | `curl -s -m 3 http://$(ipconfig getifaddr en0):8765/ ; echo "exit=$?"` (macOS; on Linux use `hostname -I \| cut -d' ' -f1`) | A connection error and a non-zero exit: it isn't reachable from the network | ✅ |
| B6 | In the main browser, open DevTools → Application/Storage → Cookies for 127.0.0.1 | One cookie `dast_session`, marked **HttpOnly** and **SameSite Strict** | ✅ |
| B7 | DevTools → Network, reload any page, select the document request, look at Response Headers | `content-security-policy` present, containing `frame-ancestors 'none'` and no `unsafe-inline` | ✅ |

---

## Part C — Overview and lists

| # | Do | Expect | Pass |
|---|---|---|---|
| C1 | Look at the Overview | Three tiles: **Applications 4**, **ZAP: Not answering** (http://127.0.0.1:9), **AI provider: Not set up** | ✅ (QA-1: rows misaligned on list pages) |
| C2 | Read "Applications and their latest run" | Four rows. juice-shop's latest run is `20261021T090000Z`, status **complete**; the others say "never scanned" | ✅ |
| C3 | Click each tile under "What would you like to do?" | Each opens the matching page; no blank page, no error | ✅ |
| C4 | Click **Apps**, **Runs**, **Findings**, **Automation** in the top bar | Each lists the four apps with links that fit the page (Settings / Run / Results / Get workflow) | ✅ |
| C5 | Press **Tab** repeatedly from the top of any page | A visible focus ring moves through the skip link, every nav item and every control in order | ✅ |

---

## Part D — App settings (`orders-portal`: a test environment with durable data)

Open **Apps → orders-portal → Settings**.

| # | Do | Expect | Pass |
|---|---|---|---|
| D1 | Look at the four bands | **Required** (amber), **Optional** (blue, collapsed as "Advanced"), **Needs approval** (purple table), **Always on** (grey, collapsed) | ✅ |
| D2 | In Required, find "Never touched" | Shows `/api/notify/email` and `/api/payments/` — it's required here because this app's data is durable | ✅ |
| D3 | Find the two "Test account … is kept in" fields | Each shows the variable name and an amber "isn't set in this shell" tag — never a value | ✅ |
| D4 | Expand **Advanced**, change "Time limit for the scan (minutes)" from `8` to `12`, click **Preview** | The right panel shows a diff with exactly one line removed (`max_scan_min: 8`) and one added (`max_scan_min: 12`) | ✅ |
| D5 | Click **Save** | A green "Saved" tag; the field now shows 12 with no "Changed, not saved" tag | ✅ |
| D6 | In the terminal: `grep -n "max_scan_min\|# orders-portal" "$QA/apps/orders-portal/app.yaml"` | `max_scan_min: 12`, and the file's comments are still there | ✅ |
| D7 | In the Needs approval table, look for "Fail the build at", "Scanner rules switched off", "How hard to test" | Listed read-only with their values; "Approved by: not committed yet" (the QA workspace isn't in git) | ✅ |
| D8 | Change "Time limit for the scan" to `ten`, click **Preview** | A red message that the value isn't valid; nothing saved | ✅ (QA-4: error shown at page top) |
| D9 | Undo with **Discard**. Then, without reloading, edit the file in the terminal: `sed -i '' 's/delay_ms: 200/delay_ms: 250/' "$QA/apps/orders-portal/app.yaml"` (Linux: `sed -i`). Now change "Time limit" to `13` in the UI and click **Save** | A message that the settings changed since you opened them, telling you to reload. The file still says 12 | ✅ |
| D10 | Reload the page | "Request rate" (Advanced) now shows `delay_ms` 250; the time limit is 12 | ✅ |
| D11 | Read "Same thing on the command line" | `python -m dast scan orders-portal` | ✅ |
| D12 | Click **Run a scan** | A red message: "ZAP isn't answering at http://127.0.0.1:9, so nothing was started." with a fix. No run appears | ✅ |
| D13 | Open **dvwa → Settings** (a dev environment with disposable data) and expand **Advanced** | "How hard to test" and "Reset data before scanning" are editable under Optional — in orders-portal (test, durable) the first was in Needs approval and the second doesn't apply | ✅ |

---

## Part E — Results, finding detail and triage (`juice-shop`)

Open **Findings → juice-shop → Results** (run `20261021T090000Z`).

| # | Do | Expect | Pass |
|---|---|---|---|
| E1 | Read the three tiles | **47** findings: 2 high, 15 medium, 15 low, 15 info. **359** routes, 113 rules, "cut short: 10104". Compared with last time: 0 new, 44 open, 0 resolved, **3 not tested**, 0 suppressed | ✅ |
| E2 | Look at the top of the Findings table | The two **high** SQL injection rows come first, both marked **not tested** | ✅ |
| E3 | Set "Show" to **not tested** | Exactly 3 rows | ❌ QA-5 |
| E4 | Set "Show" to **high** and click **SQL Injection** on `/rest/user/login` | Input `email`, what was sent `'`, what came back (a database error excerpt), the request, how to fix, references and a `curl` replay line. (Passive findings such as "CSP Header Not Set" genuinely have no input or payload) | ✅ (reworded; QA-6 for passive findings) |
| E5 | In "Set this finding aside", choose **Accepted risk**, type a reason, leave the date empty, click **Propose** | A red message asking for a review date. Nothing saved | ✅ |
| E6 | Add a date (e.g. end of the year), click **Propose** | The panel shows **proposed**, "Proposed by <you>", and an **Approve** button | ✅ |
| E7 | In the terminal: `cat "$QA/apps/juice-shop/suppressions.yaml"` | One entry with `status: proposed`, `proposed_by: <you>`, your reason and date | ✅ |
| E8 | Go back to Results | The row now has a purple "set-aside proposed" tag; the lifecycle tile still says **0 suppressed** (a proposal changes nothing) | ✅ |
| E9 | Open the finding again, click **Approve** | Status **approved**, "approved by <you>" | ✅ |
| E10 | In the terminal: `python -m dast report juice-shop --fail-on none` then reload Results | The command finishes; the row says "set aside" and the tile shows it **suppressed** — once per copy: a finding ZAP reported more than once (same rule, page and input) is suppressed in every copy, so the CSP finding on `/` counts **2**. The totals change too: the report recounts from the full records against a fresh state file | ✅ |
| E11 | Open a different finding and propose **False positive** with a reason; then edit `suppressions.yaml` so its entry has `status: approved` and `expires: 2026-01-01`, and reload Results | That row shows an amber **set-aside expired** tag | ✅ |

---

## Part F — Publishing (don't actually publish)

Still on juice-shop's Results page, in "Publish to GitHub".

| # | Do | Expect | Pass |
|---|---|---|---|
| F1 | Look at the form | Owner, repository, ref and commit pre-filled from the app's settings; token variable `GITHUB_TOKEN` | ✅ |
| F2 | Clear "Deployed commit", click **Preview** | A message asking which build was scanned (no default, on purpose) | ✅ |
| F3 | Restore the commit (`5658473cf8814459bf89000ce373b20ed0b4eb37`), change "Token variable" to `QA_NOT_SET_TOKEN`, click **Preview** | "The token variable QA_NOT_SET_TOKEN isn't set." — and the preview never shows a token value | ✅ (QA-7: side panel hard to reach when scrolling) |
| F4 | Read "Same thing on the command line" as you change Where/Owner | The command updates: `--upload` for code scanning, `--issues` for Issues | ✅ |
| F5 | **Don't press Publish** unless the repository is a throwaway one you own | — | ✅ |

---

## Part G — Governance and automation

| # | Do | Expect | Pass |
|---|---|---|---|
| G1 | Open **Governance** | Tiles for approved settings, known gaps (with "undecided" count) and audit entries | ✅ |
| G2 | Read "What scans deliberately don't test" | `40026` for dvwa and orders-portal; orders-portal's two never-touched paths; SP-1, SP-1a, SP-2, SP-3, SP-4, SP-6, SP-7 marked **not decided**; SP-5 **decided** | ✅ |
| G3 | Read the Audit trail | Your actions from Parts D–E at the top (`settings.save`, `suppression.propose`, `suppression.approve`) by you; older Juice Shop events by **outside the UI** | ✅ |
| G4 | Read the Environment registry | `juice`, `dvwa`, `webgoat` as dev; `orders.test.example.internal` as test; the production patterns underneath. No way to edit it | ✅ |
| G5 | Open **Automation → orders-portal** | A workflow named `dast-orders-portal`, with `secrets.ORDERS_PORTAL_USER` and `secrets.ORDERS_PORTAL_PASS` and the steps author → scan → report | ✅ |
| G6 | Click **Download workflow** | A file `dast-orders-portal.yml` downloads with the same content | ✅ |
| G7 | (Optional, provenance) Stop the UI, `unset DAST_APPS_DIR DAST_OUT DAST_ENV_REGISTRY`, start it again, open **Governance**. **Look only — don't save anything in this mode: it edits the real configs** | Approvals for dvwa/juice-shop/webgoat show a real author and date from git instead of "not committed yet". Then stop it and re-export the A2 variables | ✅ (run read-only on a separate port; dvwa, juice-shop, webgoat show Cody Yang with dates, semgate shows its bot author) |

---

## Part H — Onboarding (no AI)

Open **Onboard**.

| # | Do | Expect | Pass |
|---|---|---|---|
| H1 | Application id `billing`, address `https://billing.test.example.internal`, environment **Test**, **Continue** | Back on step 1 with a red message: the host isn't in the environment registry, ask Governance to add it as test | ✅ |
| H2 | Change the address to `https://orders.prod.example.internal`, **Continue** | Refused: it looks like a production system | ✅ |
| H3 | Application id `qa-app`, address `http://qa-app.dev.local`, environment **Development**, **Continue** | Step 2: "Hosts in scope" pre-filled with `qa-app.dev.local` | ❌ QA-8 (kept the refused host) |
| H4 | Add `/api/notify` under "Never touched", **Continue** | Step 3: login type, login page (placeholder `/login`), and two variable-name fields pre-filled `QA_APP_USER` / `QA_APP_PASS`, each tagged "not set in this shell" | ❌ QA-8 (BILLING_USER/PASS pre-filled); rest of step OK after manual fix |
| H5 | Check: is there any field asking for a password **value**? | No — only variable names | ✅ |
| H6 | Read "Same thing on the command line" | `python -m dast onboard qa-app --base-url http://qa-app.dev.local --environment-class dev --auth form --login-url /login` | ✅ |
| H7 | **Check the login** | The button reads "Checking the login…", then step 4 says no AI provider was available and the app will be saved with a starting point | ✅ |
| H8 | Check that `$QA/apps/qa-app/app.yaml` does **not** exist yet: `ls "$QA/apps/qa-app"` | "No such file or directory" — nothing is written until you confirm | ✅ |
| H9 | Enter a page to test (e.g. `/account`), click **Save the starting point** | You land on qa-app's Settings; `$QA/apps/qa-app/app.yaml` now exists with `QA_APP_USER` / `QA_APP_PASS` and your never-touched path | ✅ (QA-9: saved file became owner-only) |
| H10 | Start onboarding `qa-app` again with the same details | Refused: qa-app is already onboarded | ✅ |
| H11 | (Optional, with AI) Stop the UI, `export ANTHROPIC_API_KEY=…`, start the semgate lab (Part I1) and onboard `http://localhost:8084`, login page `/signin`, variables `SEMGATE_USER`/`SEMGATE_PASS` | Known gap: discovery reports it couldn't verify a sign-in check and saves a starting point (status doc, "Discovery proof (ONB-8)") | ☐ |

---

## Part I — A real scan (optional, 30–45 minutes)

This starts its own ZAP and Juice Shop with `scripts/ui_stack.sh`, on Podman or Docker
([`../podman_and_docker.md`](../podman_and_docker.md)), published only on `127.0.0.1`. Run 1 used
a hand-written compose override on Docker for the same result.

### I1. Start the isolated scanner

Stop the UI first (Ctrl+C). Then, from the repository root, in the A2 terminal:

```bash
# Only where 8080 or 3000 is already taken (e.g. by your own ZAP or Juice Shop):
export DAST_ZAP_PORT=18080 DAST_JUICE_PORT=13000
bash scripts/ui_stack.sh up juice
# then run the `export` line it prints (DAST_ZAP_API, and ZAP_API_KEY unless already set)
```

- [x] **Expect:** `engine: podman` or `docker`, then `ZAP is ready.` (ZAP can take a minute).

### I2. Author Juice Shop once

```bash
export AUTH_EMAIL=qa-$(openssl rand -hex 3)@juice-sh.op AUTH_PASSWORD=$(openssl rand -hex 10)
python -m dast author juice-shop
```

- [x] **Expect:** it ends with `bundle ready: … — next: dast scan juice-shop`.

**Or from the UI** (QA-12): export the two variables above, skip the `dast author` line, and in
I3 open **juice-shop → Settings** first. A banner says the login hasn't been recorded; click
**Record the login**.

- [ ] **Expect:** "Recording the login…", then "Login recorded. You can run a scan now." within
  about 10 seconds, and the banner goes.

### I3. Scan from the UI

Start the UI again (`python -m dast ui`) and open **Overview**.

| # | Do | Expect | Pass |
|---|---|---|---|
| I3.1 | Read the ZAP tile | **Reachable** at `DAST_ZAP_API` (run 1: http://127.0.0.1:18080) | ✅ |
| I3.2 | Open **juice-shop → Settings → Run a scan** | You're taken to the run's progress page within a few seconds | ✅ (0.8 s) |
| I3.3 | Watch the five stages | Safety checks ✓, Sign in ✓, then Scan in progress; the Activity list fills with events | ✅ |
| I3.4 | Wait for it to finish (about 5–8 minutes) | All five stages ✓ and a **See results** button | ✅ (about 3 min) |
| I3.5 | Open the results | A new run with findings; coverage in the hundreds of routes | ✅ (1,213 findings, 314 routes; QA-10, QA-11 noted) |
| I3.6 | Start another scan, and click **Stop scan** while it's scanning | Status **stopped** (not failed); in Runs it's listed as stopped | ✅ |
| I3.7 | In the terminal: `python -m runner.evidence --check "$QA/out/juice-shop/scans/<new run id>"` | `evidence clean: …` | ✅ (both new runs clean) |
| I3.8 | Open **Governance → Audit trail** | `job.start` and `job.stop` by you; the scan's own events also by you (not "outside the UI") | ✅ |

### I4. Clean up

```bash
bash scripts/ui_stack.sh down
rm -rf "$QA"
```

- [x] **Expect:** the `ssd-dast-poc-*` containers are gone; nothing else you run is affected.

---

## Results

| Part | Steps passed | Problems found (step, expected, actual) |
|---|---|---|
| A Set up | 3 / 3 ✅ | |
| B Security | 7 / 7 ✅ | |
| C Overview and lists | 5 / 5 ✅ | QA-1 (rows misaligned on list pages); QA-2 (narrowed in H: browser back arrow leaves the wizard) |
| D App settings | 13 / 13 ✅ | QA-3 (required settings missing from app.yaml aren't shown); QA-4 (validation error at page top) |
| E Results and triage | 10 / 11 | E3 ❌ QA-5 (filter shows stale rows: duplicate fingerprints as row keys); QA-6 (bare dashes on passive findings) |
| F Publishing | 5 / 5 ✅ | QA-7 (publish side panel hard to reach when scrolling) |
| G Governance and automation | 7 / 7 ✅ | |
| H Onboarding | 8 / 10 (H11 optional, not run) | H3, H4 ❌ QA-8 (pre-fills keep the refused host and id); QA-9 (UI-saved app.yaml becomes owner-only) |
| I Real scan (optional) | 8 / 8 ✅ (I1–I4 done; run headless by Claude) | QA-10 ("compared with last time" shows 0 new before `dast report`); QA-11 ("cut short" shows a bare rule id) |

Tested by: codyyang Date: 2026-10-22 Commit (`git rev-parse --short HEAD`): 7b241c9 — run 1 complete (H11 optional, not run)

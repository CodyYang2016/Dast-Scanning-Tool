# DAST tool UI — requirements (draft)

*Draft, 2026-10-09; decisions recorded 2026-10-21. Built from the personas in
[`dast_poc_remediation_plan.md`](../dast_poc_remediation_plan.md) §1 and §3, and from an inventory of
everything the tool exposes today: 4 commands with about 30 flags, about 60 `app.yaml` fields, and
about 30 environment variables. §8 records the decisions taken on the original open questions,
and the scan postures that are still pending.*

*Mockups of these screens, in three visual styles, are in [`README.md`](README.md). Style 2,
"Enterprise workspace", is the chosen direction (§8 Q1).*

## 1. Purpose

Running the tool today means a long runbook, several terminals, exported credentials, and knowing
which of about 120 settings matter. A UI should make one thing easy: **take an application from
"never scanned" to "findings a developer can act on" without reading a runbook.**

It must not break the rule the project already adopted (remediation plan §1):

> **Config in, contracts out, one command, one artifact.**

That gives the UI three constraints:

1. **The config file stays the source of truth.** The UI reads and writes
   `security/dast/<app>/app.yaml` and `suppressions.yaml`, validated against
   `contracts/app.schema.json`. Nothing that changes a scan lives only inside the UI.
2. **The UI is a front end to the `dast` commands, not a second implementation.** Every action
   maps to `dast onboard | author | scan | report`, and the UI can show the equivalent command.
3. **The UI is never more permissive than the CLI.** Guardrails are enforced in the core: preflight,
   scope, the environment registry. The UI shows them; it cannot turn them off.

## 2. Who uses it

| Persona | What they come to the UI for | How much of it they see |
|---|---|---|
| **SEC**: security engineer, the operator | Onboard an app, verify login, choose what gets tested, run scans, read results, approve triage | Everything except approvals they don't hold |
| **DEV**: app developer | Understand a finding, reproduce it, propose "false positive", "won't fix" or "accepted risk" | Results and triage. Triage happens only in the UI (§8 Q4); GitHub alerts or issues notify them and link back here |
| **OPS**: platform/DevOps | Move a working setup into CI on a schedule; set installation settings once | Export to CI, installation settings, run history |
| **GOV**: governance/approver | Approve what a scan may do, see what was excluded and why, audit who ran what | Approvals, disclosed gaps, audit trail; read-only elsewhere |

**Decided (§8 Q1):** one shared UI that every persona uses, in the style 2 "Enterprise workspace"
design and format. It is built for a mix of people, many of whom use it occasionally, so it explains
itself as it goes.

## 3. How options are classified

Each setting gets exactly one tier. These answer "what needs to be an option, what could be, and
what shouldn't be":

| Tier | Meaning | How the UI treats it |
|---|---|---|
| **A: Must ask** | Required, and no default is safe. The tool refuses to run without it | A wizard step. Blocks progress until answered |
| **B: Offer, with a default** | A real choice, but the default is right for most apps | Under "Advanced". The default and its consequence are shown |
| **C: Approval, not a setting** | Needs a decision, but not by the person running the scan, because it widens what the scan may do to a shared environment | Shown read-only, with who approved it and when. Changed through approval (§8 Q3), never by a toggle in the run flow |
| **D: Not an option** | One of three kinds. **D1** a fixed guardrail. **D2** worked out by the tool. **D3** an installation setting OPS sets once | D1 shown as an explanation when it refuses something. D2 shown read-only. D3 on an admin screen, not in the run flow |

## 4. Option inventory, by stage

"Source" is where the setting lives today. The UI writes the same place.

### 4.1 Onboard: describe the app

| Option | Source | Tier | Owner | Why |
|---|---|---|---|---|
| App name / id | `app_id` | **A** | SEC | Everything is keyed by it; it must match the folder name |
| Where the app is | `base_url` | **A** | SEC | No default. The UI should test reachability and explain "as ZAP sees it" |
| Environment: dev, test or staging | `environment_class` | **A** | SEC | Deliberately has no default. Preflight checks it against the environment registry and refuses prod. A wrong answer is the most dangerous mistake possible |
| Hosts that may be tested | `scope.allow` | **A** (pre-filled from `base_url`) | SEC | The attack boundary. Adding a host beyond the app's own warrants a warning |
| How people log in | `auth.mode` (form / seeded) | **A** | SEC | Ask in plain words: "a username/password form" or "SSO or MFA, so you log in yourself once" |
| Login page | `auth.login_url` | **A** (form only) | SEC | |
| Test account, by reference | `auth.credentials.*_env` | **A** | SEC | The UI asks which secret holds it, never the value itself (UI-4) |
| Endpoints that must never be touched | `scope.exclude` | **A** if data is durable; otherwise **B** | SEC, with GOV visibility | Mail, SMS, payments, partner calls. Ties to the open W4-8 decision. With durable data, "none" must be an explicit answer |
| Login steps and selectors | `auth.steps`, `auth.selectors.*` | **D2**, editable as **B** | SEC | The hardest part today, and the UI shouldn't ask for it. `dast onboard --discover` proposes it and the code verifies it by logging in. Hand-editing is an escape hatch |
| How we know login worked | `auth.proof.*` | **D2**, confirmed by the user | SEC | Proposed by discovery. The user confirms "this page only shows when you're logged in" |
| Cookie banners to dismiss | `ui.dismiss_selectors` | **B** | SEC | Derivable during discovery |
| Login-only hosts (SSO) | `scope.traverse` | **B**, shown only for SSO | SEC | |
| App-specific quirks | `auth.cookies`, `auth.bearer_from_cookie` | **B** (Advanced) | SEC | Rare |
| Tool may create its own accounts | `auth.identity: self-register` | **C** | GOV | Creates data in the target. Default `provisioned` |
| Data can be thrown away | `data_policy: disposable` | **C** | GOV / app owner | An attestation. It unlocks writes and data reset, so the operator can't simply assert it |
| How old a saved login may be | `auth.storage_state_ttl_hours` | **C** | GOV | Policy, not per-app taste |
| Where the saved login lives | `auth.storage_state` | **D2** | — | The UI manages it |
| Output folder | `output.dir`, `--out`, `DAST_OUT` | **D3** | OPS | |

### 4.2 Author: decide what gets tested

| Option | Source | Tier | Owner | Why |
|---|---|---|---|---|
| Pages to test | `record.authenticated_routes` | **A** for the recorded walk (at least one) | SEC | Offer a picker from pages seen during login, rather than typing paths |
| Recorded walk or exploration | `--explore` | **B** | SEC | Default: recorded walk when routes are given |
| Use the AI | `--no-llm` / on | **B**, only where a provider is approved | SEC | Off is always allowed |
| AI fails, so stop | `--require-llm` | **D1** | — | In the UI, "AI on" always means "stop if the AI is unavailable". A silent fallback would make results look AI-driven when they weren't |
| Which AI provider and model | `LLM_PROVIDER`, `--model`, `ANTHROPIC_MODEL`, `COPILOT_MODEL` | **C** | GOV | Which providers may see app content is an approval (Copilot is the Nationwide-approved one). Set once, not per run |
| Where exploration starts | `explore.seed_routes` | **B** | SEC | |
| Exploration limits | `explore.budgets.*` | **B** | SEC | The defaults suit most apps |
| Submit search-style (GET) forms | `explore.submit_get_forms` | **B** (default on) | SEC | |
| Test values to type into forms | `explore.test_data` | **B** | SEC | |
| Fields the AI may answer | `explore.inferred_fields` | **B** (Advanced) | SEC | Each needs a strict shape. The UI should require one |
| Submit forms that change data | `explore.write_mode`, `explore.safe_forms` | **C** | GOV | Writes in a shared environment are an approval (SP-1). Only allowed when `data_policy: disposable` |
| Watch the browser | `--headed` | **B** | SEC | A "show me" toggle, useful for debugging |
| Skip the login replay check | `--no-replay` | **D1** | — | The UI always verifies |
| Seed file, proxy address | `--seed`, `--zap-proxy` | **D2** | — | |
| API URL patterns | `api.patterns` | **B**, derivable | SEC | Pre-fill from traffic seen during authoring |

### 4.3 Scan: attack it

| Option | Source | Tier | Owner | Why |
|---|---|---|---|---|
| API spec (OpenAPI) | `scan.openapi` | **B**, encouraged | SEC | The biggest single coverage gain for API apps. The UI should prompt for it |
| Attack strength, alert threshold | `scan.policy.attack_strength`, `alert_threshold` | **B** in dev; **C** in test/staging | SEC / GOV | A scan posture (SP-*) in shared environments |
| ZAP rules switched off | `scan.policy.disabled_rules` | **C** | GOV | Each one is a disclosed gap, and should show in the GOV view (UI-13) |
| Time limits | `scan.budgets.*` | **B** | SEC | |
| Request rate | `scan.throttle.*` | **B**, conservative defaults in test/staging | SEC | Etiquette in shared environments |
| DOM-XSS pass | `scan.dom_xss.*` | **B** | SEC | Costs about 5 GiB and about 15 minutes on a full site. Show the cost next to the toggle |
| Reset data before scanning | `scan.reset.*` | **B**, only when disposable | SEC | |
| Login check during the scan, re-login | `scan.liveness_path`, `scan.reauth.*` | **D2** / **B** (Advanced) | — | Derived from the login proof; re-login on by default |
| Extra anti-CSRF fields, state probes | `scan.anti_csrf_tokens`, `scan.state_probes` | **B** (Advanced) | SEC | Rare |
| ZAP API key, ZAP access list | `ZAP_API_KEY`, `ZAP_API_ALLOW` | **D2** | — | The UI generates a key per run and never shows it |
| ZAP addresses | `--zap-api`, `--zap-proxy` | **D3** | OPS | |
| Self-test mode | `--expect-findings` | **D1** (CI only) | — | For deliberately vulnerable targets |
| Stop a running scan | (behaviour) | Must exist (UI-7) | SEC | |

### 4.4 Report and publish

| Option | Source | Tier | Owner | Why |
|---|---|---|---|---|
| Publish or not, and where (code scanning or Issues) | `--upload`, `--issues` | **A** before the first publish | SEC | Publishing is one-way: other people read it |
| Repository | `publish.github.owner/repo`, `--owner/--repo` | **A** if publishing | SEC | |
| Deployed build that was scanned (ref and commit) | `--ref`, `--commit`, `DAST_TARGET_REF/COMMIT` | **A** if publishing | SEC / OPS | No default, deliberately: the scanner's own checkout is not the target. Pull from deployment metadata where possible |
| GitHub token | `GITHUB_TOKEN` / `GH_TOKEN` | **A** if publishing, by reference | SEC / OPS | |
| Fail threshold (the gate) | `gate.fail_on`, `--fail-on`, `DAST_FAIL_ON` | **C** | GOV | The gate is policy. The person being gated shouldn't be the one lowering it |
| Minimum severity for Issues | `--issue-min-severity` | **B** | SEC | |
| Category, tool version | `--category`, `--driver-version` | **D2** | — | Category must be `dast/<app>`; two apps sharing one overwrite each other's alerts |
| Evidence link | `--evidence-url`, `DAST_EVIDENCE_URL` | **D2** if the UI hosts evidence; else **D3** | OPS | |

### 4.5 Triage

| Option | Source | Tier | Owner | Why |
|---|---|---|---|---|
| Mark false positive / won't fix / accepted risk / test data | `suppressions.yaml` | DEV **proposes**, SEC **approves** | DEV, SEC | Recorded decisions, keyed by fingerprint |
| Reason | `suppressions.yaml` | **A** for every suppression | DEV | |
| Expiry | `suppressions.yaml` | **A** for accepted risk | SEC | Accepted risk must expire. The UI should not offer "never" |
| Suppressed findings still published | (behaviour) | **D1** | — | Dropping a result is how GitHub closes an alert as "fixed" |
| Where triage happens | (behaviour) | **D1**: the UI only (§8 Q4) | — | One place to decide, so a finding can't get conflicting decisions. Dismissing an alert in GitHub isn't a triage path |

### 4.6 Operate

| Option | Source | Tier | Owner |
|---|---|---|---|
| Environment registry (which hosts are dev/test/staging, prod patterns) | `security/dast/environments.yaml`, `DAST_ENV_REGISTRY` | **C** | GOV |
| Schedule / CI | GitHub Actions (outside the tool) | Out of scope as a UI feature; the UI **exports** a workflow (UI-14) | OPS |
| Log format, debug flags | `DAST_LOG_FORMAT`, `LLM_DEBUG` | **D3** | OPS |
| Copilot CLI path, flags, timeout | `COPILOT_CLI`, `COPILOT_FLAGS`, `COPILOT_TIMEOUT_SECONDS` | **D3** | OPS |
| Build and network settings | `PIP_INDEX_URL`, `DAST_CA_BUNDLE`, `ZAP_IMAGE`, `JUICE_IMAGE`, `PLAYWRIGHT_IMAGE`, `DAST_SUBNET`, `DAST_RUNNER_IP`, Podman settings | **D3** | OPS |
| Internal tuning | `MAX_PER_RULE`, `DAST_ZAP_SPEC_DIR` | **D3** | OPS |

### 4.7 Guardrails that are never options (D1)

The UI explains these when they refuse something. It never offers them as settings:

- Production hosts are refused, whatever the config says.
- Deny beats allow. Every request is checked against scope before it is sent.
- A test or staging host must be in the environment registry.
- ZAP's API always needs a key.
- Content is redacted before any AI sees it.
- A finding is only `resolved` when its route, parameter and rule were re-tested. Otherwise it stays `not_scanned` and stays published.
- A scan that lost its session, or wrote to the app, can never resolve anything.

## 5. Functional requirements

"Must" is required for a first version; "Should" may be cut.

| ID | Requirement | Acceptance criterion |
|---|---|---|
| UI-1 | **Must** read and write `app.yaml` and `suppressions.yaml` as the source of truth, validated against `contracts/app.schema.json`, and show every change as a diff before saving | Editing the YAML by hand and in the UI produces the same scan. Nothing the scan depends on is stored only in the UI |
| UI-2 | **Must** map every action to a `dast` command and be able to show that command | A run started in the UI can be reproduced from the shown command |
| UI-3 | **Must** onboard an app by asking only the tier-A questions in §4.1, deriving login steps and proof with discovery, and verifying login live before saving | A new app (WebGoat-like) is onboarded by someone who has not read the runbook, in about 10 minutes. The CLI baseline is 4–5 minutes for someone who has |
| UI-4 | **Must** handle secrets by reference only: never display, log or write a value. Where a secret is resolved from (environment variable today) sits behind one interface, so a shared deployment can add a secret store | No credential or token value appears in `app.yaml`, logs, the browser's storage or screenshots |
| UI-5 | **Must** support the human-in-the-loop login for SSO/MFA (seeded mode): open a browser, let the person log in, save the session per the TTL policy | An SSO app is onboarded without the operator handling cookies or files |
| UI-6 | **Must** show tier-C settings read-only, with the current value, who approved it and when | The operator cannot widen writes, disabled rules, the gate threshold or the registry from the UI |
| UI-7 | **Must** show a run's progress through preflight → login replay → scan → normalize → coverage, live from `events.jsonl`, and allow stopping it | Stopping leaves the app in its pre-scan state and the run marked stopped, not failed silently |
| UI-8 | **Must** explain every refusal in one plain sentence, with the fix | e.g. "`orders.test.internal` is not in the environment registry. Ask GOV to add it as `test`." No tracebacks |
| UI-9 | **Must** present results the way `summary.md` does: findings with fix, parameter, evidence and a replay line, and coverage as "N of M routes" with `not_scanned` kept visible | A DEV can reproduce a finding from the UI alone |
| UI-10 | **Must** be the only place triage happens: DEV proposes with a reason; SEC approves; accepted risk needs an expiry; writes `suppressions.yaml` | An expired suppression shows as expired, not silently gone. Every published alert or issue links back to the finding in the UI |
| UI-11 | **Must** preview what publishing will send (destination, count, deployed ref/commit) and require those tier-A answers before the first publish | Publishing without a deployed commit is impossible |
| UI-12 | **Should** show, when the AI was used, which steps it chose (`steps_by_source`) | A reviewer can tell an AI-driven run from a deterministic one |
| UI-13 | **Should** give GOV one view: approvals, disclosed gaps (disabled rules, exclusions, postures), run audit trail, registry (read-only) | GOV can answer "what did this scan not test, and who decided?" without asking SEC |
| UI-14 | **Should** export a working CI workflow for an onboarded app | OPS pastes it into the app's repository and the scheduled run passes |
| UI-15 | **Should** keep tier-B settings under "Advanced", each showing its default and what changing it costs | No tier-B setting appears in the default flow |

## 6. Non-functional requirements

| ID | Requirement |
|---|---|
| UI-N1 | **Local first, ready to be shared.** The first version runs where the tool runs: a workstation with Docker or Podman, including inside Nationwide. Nothing in it may rule out running later as a shared service (§8 Q2, UI-N6) |
| UI-N2 | **Loopback only while local.** The UI holds credentials and controls an attack tool, so a local install is never reachable from another machine. A shared deployment adds login and roles before it listens on a network |
| UI-N3 | **Validation lives in the core,** not the UI, so the CLI and UI can't disagree about what is allowed |
| UI-N4 | **Every UI action is recorded** in the run's `events.jsonl`, with who did it |
| UI-N5 | **Accessible** (keyboard-operable, readable contrast) and usable on a laptop screen |
| UI-N6 | **No single-user assumptions.** Every action carries an identity (UI-N4) even when only one person uses it; run history, approvals and triage are stored per app, not per machine; and an app's test account isn't assumed to be the only one (SP-7 may need two). Moving to a shared service then adds login, roles and a secret store without reshaping the data |
| UI-N7 | **Tiers are configuration.** Which tier each setting falls into lives in one mapping, not in screen code, so a posture decision (§8 Q5) changes one entry. Until a posture is decided, its settings are tier C |

## 7. Out of scope

- Replacing CI or scheduling. The UI exports; GitHub Actions runs.
- Becoming the vulnerability system of record. GitHub alerts and issues stay the published record;
  triage decisions are made in the UI (§8 Q4).
- Editing guardrails (§4.7) or approvals (tier C) from the run flow.
- Multi-user hosting, roles and login for the UI itself, in the first version. The design must allow
  them later (UI-N6).
- An approval system inside the UI, in the first version (§8 Q3).

## 8. Decisions and pending items

*Q1–Q4 were decided on 2026-10-21. Q5 is still pending, but it does not block building the UI.*

### Decided

| # | Question | Decision | What it means for the design |
|---|---|---|---|
| Q1 | Who is the primary user? | **Everyone, in the style 2 "Enterprise workspace" design and format.** | One shared UI for all four personas, built for occasional use: tier B stays under "Advanced", tier C shows read-only with who decided, and each screen explains itself. Further mockup work refines style 2 |
| Q2 | Local tool or shared service? | **Local first, with the capability of becoming a shared service.** | The first version runs on one workstation (UI-N1, UI-N2), but nothing may assume it always will: secrets resolve through one interface (UI-4), and every action carries an identity, with no single-user assumptions in the data (UI-N6) |
| Q3 | Where do approvals happen? | **Not needed while local; design for it.** | Tier C settings show read-only with who approved and when (UI-6), so either route can be added later: pull-request review of `app.yaml` with GOV as code owners (recommended), or approvals inside the UI. No approval system in the first version |
| Q4 | Does DEV use the UI? | **Yes — everyone uses the UI, and triage happens only in the UI.** | Developers mark false positives, won't-fix and accepted risk in the UI (UI-10). GitHub alerts and issues become the notification and the published record, and link back to the finding in the UI |

**Follow-up from Q4.** The tool can import dismissals made in GitHub as triage decisions
(`dast triage --from-github`). With triage in the UI only, that import has to be retired, or turned
into a proposal that waits for approval in the UI. To decide before triage is built.

### Q5 — scan postures (pending, not blocking the UI)

The scan postures decide how aggressive a scan is allowed to be. Each trades detection against
safety in a shared environment. Today's defaults were tuned for a safe demo against a disposable
container; each has to be chosen, signed off and disclosed before the benchmark against commercial
scanners, or the vendors' extra findings will read as better detection when the real difference is
safety. They are tracked in [`evaluation_scorecard.md`](../evaluation_scorecard.md) and
[`dast_first_internal_app_readiness.md`](../dast_first_internal_app_readiness.md), and wait on the
scorecard sign-off ([`status_and_roadmap.md`](../status_and_roadmap.md)).

| # | The question | Today | Options | What it changes in the UI |
|---|---|---|---|---|
| SP-1 | May exploration submit forms that change data? | No (`write_mode: deny`) | Never · an approved list per app (`safe_forms`) · yes | Stays tier C either way. A per-app list means a "request this form" flow |
| SP-1a / W4-8 | ZAP's attack phase hits every data-changing request it has seen, whatever SP-1 says. On Juice Shop it registers users on every run, which makes one finding flaky | Unbounded | Accept it (disposable data only) · keep write endpoints out of the attack · limit HTTP methods per app | If "keep them out": `scope.exclude` is a required question for any app with durable data, as §4.1 already has it |
| SP-2 | How long may a scan run? | Per-app limits; rules cut short are recorded | Agree minimum and maximum minutes | Time limits stay tier B, within bounds GOV sets |
| SP-3 | Run the DOM-XSS check (rule 40026)? | Off unless `scan.dom_xss` is on. On DVWA: ~15 min, ~5 GiB, one class nothing else found | Off, disclosed · on with a bigger budget | Tier B with its cost shown, or required for single-page apps if mandated |
| SP-4 | How does the scanner learn what to attack? | The recorded walk plus a crawler; `scan.openapi` can import a spec | As is · require a spec where one exists | If required, "do you have an OpenAPI spec?" becomes a tier A onboarding question |
| SP-5 | What if a long scan is signed out? | Effectively decided: re-authentication shipped and was verified on DVWA (W5-2). The scorecard row still says "detect and fail" and needs updating | Confirm re-authentication | No change: on by default, shown on the run screen |
| SP-6 | Test for out-of-band ("blind") vulnerabilities? | Out | Out, disclosed · in (needs a callback host and network approval) | If out: a permanent disclosed gap in the governance view. If in: a new installation setting and a per-app opt-in |
| SP-7 | Test whether one user can reach another's data (authorization, OWASP #1)? | Out — one identity per app | Out, naming the control that covers it · fund multi-identity scanning | If in: onboarding asks for two test accounts. The biggest UI change on this list, which is why UI-N6 rules out assuming one account |

**Why this doesn't block the build.** Every posture setting already exists in `app.yaml`, and every
screen it touches is designed. A decision only moves settings between tiers, and tiers are
configuration (UI-N7). Until a posture is decided, its settings stay tier C, the safe default: the
UI can't widen what a scan may do. The postures must be settled before the pilot and the benchmark,
on the scorecard track, not before the UI.

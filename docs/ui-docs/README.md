# DAST tool UI — mockups

Three visual directions for the UI described in [`ui_requirements.md`](ui_requirements.md). Each
style has the same seven pages and the same data, so they can be compared like for like.

**Data:** the totals are real. DVWA's run had 522 findings (19 high), covering 6 of 6 routes;
Juice Shop's self-test covers 359 routes. Field names, commands and exit codes match the tool. The
people, dates, the `orders-portal` app and the split of the 19 high findings by rule are
illustrative.

**To view:** open any `style-N/index.html` in a browser. The pages are static, need no network,
and link to each other. The screenshots below are for reviewing on GitHub, which shows HTML as
source.

| | [Style 1 — Operator console](style-1/index.html) | [Style 2 — Enterprise workspace](style-2/index.html) | [Style 3 — Guided flow](style-3/index.html) |
|---|---|---|---|
| **Feel** | Dark, dense, keyboard-driven | Light, calm, card-based | One task at a time, large type, plain language |
| **Layout** | Left sidebar of apps and runs, tight tables | Top navigation, cards, a "what this means" help panel | Centred single column, a step-by-step journey bar |
| **How tiers show** | Badges: MUST · OPT · APPROVAL · FIXED | Labelled card bands: Required · Optional · Needs approval · Always on | Sentences: "We need this from you" · "Someone else decides this" |
| **Fits best if** | Security engineers run scans for app teams | Many teams use it occasionally; approvers and developers read it as much as engineers run it | App teams run scans themselves |

**Chosen direction: style 2, Enterprise workspace** (2026-10-21). One shared UI that every persona uses; see
§8 Q1 in the requirements. Styles 1 and 3 are kept for reference.

## Pages

| Page | Persona | Shows | Requirements |
|---|---|---|---|
| `index.html` | all | Where to start; the four tiers explained | — |
| `01-onboard-wizard.html` | SEC | Only the must-ask questions; the tool finds the login and asks you to confirm it | UI-3, 4, 5 |
| `02-app-settings.html` | SEC | All four tiers on one page; changes as a diff before saving | UI-1, 2, 6, 15 |
| `03-run-progress.html` | SEC | Live stages, safe stop, the audit log, a refusal in plain words | UI-7, 8 |
| `04-results-and-finding.html` | SEC, DEV | Coverage, one finding end to end, triage, the publish check | UI-9 to 12 |
| `05-governance.html` | GOV | Pending approvals, disclosed gaps, audit trail, environment registry | UI-13 |
| `06-export-to-ci.html` | OPS | A ready workflow; installation settings kept out of the run flow | UI-14 |

## Style 1 — Operator console

| | |
|---|---|
| ![Overview](style-1/screenshots/index.png) | ![Onboard](style-1/screenshots/01-onboard-wizard.png) |
| ![App settings](style-1/screenshots/02-app-settings.png) | ![Run progress](style-1/screenshots/03-run-progress.png) |
| ![Results and finding](style-1/screenshots/04-results-and-finding.png) | ![Governance](style-1/screenshots/05-governance.png) |
| ![Export to CI](style-1/screenshots/06-export-to-ci.png) | |

## Style 2 — Enterprise workspace

| | |
|---|---|
| ![Overview](style-2/screenshots/index.png) | ![Onboard](style-2/screenshots/01-onboard-wizard.png) |
| ![App settings](style-2/screenshots/02-app-settings.png) | ![Run progress](style-2/screenshots/03-run-progress.png) |
| ![Results and finding](style-2/screenshots/04-results-and-finding.png) | ![Governance](style-2/screenshots/05-governance.png) |
| ![Export to CI](style-2/screenshots/06-export-to-ci.png) | |

## Style 3 — Guided flow

| | |
|---|---|
| ![Overview](style-3/screenshots/index.png) | ![Onboard](style-3/screenshots/01-onboard-wizard.png) |
| ![App settings](style-3/screenshots/02-app-settings.png) | ![Run progress](style-3/screenshots/03-run-progress.png) |
| ![Results and finding](style-3/screenshots/04-results-and-finding.png) | ![Governance](style-3/screenshots/05-governance.png) |
| ![Export to CI](style-3/screenshots/06-export-to-ci.png) | |

## Regenerating the screenshots

```bash
.venv/bin/python docs/ui-docs/render.py            # every style
.venv/bin/python docs/ui-docs/render.py style-2    # one style
.venv/bin/python docs/ui-docs/render.py --phone    # also check 390px wide
```

The script fails on a broken link between pages, a console error, or sideways scrolling at phone
width.

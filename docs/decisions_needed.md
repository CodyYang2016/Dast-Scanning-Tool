# Decisions needed before the first internal scan

*2026-10-22. One page for the people who own these calls. No code blocks the first scan of an
internal application; these decisions do. Each one says what's being asked, the options, a
recommendation from the project's own analysis, and what it unblocks. Detail:
[`status_and_roadmap.md`](status_and_roadmap.md),
[`dast_first_internal_app_readiness.md`](dast_first_internal_app_readiness.md),
[`evaluation_scorecard.md`](evaluation_scorecard.md).*

## Decide first: the longest lead time

| # | Decision | Options | Recommendation | Who decides | Unblocks |
|---|---|---|---|---|---|
| 1 | **Which internal application is scanned first, and who runs the scans? (Gate 0)** | Any app with a non-production environment and a test account | An app with real single sign-on: SSO is the capability actually under test. Accept the longer identity setup that comes with it | Security engineering lead, with the app's owner | Everything below: postures are agreed per app |
| 2 | **Can Nationwide provide a self-hosted GitHub runner on its network?** | Yes · no, so evidence needs another governed store | Ask now. GitHub's own runners can't reach internal apps (IP allow list), so without one there is no unattended scanning and no hosted evidence | Platform / DevOps | Scheduled scans; evidence hosting items 4–5 |
| 3 | **Who signs the scorecard?** (W6-7) | Security engineering alone · whoever will act on the result | Whoever will act on the comparison with commercial tools. Weights agreed only by the team being measured are worth little | Governance | The benchmark against commercial scanners |

## Agree per application: scan postures

Each trades detection against safety in a shared environment. Whatever is chosen is disclosed
on the scorecard, so a deliberate exclusion never reads as weaker detection.

| # | Posture | Today | Recommendation |
|---|---|---|---|
| SP-1 | May exploration submit forms that change data? | No | In test environments, allow an approved list of forms per app (`explore.safe_forms`), never a blanket yes; budget a data reset |
| SP-1a / W4-8 | ZAP's attack phase reaches every data-changing request it saw | Unbounded | For apps with durable data, keep the write endpoints the app team names out of the attack (`scope.exclude`). Full write coverage only in a disposable environment |
| SP-2 | How long may a scan run? | Per-app limits; cut-short rules are reported | Size the limit to the app; truncation is already recorded, so a short limit is visible, not silent |
| SP-3 | Run the DOM-XSS check? | Off unless enabled | On for single-page apps, with its own time budget (~15 min, ~5 GiB on DVWA) |
| SP-4 | How does the scanner learn what to attack? | Recorded walk plus crawler | Import the OpenAPI spec wherever one exists; coverage then has a denominator |
| SP-5 | A long scan gets signed out | Signs in again (shipped, verified) | Confirm. Nothing to build |
| SP-6 | Out-of-band ("blind") vulnerabilities | Not tested | Out of the pilot, disclosed. In needs a callback host and network approval: a project, not a setting |
| SP-7 | Can one user reach another's data? (OWASP #1) | Not tested: one identity | Out of the pilot, naming the control that covers it today; or fund multi-identity scanning as its own project |

**Who decides:** Governance, with the security engineer running the scan and the app team.

## Decide when the pilot results are in

| # | Decision | Recommendation |
|---|---|---|
| 4 | **Build vs buy** (W8-4): what to keep building whichever scanner is chosen | Decide with the benchmark results. The governed discovery, the honest lifecycle ("not tested" is never "fixed") and the UI work on top of any engine |
| 5 | **OAST and authorization testing** (W6-5, W6-6): fund them, or keep them as disclosed exclusions | Follow SP-6 and SP-7 above; revisit if the benchmark shows they decide the comparison |

## Already decided (2026-10-21)

The UI's primary user (everyone, style 2), local first and ready to be shared, approvals by pull
request when that matters, and triage in the UI only — see
[`ui-docs/ui_requirements.md`](ui-docs/ui_requirements.md) §8.

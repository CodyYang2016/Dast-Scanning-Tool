# Archive

Documents that shaped this project and no longer describe it.

Nothing here is maintained. Where one of these disagrees with a document in `docs/`, the one in
`docs/` is right — these are kept for provenance, not guidance: they answer *why is it like
this* long after they stopped answering *how does it work*.

| Document | What it was | Superseded by |
|---|---|---|
| `Authenticated-Application-Discovery-DAST-Design-Proposal.md` | The architecture proposal. Origin of the D-decisions (D1–D10) still cited throughout the code | What was actually built — including the D9 reversal, which this document still describes as proposed |
| `dast_poc_review.md` | An evidence-based funding review at commit `c3bac3b` | `../dast_poc_remediation_plan.md`, which tracks every finding it raised as a numbered work item |
| `dast_poc_3week_plan.md` | The original three-week POC schedule | `../dast_poc_remediation_plan.md` |
| `dast_poc_demo_plan.md` | The risk-gated demo plan across three milestones | `../dast_poc_phase2_demo_runbook.md` |
| `dast_poc_day1_runbook.md` | First-day environment setup | `../onboarding_a_new_application.md` |
| `dast_poc_phase1_demo_script.md` | The Phase 1 demo walkthrough | `../dast_poc_phase2_demo_script.md` |
| `dast_poc_playwright_demo_runbook.md` | A focused runbook for demoing the `record` step | `../dast_poc_phase2_demo_runbook.md`, which covers the whole Phase 2 flow |

Commands and paths in these files are not expected to work. Several predate the `dast` CLI, the
per-app `app.yaml` contract, and the configurable output root, so they reference tooling and
layouts that no longer exist.

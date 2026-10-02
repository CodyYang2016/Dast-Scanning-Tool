# Fix → re-scan → `resolved`, and the `not_scanned` counter-case (W8-2)

The project's definition of done (requirements §9 step 4): fix a finding, re-scan, and watch it
become `resolved`; and show that a finding whose route the re-scan did **not** visit is labelled
`not_scanned`, not `resolved`, even though it is just as absent. Run on 2026-10-01 against DVWA;
reproduce with `scripts/demo_fix_rescan.sh`.

## The fix

DVWA ships a hardened implementation of every lesson: security level **`impossible`**
(parameterised queries, output encoding, anti-CSRF tokens). Scan 1 runs at `low`; scan 2 at
`impossible`. That is a switch to the application's own fixed code — the closest thing to a
developer's fix on an application we cannot edit — and it fixes many findings at once, not one.

Scan 2 also excludes `/vulnerabilities/xss_r` (`scope.exclude`). That route is NOT fixed by
anything we did; it is simply not visited. It is the counter-case.

| | Scan 1 | Scan 2 |
|---|---|---|
| `auth.cookies.security` | `low` | `impossible` |
| `scope.exclude` | — | `/vulnerabilities/xss_r` |
| Scan id | `20261001T225433Z` | `20261001T230452Z` |
| Lifecycle | new 344 | open 294 · **resolved 35** · **not_scanned 7** · new 49 |

## Every high-severity finding from scan 1, after the re-scan

| Finding | Route · parameter | After re-scan | In re-scan SARIF? |
|---|---|---|---|
| SQL Injection - MySQL | `/vulnerabilities/sqli` · `id` | **resolved** | no — GitHub would close it |
| SQL Injection - MySQL | `/vulnerabilities/brute` · `username` | **resolved** | no |
| SQL Injection | `/vulnerabilities/sqli_blind` · `id` | **resolved** | no |
| Cross Site Scripting (Reflected) | `/vulnerabilities/sqli` · `id` | **resolved** | no |
| Cross Site Scripting (Reflected) | `/vulnerabilities/brute` · `username` | **resolved** | no |
| Path Traversal | `/vulnerabilities/fi` · `page` | **resolved** | no |
| Cross Site Scripting (Reflected) | `/vulnerabilities/xss_r` · `name` | **not_scanned** | **yes — kept open** |

Fingerprints and the raw counts are in [`fix_rescan_resolved.json`](fix_rescan_resolved.json),
extracted from the two scans' `labeled.json` and the re-scan's `results.sarif` by the script —
not typed by hand.

The `xss_r` finding is the point of the exercise. A scanner that equates "not found this time"
with "fixed" would have closed it, and the GitHub alert with it. This one did not: its route was
not exercised, so the finding is carried forward as `not_scanned` and stays in the upload. (This
is the same failure, in reverse, as the live upload that once wrongly closed 13 findings.)

## What `dast explain` says

```
what happened to the findings that are gone: app_state_changed=35, route_excluded=7

  [high] Cross Site Scripting (Reflected) -> /vulnerabilities/xss_r
    route_excluded: /vulnerabilities/xss_r was excluded from this scan by '…/vulnerabilities/xss_r…',
    so nothing tested it; remove the exclusion to scan it again

  [high] SQL Injection - MySQL -> /vulnerabilities/sqli
    app_state_changed: the application was not in the same condition: /security.php answered
    differently (status 200→200, body digest changed)
```

`explain` does **not** call the resolved findings "fixed". The state probe on `/security.php`
saw the application change condition between the scans — which is exactly what happened: the
security level IS the fix. Lifecycle says `resolved` (the route, parameter and rule were all
exercised and the finding is gone); `explain` adds that the application's state moved, so a
reader can tell a code fix from, say, a test-data reset. That is the intended behaviour: the tool
never claims more than it observed.

## Also worth noting

- **49 new findings in scan 2** are mostly the hardened pages answering differently (new headers,
  anti-CSRF forms) — new low/informational findings, not regressions; none is high.
- Scan 2 tested 18 of 18 routes the authoring walk discovered (scan 1: 19 of 19; the excluded
  route is subtracted from both sides).
- Both scans ran in their own output root; `out/dvwa` and its lifecycle state were untouched,
  and `app.yaml` was restored by the script on exit.

# DAST scan — juice-shop

Scan `20261019T125049Z`

**Verdict: not evaluated** — no policy gate ran on this scan.

## Findings

| Severity | New | Open | Not scanned | Suppressed |
|---|---:|---:|---:|---:|
| High | 2 | 0 | 0 | 0 |
| Medium | 521 | 0 | 0 | 0 |
| Low | 456 | 0 | 0 | 0 |
| Info | 376 | 0 | 0 | 0 |
| **Total** | 1355 | 0 | 0 | 0 |

## New findings

| Severity | Finding | Where | Parameter |
|---|---|---|---|
| High | SQL Injection | `/rest/products/search` | `q` |
| High | SQL Injection | `/rest/user/login` | `email` |
| Medium | CSP: Failure to Define Directive with No Fallback | `/assets` | `Content-Security-Policy` |
| Medium | CSP: Failure to Define Directive with No Fallback | `/assets/i18n` | `Content-Security-Policy` |
| Medium | CSP: Failure to Define Directive with No Fallback | `/assets/public` | `Content-Security-Policy` |
| Medium | CSP: Failure to Define Directive with No Fallback | `/assets/public/images` | `Content-Security-Policy` |
| Medium | CSP: Failure to Define Directive with No Fallback | `/assets/public/images/products` | `Content-Security-Policy` |
| Medium | CSP: Failure to Define Directive with No Fallback | `/media` | `Content-Security-Policy` |
| Medium | Content Security Policy (CSP) Header Not Set ×2 | `/` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/api` |  |
| Medium | Content Security Policy (CSP) Header Not Set ×2 | `/api/users` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/assets` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/assets/assets/public/assets/public/assets/public/assets/public/favicon_js.ico` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/assets/assets/public/assets/public/assets/public/favicon_js.ico` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/assets/assets/public/assets/public/assets/public/main.js` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/assets/assets/public/assets/public/assets/public/polyfills.js` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/assets/assets/public/assets/public/assets/public/scripts.js` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/assets/assets/public/assets/public/assets/public/styles.css` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/assets/assets/public/assets/public/favicon_js.ico` |  |
| Medium | Content Security Policy (CSP) Header Not Set | `/assets/assets/public/assets/public/main.js` |  |

…and 1333 more of 1355 in the SARIF and `labeled.json`.

## Where the open findings are

| Rule | Open |
|---|---:|
| Timestamp Disclosure - Unix | 446 |
| Cross-Domain Misconfiguration | 272 |
| Content Security Policy (CSP) Header Not Set | 235 |
| Modern Web Application | 216 |
| User Agent Fuzzer | 156 |

| Route | Open |
|---|---:|
| `/socket.io` | 65 |
| `/rest/user/login` | 20 |
| `/assets` | 19 |
| `/assets/i18n` | 19 |
| `/assets/public` | 19 |

## Coverage

- Tested **359 routes** with **113 rules**.
- Stopped early by the per-rule time limit: `10104` — their routes are not fully tested.
- Excluded from the scan: `(?i).*logout.*`, `(?i).*delete\-account.*`.
- DOM-XSS (40026) not run — `scan.dom_xss` is off; DOM-based XSS is a disclosed gap (SP-3).
- Request/response stored for 523 findings.
- Session: alive throughout (4 checks).
- ZAP API: key required.
- ZAP was confined to: `^https?://juice(?::\d+)?(?:[/?#].*)?$`.
- Policy: strength default, threshold default, write mode deny, throttle zap defaults.

## Results

- No GitHub destination configured; SARIF written locally.

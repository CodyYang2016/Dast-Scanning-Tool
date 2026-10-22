// RES-3, RES-4, TRI-5 (component layer). The page is mounted through the app's own routes with
// `fetch` answering in the shapes the API contract defines (ui_acceptance_criteria.md §3). The
// assertions read only the data-testid hooks in §4.
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../src/App";

const APP = "juice-shop";
const SCAN = "20261021T090000Z";

const finding = (fp: string, status: string, extra: Record<string, unknown> = {}) => ({
  fingerprint: fp, severity: "medium", rule_id: "10038", title: "Content Security Policy Header Not Set",
  endpoint: "/rest/products", parameter: null, status, ...extra,
});

const findings = [
  finding("fp-open", "open"),
  finding("fp-ns-1", "not_scanned"),
  finding("fp-ns-2", "not_scanned"),
  finding("fp-expired", "open", {
    suppression: { reason: "accepted_risk", status: "approved", expires: "2026-01-31", expired: true },
  }),
];

const detail = {
  ...finding("fp-sqli", "new"),
  severity: "high", rule_id: "40018", title: "SQL Injection", endpoint: "/rest/user/login",
  parameter: "email", attack: "'", evidence: "SQLITE_ERROR: unrecognized token",
  solution: "Use parameterized queries.", references: "https://owasp.org/www-community/attacks/SQL_Injection",
  request_line: "POST /rest/user/login",
  replay: "curl -s -X POST 'http://juice:3000/rest/user/login' --data 'email=%27'",
};

const routes: Record<string, unknown> = {
  "/api/session": { actor: "tester", csrf_token: "c" },
  "/api/system": { zap: { url: "http://127.0.0.1:8080", reachable: true }, ai: { provider: "anthropic", available: false } },
  "/api/apps": [{ app_id: APP, environment_class: "dev", base_url: "http://juice:3000", latest_run: { scan_id: SCAN, status: "complete" } }],
  [`/api/apps/${APP}/runs`]: [{ scan_id: SCAN, status: "complete", started_at: "2026-10-21T09:00:00Z" }],
  [`/api/apps/${APP}/runs/${SCAN}`]: {
    scan_id: SCAN, status: "complete",
    counts: { high: 0, medium: 4, low: 0, info: 0 },
    lifecycle: { new: 0, open: 2, resolved: 0, not_scanned: 2, suppressed: 0 },
    coverage: { routes_tested: 359, rules: 113, truncated_rules: ["10104"], excluded: [], declared: null, exercised: null },
  },
  [`/api/apps/${APP}/runs/${SCAN}/findings`]: findings,
  [`/api/apps/${APP}/runs/${SCAN}/findings/fp-sqli`]: detail,
  [`/api/apps/${APP}/suppressions`]: [
    { fingerprint: "fp-expired", reason: "accepted_risk", justification: "until the fix ships", status: "approved",
      expires: "2026-01-31", expired: true, proposed_by: "dev", approved_by: "sec", decided_at: "2026-01-02T10:00:00Z" },
  ],
};

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(typeof input === "string" ? input : input.toString(), "http://127.0.0.1:8765");
    const body = routes[url.pathname];
    return new Response(JSON.stringify(body ?? { detail: { message: "not found", fix: null } }), {
      status: body === undefined ? 404 : 200, headers: { "Content-Type": "application/json" },
    });
  }));
});
afterEach(() => vi.unstubAllGlobals());

const mount = (path: string) => render(<MemoryRouter initialEntries={[path]}><AppRoutes /></MemoryRouter>);

describe("results page", () => {
  it("RES-3: lists and counts not_scanned findings", async () => {
    mount(`/apps/${APP}/runs/${SCAN}/results`);
    expect(await screen.findByTestId("lifecycle-not_scanned")).toHaveTextContent("2");
    const rows = await screen.findAllByTestId("findings-row");
    expect(rows).toHaveLength(findings.length);
    expect(screen.getAllByTestId("status-not_scanned")).toHaveLength(2);
  });

  it("TRI-5: shows an expired suppression as expired", async () => {
    mount(`/apps/${APP}/runs/${SCAN}/results`);
    const rows = await screen.findAllByTestId("findings-row");
    const expiredRow = rows.find((r) => within(r).queryByTestId("suppression-expired"));
    expect(expiredRow).toBeDefined();
  });
});

describe("finding detail", () => {
  it("RES-4: shows parameter, attack, evidence, fix, references and replay from the record", async () => {
    mount(`/apps/${APP}/runs/${SCAN}/findings/fp-sqli`);
    expect(await screen.findByTestId("finding-parameter")).toHaveTextContent("email");
    expect(screen.getByTestId("finding-attack")).toHaveTextContent("'");
    expect(screen.getByTestId("finding-evidence")).toHaveTextContent("SQLITE_ERROR: unrecognized token");
    expect(screen.getByTestId("finding-solution")).toHaveTextContent("Use parameterized queries.");
    expect(screen.getByTestId("finding-references")).toHaveTextContent("owasp.org");
    expect(screen.getByTestId("finding-replay")).toHaveTextContent("/rest/user/login");
  });
});

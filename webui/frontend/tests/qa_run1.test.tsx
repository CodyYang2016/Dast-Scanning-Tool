// Regression tests for manual QA run 1 (docs/ui-docs/ui_qa_findings.md), page half:
// QA-1, QA-3, QA-4, QA-5, QA-6, QA-7, QA-10, QA-11. Same approach as results.test.tsx: the app's
// own routes, with `fetch` answering in the API contract's shapes.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../src/App";

const APP = "juice-shop";
const SCAN = "20261022T120000Z";

const finding = (fp: string, status: string, extra: Record<string, unknown> = {}) => ({
  fingerprint: fp, severity: "medium", rule_id: "10096", title: "Timestamp Disclosure",
  endpoint: "/styles.css", parameter: null, status, ...extra,
});

// Three copies of one finding (ZAP reports it once per piece of evidence), as in the real run.
const findings = [
  finding("fp-dup", "open"), finding("fp-dup", "open"), finding("fp-dup", "open"),
  finding("fp-ns-1", "not_scanned", { endpoint: "/a" }),
  finding("fp-ns-2", "not_scanned", { endpoint: "/b" }),
  finding("fp-new", "new", { severity: "high", title: "SQL Injection", endpoint: "/rest/user/login", parameter: "email" }),
];

const passive = {
  ...finding("fp-csp", "open"), title: "Content Security Policy (CSP) Header Not Set", endpoint: "/",
  attack: null, evidence: null, solution: "Set a CSP header.", references: null,
  request_line: "GET /", replay: "curl -s 'http://juice:3000/'",
};

const run = {
  scan_id: SCAN, status: "complete", compared: "preview",
  counts: { high: 1, medium: 5, low: 0, info: 0 },
  lifecycle: { new: 1, open: 3, resolved: 0, not_scanned: 2, suppressed: 0 },
  coverage: { routes_tested: 314, rules: 113, truncated_rules: ["10104"],
              truncated: [{ id: "10104", name: "User Agent Fuzzer" }],
              excluded: [], declared: null, exercised: null },
};

const settings = {
  app_id: "orders-portal", etag: "e1", command: "python -m dast scan orders-portal",
  fields: [
    { path: "app_id", value: "orders-portal", tier: "A", editable: false, label: "Application id", help: "", owner: "SEC" },
    { path: "scope.exclude", value: [], tier: "A", editable: true, label: "Never touched", help: "", owner: "SEC", missing: true },
    { path: "scan.budgets.max_scan_min", value: 8, tier: "B", editable: true, label: "Time limit for the scan (minutes)", help: "", owner: "SEC" },
  ],
};

type Answer = { status?: number; body: unknown };
const GET: Record<string, unknown> = {
  "/api/session": { actor: "tester", csrf_token: "c" },
  "/api/system": { zap: { url: "http://127.0.0.1:8080", reachable: true }, ai: { provider: "anthropic", available: false } },
  "/api/apps": [{ app_id: APP, environment_class: "dev", base_url: "http://juice:3000", latest_run: { scan_id: SCAN, status: "complete" } }],
  [`/api/apps/${APP}/runs/${SCAN}`]: run,
  [`/api/apps/${APP}/runs/${SCAN}/findings`]: findings,
  [`/api/apps/${APP}/runs/${SCAN}/findings/fp-csp`]: passive,
  [`/api/apps/${APP}/suppressions`]: [],
  [`/api/apps/${APP}/settings`]: { ...settings, app_id: APP, fields: [] },
  "/api/apps/orders-portal/settings": settings,
  "/api/governance": { approvals: [], gaps: [], registry: { hosts: {}, prod_patterns: [] }, audit: [] },
};
const POST: Record<string, Answer> = {
  [`/api/apps/${APP}/publish/preview`]: { body: { count: 6, category: "dast-juice-shop", scan_id: SCAN } },
  "/api/apps/orders-portal/settings/preview": { status: 422, body: { detail: {
    message: "That change isn't valid: 'ten' is not of type 'integer'",
    fix: "Check the value's type and allowed choices.", field: "scan.budgets.max_scan_min" } } },
};

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input.toString(), "http://127.0.0.1:8765");
    const method = init?.method ?? "GET";
    const a: Answer | undefined = method === "GET"
      ? (url.pathname in GET ? { body: GET[url.pathname] } : undefined) : POST[url.pathname];
    return new Response(JSON.stringify(a?.body ?? { detail: { message: "not found", fix: null } }), {
      status: a ? a.status ?? 200 : 404, headers: { "Content-Type": "application/json" },
    });
  }));
});
afterEach(() => vi.unstubAllGlobals());

const mount = (path: string) => render(<MemoryRouter initialEntries={[path]}><AppRoutes /></MemoryRouter>);
const results = `/apps/${APP}/runs/${SCAN}/results`;

describe("QA-1 table cells stay table cells", () => {
  it("no <td> on the apps or results page is a flex row", async () => {
    const a = mount("/apps");
    await screen.findByText("Settings");
    expect(a.container.querySelectorAll("td.row")).toHaveLength(0);
    a.unmount();
    const r = mount(results);
    await screen.findAllByTestId("findings-row");
    expect(r.container.querySelectorAll("td.row")).toHaveLength(0);
  });
});

describe("QA-5 duplicate findings and the filter", () => {
  it("groups copies of one finding into one row with a count", async () => {
    mount(results);
    const rows = await screen.findAllByTestId("findings-row");
    expect(rows).toHaveLength(4);
    const dup = rows.find((r) => within(r).queryByTestId("findings-copies"));
    expect(dup).toBeDefined();
    expect(within(dup!).getByTestId("findings-copies")).toHaveTextContent("×3");
  });

  it("shows exactly the chosen status after switching the filter, and everything after switching back", async () => {
    mount(results);
    await screen.findAllByTestId("findings-row");
    const select = screen.getByLabelText("Filter findings");
    fireEvent.change(select, { target: { value: "not_scanned" } });
    let rows = screen.getAllByTestId("findings-row");
    expect(rows).toHaveLength(2);
    rows.forEach((r) => expect(within(r).getByTestId("status-not_scanned")).toBeInTheDocument());
    fireEvent.change(select, { target: { value: "all" } });
    rows = screen.getAllByTestId("findings-row");
    expect(rows).toHaveLength(4);
    expect(screen.getAllByTestId("status-open")).toHaveLength(1);
  });
});

describe("QA-10 and QA-11 on the results summary", () => {
  it("says a comparison isn't recorded yet", async () => {
    mount(results);
    expect(await screen.findByTestId("compared-note")).toHaveTextContent(/not recorded yet/i);
  });

  it("names a cut-short check", async () => {
    mount(results);
    await screen.findAllByTestId("findings-row");
    expect(screen.getByText(/User Agent Fuzzer \(10104\)/)).toBeInTheDocument();
  });
});

describe("QA-7 publishing opens in a dialog", () => {
  it("opens from the header, previews inside, and keeps what was typed when closed", async () => {
    mount(results);
    await screen.findAllByTestId("findings-row");
    expect(screen.queryByTestId("publish-dialog")).not.toBeVisible();
    fireEvent.click(screen.getByTestId("open-publish"));
    const dialog = screen.getByTestId("publish-dialog");
    expect(dialog).toBeVisible();
    fireEvent.change(within(dialog).getByLabelText("Owner"), { target: { value: "acme" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Preview" }));
    expect(await within(dialog).findByText(/Will send/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByTestId("publish-close"));
    expect(dialog).not.toBeVisible();
    fireEvent.click(screen.getByTestId("open-publish"));
    expect(within(dialog).getByLabelText("Owner")).toHaveValue("acme");
    expect(screen.getByTestId("equivalent-command")).toHaveTextContent("python -m dast report");
  });
});

describe("QA-6 passive findings", () => {
  it("explains empty fields instead of showing bare dashes", async () => {
    mount(`/apps/${APP}/runs/${SCAN}/findings/fp-csp`);
    expect(await screen.findByTestId("finding-passive-note")).toHaveTextContent(/nothing was sent to an input/);
    expect(screen.queryByTestId("finding-parameter")).toBeNull();
    expect(screen.queryByTestId("finding-attack")).toBeNull();
    expect(screen.queryByTestId("finding-evidence")).toBeNull();
    expect(screen.queryByText("—")).toBeNull();
  });
});

describe("QA-3 and QA-4 on the settings page", () => {
  it("lists a required setting the file doesn't have yet", async () => {
    mount("/apps/orders-portal/settings");
    const row = await screen.findByTestId("setting-scope.exclude");
    expect(within(row).getByTestId("setting-missing")).toHaveTextContent(/not in app.yaml yet/i);
  });

  it("shows a refused value beside its setting", async () => {
    mount("/apps/orders-portal/settings");
    const row = await screen.findByTestId("setting-scan.budgets.max_scan_min");
    fireEvent.change(within(row).getByRole("spinbutton"), { target: { value: "10" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(within(row).getByRole("alert")).toHaveTextContent("not of type"));
    const input = within(row).getByRole("spinbutton");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input.getAttribute("aria-describedby")).toBe(within(row).getByRole("alert").id);
  });
});

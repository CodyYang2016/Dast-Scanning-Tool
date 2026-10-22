// QA-12: record a form login from the settings page, and follow that job as a login, not a scan
// (also the Sign in (SSO) job). QA-13: the finding header doesn't repeat "CWE-".
// Same approach as qa_run1.test.tsx: the app's own routes, `fetch` answering in contract shapes.
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../src/App";

const field = (path: string, value: unknown, tier = "A") =>
  ({ path, value, tier, editable: tier !== "C", label: path, help: "", owner: "SEC" });

const settings = (app: string, mode: string, recorded: boolean) => ({
  app_id: app, etag: "e1", command: `python -m dast scan ${app}`, login_recorded: recorded,
  fields: [field("app_id", app), field("auth.mode", mode)],
});

const job = (status: string) => ({
  job_id: "j1", app_id: "x", command: "python -m dast author x", status, exit_code: status === "running" ? null : 0,
  actor: "tester", started_at: "2026-10-22T10:00:00Z", ended_at: null, scan_id: null,
});

const finding = (cwe: unknown) => ({
  fingerprint: "fp-sqli", severity: "high", rule_id: "40018", title: "SQL Injection", endpoint: "/rest/user/login",
  parameter: "email", status: "new", attack: "'", evidence: "500", solution: "Use parameterized queries.",
  references: null, request_line: "POST /rest/user/login", replay: "curl …", cwe_id: cwe, confidence: "low",
});

let GET: Record<string, unknown>;
let posted: { path: string; body: unknown }[];
let polls: number;

beforeEach(() => {
  posted = []; polls = 0;
  GET = {
    "/api/session": { actor: "tester", csrf_token: "c" },
    "/api/governance": { approvals: [], gaps: [], registry: { hosts: {}, prod_patterns: [] }, audit: [] },
    "/api/apps/new-app/settings": settings("new-app", "form", false),
    "/api/apps/juice-shop/settings": settings("juice-shop", "form", true),
    "/api/apps/intranet-sso/settings": settings("intranet-sso", "seeded", true),
    "/api/apps/juice-shop/suppressions": [],
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input.toString(), "http://127.0.0.1:8765");
    const method = init?.method ?? "GET";
    let body: unknown;
    if (method !== "GET") {
      posted.push({ path: url.pathname, body: init?.body ? JSON.parse(String(init.body)) : null });
      body = job("running");
    } else if (url.pathname === "/api/jobs/j1") {
      polls += 1;
      body = job(polls < 2 ? "running" : "succeeded");
    } else {
      body = GET[url.pathname];
    }
    return new Response(JSON.stringify(body ?? { detail: { message: "not found", fix: null } }), {
      status: body === undefined ? 404 : method === "GET" ? 200 : 201, headers: { "Content-Type": "application/json" },
    });
  }));
});
afterEach(() => vi.unstubAllGlobals());

const mount = (path: string) => render(<MemoryRouter initialEntries={[path]}><AppRoutes /></MemoryRouter>);

describe("QA-12 recording a form login from the settings page", () => {
  it("offers to record a login that hasn't been recorded, and follows the job as a login", async () => {
    mount("/apps/new-app/settings");
    expect(await screen.findByTestId("login-not-recorded")).toHaveTextContent(/hasn't been recorded/);
    fireEvent.click(screen.getAllByRole("button", { name: "Record the login" })[0]);
    expect(await screen.findByText(/Recording the login/)).toBeInTheDocument();
    expect(posted).toEqual([{ path: "/api/apps/new-app/jobs", body: { command: "author", options: {} } }]);
    expect(await screen.findByTestId("login-recorded", {}, { timeout: 4000 })).toHaveTextContent(/Login recorded/);
    expect(screen.queryByText(/before a run started/)).toBeNull();
  });

  it("still offers to record again when a login is recorded, without the banner", async () => {
    mount("/apps/juice-shop/settings");
    expect(await screen.findByRole("button", { name: "Record the login" })).toBeInTheDocument();
    expect(screen.queryByTestId("login-not-recorded")).toBeNull();
  });

  it("an SSO app signs in instead, and a successful sign-in isn't shown as an error", async () => {
    mount("/apps/intranet-sso/settings");
    fireEvent.click(await screen.findByRole("button", { name: "Sign in (SSO)" }));
    expect(screen.queryByRole("button", { name: "Record the login" })).toBeNull();
    expect(await screen.findByTestId("login-recorded", {}, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.queryByText(/before a run started/)).toBeNull();
  });
});

describe("QA-13 the CWE in the finding header", () => {
  it.each([["CWE-89"], [89]])("cwe_id %s reads CWE-89", async (cwe) => {
    GET["/api/apps/juice-shop/runs/r1/findings/fp-sqli"] = finding(cwe);
    mount("/apps/juice-shop/runs/r1/findings/fp-sqli");
    expect(await screen.findByText(/CWE-89/)).toBeInTheDocument();
    expect(screen.queryByText(/CWE-CWE/)).toBeNull();
  });
});

// The only way the UI talks to the server. Same origin, session cookie, and the CSRF token on
// every write (security.py). Errors carry the server's plain-language message and fix.
import type { ApiErrorDetail } from "./types";

export class ApiError extends Error {
  status: number;
  fix: string | null;
  constructor(status: number, detail: ApiErrorDetail) {
    super(detail.message);
    this.status = status;
    this.fix = detail.fix;
  }
}

let csrf: Promise<string> | null = null;

async function csrfToken(): Promise<string> {
  if (!csrf) {
    csrf = fetch("/api/session", { credentials: "same-origin" })
      .then((r) => r.json())
      .then((s) => s.csrf_token as string)
      .catch((e) => { csrf = null; throw e; });
  }
  return csrf;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = await csrfToken();
  const res = await fetch(path, {
    method, headers, credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data: unknown = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const detail = (data && typeof data === "object" && "detail" in data
      ? (data as { detail: ApiErrorDetail }).detail : null);
    throw new ApiError(res.status, detail && typeof detail === "object" && "message" in detail
      ? detail : { message: `The server answered ${res.status}.`, fix: null });
  }
  return data as T;
}

export const api = {
  get: <T,>(path: string) => request<T>("GET", path),
  post: <T,>(path: string, body: unknown = {}) => request<T>("POST", path, body),
  put: <T,>(path: string, body: unknown) => request<T>("PUT", path, body),
  text: async (path: string) => (await fetch(path, { credentials: "same-origin" })).text(),
};

export const enc = encodeURIComponent;

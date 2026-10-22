// Shapes from the API contract (docs/ui-docs/ui_acceptance_criteria.md §3).
export type Tier = "A" | "B" | "C" | "D";
export type Severity = "high" | "medium" | "low" | "info";
export type Lifecycle = "new" | "open" | "resolved" | "not_scanned" | "suppressed";

export interface Session { actor: string; csrf_token: string }
export interface System { zap: { url: string; reachable: boolean }; ai: { provider: string; available: boolean } }
export interface AppSummary {
  app_id: string; environment_class: string | null; base_url: string | null;
  latest_run: { scan_id: string; status: string } | null;
}
export interface SettingField {
  path: string; value: unknown; tier: Tier; editable: boolean; label: string; help: string;
  owner: string; secret?: { name: string; set: boolean };
}
export interface Settings { app_id: string; etag: string; command: string; fields: SettingField[] }
export interface RunSummary { scan_id: string; status: string; started_at: string | null }
export interface RunDetail {
  scan_id: string; status: string;
  counts: Record<Severity, number>; lifecycle: Record<Lifecycle, number>;
  coverage: { routes_tested: number; rules: number; truncated_rules: string[]; excluded: string[];
              truncated?: { id: string; name: string | null }[];
              declared: number | null; exercised: number | null };
}
export interface SuppressionInfo { reason: string; status: string; expires: string | null; expired: boolean }
export interface Finding {
  fingerprint: string; severity: Severity; rule_id: string; title: string; endpoint: string;
  parameter: string | null; status: Lifecycle; suppression?: SuppressionInfo;
}
export interface FindingDetail extends Finding {
  attack: string | null; evidence: string | null; solution: string | null;
  references: string | null; request_line: string | null; replay: string;
  description?: string | null; confidence?: string | null; cwe_id?: string | number | null;
}
export interface Suppression {
  fingerprint: string; reason: string; justification: string; status: string;
  expires: string | null; expired: boolean; proposed_by: string | null;
  approved_by: string | null; decided_at: string | null;
}
export interface Refusal { kind: string; message: string; fix: string }
export interface Job {
  job_id: string; app_id: string; command: string; status: "running" | "succeeded" | "failed" | "stopped";
  exit_code: number | null; actor: string; started_at: string; ended_at: string | null;
  scan_id: string | null; refusal?: Refusal; summary?: { steps_by_source: Record<string, number> };
}
export interface Governance {
  approvals: { app_id: string; path: string; value: unknown; approved_by: string | null; approved_at: string | null }[];
  gaps: { app_id: string; kind: string; item: string; decided: boolean }[];
  registry: { hosts: Record<string, string>; prod_patterns: string[] };
  audit: { ts: string; actor: string; app_id: string | null; event: string; detail: Record<string, unknown> }[];
}
export interface ApiErrorDetail { message: string; fix: string | null }

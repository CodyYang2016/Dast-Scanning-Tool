import { useState } from "react";
import { useParams } from "react-router-dom";
import { api, ApiError, enc } from "../api";
import { Card, ErrorNote, Loading, Tag, TitleBar } from "../components/ui";
import type { FindingDetail, Suppression } from "../types";
import { useApi } from "../useApi";

const SEV_TAG: Record<string, string> = { high: "bad", medium: "warn", low: "b", info: "d" };
const REASONS: [string, string][] = [["false_positive", "False positive"], ["accepted_risk", "Accepted risk"],
  ["wont_fix", "Won't fix"], ["test_data", "Test data"]];

export default function Finding() {
  const { app = "", scanId = "", fingerprint = "" } = useParams();
  const f = useApi<FindingDetail>(`/api/apps/${enc(app)}/runs/${enc(scanId)}/findings/${enc(fingerprint)}`);
  const supps = useApi<Suppression[]>(`/api/apps/${enc(app)}/suppressions`);
  const [reason, setReason] = useState("false_positive");
  const [why, setWhy] = useState("");
  const [expires, setExpires] = useState("");
  const [problem, setProblem] = useState<ApiError | null>(null);
  const current = supps.data?.find((s) => s.fingerprint === fingerprint);

  async function propose() {
    setProblem(null);
    try {
      await api.post(`/api/apps/${enc(app)}/suppressions`, { fingerprint, reason, justification: why, expires: expires || null });
      supps.reload(); f.reload();
    } catch (e) { setProblem(e as ApiError); }
  }
  async function approve() {
    setProblem(null);
    try { await api.post(`/api/apps/${enc(app)}/suppressions/${enc(fingerprint)}/approve`); supps.reload(); f.reload(); }
    catch (e) { setProblem(e as ApiError); }
  }

  if (f.loading && !f.data) return <Loading what="the finding" />;
  if (f.error) return <ErrorNote error={f.error} />;
  const d = f.data!;
  return (
    <>
      <TitleBar crumbs={[{ to: "/", label: "Overview" }, { to: `/apps/${enc(app)}/runs/${enc(scanId)}/results`, label: `${app} · ${scanId}` }, { label: "Finding" }]}
        title={<><Tag kind={SEV_TAG[d.severity] ?? "d"}>{d.severity}</Tag> {d.title}</>}
        sub={<>Rule {d.rule_id}{d.cwe_id ? ` · ${String(d.cwe_id).startsWith("CWE-") ? d.cwe_id : `CWE-${d.cwe_id}`}` : ""}{d.confidence ? ` · ${d.confidence} confidence` : ""} · <span className="mono">{d.endpoint}</span></>} />
      <div className="layout">
        <div className="stack">
          <Card title="What the scanner saw">
            <div className="fields">
              {/* Passive checks (headers, cookies) send nothing to an input: say so, rather than three dashes. */}
              {!d.parameter && !d.attack && !d.evidence
                ? <p className="body muted" data-testid="finding-passive-note">A passive check: the scanner read the
                    response; nothing was sent to an input.</p>
                : <>
                  {d.parameter && <div className="field"><div className="label"><b>Input that's vulnerable</b></div>
                    <div className="value value-display" data-testid="finding-parameter">{d.parameter}</div></div>}
                  {d.attack && <div className="field"><div className="label"><b>What was sent</b></div>
                    <div className="value value-display" data-testid="finding-attack">{d.attack}</div></div>}
                  {d.evidence && <div className="field"><div className="label"><b>What came back</b></div>
                    <div className="value value-display" data-testid="finding-evidence">{d.evidence}</div></div>}
                </>}
              {d.request_line && <div className="field"><div className="label"><b>Request</b></div>
                <div className="value value-display">{d.request_line}</div></div>}
            </div>
          </Card>
          <Card title="How to fix it">
            <div className="body">
              <p data-testid="finding-solution">{d.solution ?? "No fix text from the scanner."}</p>
              {d.description && <p className="muted mt">{d.description}</p>}
              <p className="mt mono-block" data-testid="finding-references">{d.references ?? "No references."}</p>
            </div>
          </Card>
          <Card title="Reproduce it yourself">
            <pre data-testid="finding-replay" tabIndex={0}>{d.replay}</pre>
          </Card>
        </div>
        <aside className="help-panel" aria-label="Triage">
          <Card title="Set this finding aside">
            <div className="body">
              {current ? (
                <>
                  <p><Tag kind={current.expired ? "warn" : "c"} testid="suppression-status">
                    {current.expired ? "expired" : current.status}</Tag> {current.reason.replace("_", " ")}</p>
                  {current.expired && <p data-testid="suppression-expired">This set-aside expired on {current.expires}, so the finding counts again.</p>}
                  <p>{current.justification}</p>
                  <p className="faint">Proposed by {current.proposed_by ?? "—"}{current.approved_by ? ` · approved by ${current.approved_by}` : ""}</p>
                  {current.status === "proposed" &&
                    <button className="btn primary" type="button" data-testid="approve-suppression" onClick={approve}>Approve</button>}
                </>
              ) : (
                <>
                  <label className="stacked"><span>Reason</span>
                    <select value={reason} onChange={(e) => setReason(e.target.value)}>
                      {REASONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
                  <label className="stacked"><span>Why (required)</span>
                    <textarea value={why} onChange={(e) => setWhy(e.target.value)} rows={3} /></label>
                  <label className="stacked"><span>Review again by{reason === "accepted_risk" || reason === "wont_fix" ? " (required)" : ""}</span>
                    <input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} /></label>
                  <p className="faint">Accepted risks always expire. A security engineer approves before it takes effect.</p>
                  <button className="btn primary" type="button" data-testid="propose-suppression" onClick={propose}>Propose</button>
                </>
              )}
              <ErrorNote error={problem} />
            </div>
          </Card>
        </aside>
      </div>
    </>
  );
}

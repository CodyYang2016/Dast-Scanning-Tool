import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, enc } from "../api";
import { Card, Command, ErrorNote, Loading, Metric, STATUS_TAG, Tag, TitleBar } from "../components/ui";
import type { Finding, Job, RunDetail, Settings } from "../types";
import { useApi } from "../useApi";

const SEVS = ["high", "medium", "low", "info"] as const;
const STATES = ["new", "open", "resolved", "not_scanned", "suppressed"] as const;
const SEV_TAG: Record<string, string> = { high: "bad", medium: "warn", low: "b", info: "d" };
const LABEL: Record<string, string> = { not_scanned: "not tested" };

type Pub = { destination: "code-scanning" | "issues"; owner: string; repo: string; ref: string; commit: string; token_env: string };

export default function Results() {
  const { app = "", scanId = "" } = useParams();
  const navigate = useNavigate();
  const run = useApi<RunDetail>(`/api/apps/${enc(app)}/runs/${enc(scanId)}`);
  const findings = useApi<Finding[]>(`/api/apps/${enc(app)}/runs/${enc(scanId)}/findings`);
  const settings = useApi<Settings>(`/api/apps/${enc(app)}/settings`);
  const [filter, setFilter] = useState<string>("all");
  const [pub, setPub] = useState<Pub>({ destination: "code-scanning", owner: "", repo: "", ref: "", commit: "", token_env: "GITHUB_TOKEN" });
  const [preview, setPreview] = useState<{ count: number; category: string; scan_id: string } | null>(null);
  const [problem, setProblem] = useState<ApiError | null>(null);

  useEffect(() => {        // prefill the destination from the app's own publish settings
    const v = (p: string) => String(settings.data?.fields.find((f) => f.path === p)?.value ?? "");
    if (settings.data) setPub((x) => ({ ...x, owner: v("publish.github.owner"), repo: v("publish.github.repo"),
      ref: v("publish.github.ref"), commit: v("publish.github.commit") }));
  }, [settings.data]);

  const command = ["python -m dast report", app, pub.destination === "issues" ? "--issues" : "--upload",
    "--owner", pub.owner || "<owner>", "--repo", pub.repo || "<repo>", "--ref", pub.ref || "<ref>",
    "--commit", pub.commit || "<deployed commit>"].join(" ");

  async function doPreview() {
    setProblem(null);
    try { setPreview(await api.post(`/api/apps/${enc(app)}/publish/preview`, pub)); }
    catch (e) { setProblem(e as ApiError); setPreview(null); }
  }
  async function publish() {
    setProblem(null);
    try {
      const j = await api.post<Job>(`/api/apps/${enc(app)}/publish`, pub);
      navigate(`/apps/${enc(app)}/runs/${enc(scanId)}/progress?job=${enc(j.job_id)}`);
    } catch (e) { setProblem(e as ApiError); }
  }

  const order = (f: Finding) => SEVS.indexOf(f.severity) * 10 + STATES.indexOf(f.status);
  const rows = (findings.data ?? []).filter((f) => filter === "all" || f.status === filter || f.severity === filter)
    .sort((a, b) => order(a) - order(b));
  const d = run.data;
  return (
    <>
      <TitleBar crumbs={[{ to: "/", label: "Overview" }, { to: "/findings", label: "Findings" }, { label: `${app} · ${scanId}` }]}
        title={`${app} — scan results`} sub={d ? `Run ${scanId} · ${d.status}` : undefined} />
      <ErrorNote error={run.error ?? findings.error} />
      {d && (
        <div className="cols-3 mb">
          <Metric label="Findings" value={SEVS.reduce((n, s) => n + d.counts[s], 0)}>
            <div className="row gap-sm">{SEVS.map((s) => (
              <span key={s}><Tag kind={SEV_TAG[s]} testid={`count-${s}`}>{d.counts[s]}</Tag> {s}</span>))}</div>
          </Metric>
          <Metric label="How much was tested" value={d.coverage.routes_tested} small="routes">
            <div className="faint">{d.coverage.rules} rules
              {d.coverage.truncated_rules.length > 0 && ` · cut short: ${d.coverage.truncated_rules.join(", ")}`}</div>
          </Metric>
          <Metric label="Compared with last time" value="">
            <div className="row gap-sm">{STATES.map((s) => (
              <span key={s}><Tag kind={STATUS_TAG[s]} testid={`lifecycle-${s}`}>{d.lifecycle[s]}</Tag> {LABEL[s] ?? s}</span>))}</div>
          </Metric>
        </div>)}
      <div className="layout">
        <div className="stack">
          <Card title="Findings" note={
            <label>Show <select value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter findings">
              <option value="all">all</option>{SEVS.map((s) => <option key={s} value={s}>{s}</option>)}
              {STATES.map((s) => <option key={s} value={s}>{LABEL[s] ?? s}</option>)}
            </select></label>}>
            {findings.loading && <Loading what="findings" />}
            {findings.data && (
              <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table className="findings">
                <thead><tr><th>Severity</th><th>Problem</th><th>Page</th><th>Input</th><th>Status</th></tr></thead>
                <tbody>{rows.map((f) => (
                  <tr key={f.fingerprint} data-testid="findings-row">
                    <td><Tag kind={SEV_TAG[f.severity] ?? "d"}>{f.severity}</Tag></td>
                    <td><Link to={`/apps/${enc(app)}/runs/${enc(scanId)}/findings/${enc(f.fingerprint)}`}>{f.title}</Link></td>
                    <td className="mono">{f.endpoint}</td>
                    <td className="mono">{f.parameter ?? "—"}</td>
                    <td className="row gap-sm">
                      <Tag kind={STATUS_TAG[f.status] ?? "d"} testid={`status-${f.status}`}>{LABEL[f.status] ?? f.status}</Tag>
                      {f.suppression && (f.suppression.expired
                        ? <Tag kind="warn" testid="suppression-expired">set-aside expired {f.suppression.expires}</Tag>
                        : <Tag kind="c" testid="suppression-status">{f.suppression.status === "proposed" ? "set-aside proposed" : "set aside"}</Tag>)}
                    </td>
                  </tr>))}</tbody>
              </table></div>)}
          </Card>
        </div>
        <aside className="help-panel" aria-label="Publish">
          <Card title="Publish to GitHub">
            <div className="body">
              <label className="stacked"><span>Where</span>
                <select value={pub.destination} onChange={(e) => setPub({ ...pub, destination: e.target.value as Pub["destination"] })}>
                  <option value="code-scanning">Code scanning alerts</option><option value="issues">Issues (no Advanced Security)</option>
                </select></label>
              <label className="stacked"><span>Owner</span><input value={pub.owner} onChange={(e) => setPub({ ...pub, owner: e.target.value })} /></label>
              <label className="stacked"><span>Repository</span><input value={pub.repo} onChange={(e) => setPub({ ...pub, repo: e.target.value })} /></label>
              <label className="stacked"><span>Deployed ref</span><input value={pub.ref} onChange={(e) => setPub({ ...pub, ref: e.target.value })} /></label>
              <label className="stacked"><span>Deployed commit</span><input value={pub.commit} placeholder="full SHA of the build that was scanned"
                onChange={(e) => setPub({ ...pub, commit: e.target.value })} /></label>
              <label className="stacked"><span>Token variable (name only)</span><input value={pub.token_env} onChange={(e) => setPub({ ...pub, token_env: e.target.value })} /></label>
              <ErrorNote error={problem} />
              {preview && <p>Will send <b>{preview.count}</b> results from run {preview.scan_id} as <code>{preview.category}</code>. Set-aside findings are still sent.</p>}
              <div className="row"><button className="btn" type="button" onClick={doPreview}>Preview</button>
                <button className="btn primary" type="button" onClick={publish} disabled={!preview}>Publish</button></div>
            </div>
          </Card>
          <Command text={command} />
        </aside>
      </div>
    </>
  );
}

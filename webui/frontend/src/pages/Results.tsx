import { useEffect, useRef, useState } from "react";
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
  // Publishing is a one-off, one-way action, so it opens in a dialog rather than a side panel
  // that has to stay reachable while the findings table scrolls (QA-7).
  const dialog = useRef<HTMLDialogElement>(null);
  const openPublish = () => {
    const d = dialog.current;
    if (!d || d.open) return;
    if (typeof d.showModal === "function") d.showModal(); else d.setAttribute("open", "");
  };
  const closePublish = () => {
    const d = dialog.current;
    if (!d) return;
    if (typeof d.close === "function") d.close(); else d.removeAttribute("open");
  };

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
  // ZAP reports the same rule, page and input once per piece of evidence, so a run holds several
  // copies of one finding. One row per finding, with the count: the fingerprint is then a unique
  // row key, and changing the filter can't leave stale rows behind (QA-5).
  const grouped = new Map<string, { f: Finding; n: number }>();
  for (const f of findings.data ?? []) {
    const g = grouped.get(f.fingerprint);
    if (g) g.n += 1; else grouped.set(f.fingerprint, { f, n: 1 });
  }
  const rows = [...grouped.values()].filter(({ f }) => filter === "all" || f.status === filter || f.severity === filter)
    .sort((a, b) => order(a.f) - order(b.f));
  const d = run.data;
  return (
    <>
      <TitleBar crumbs={[{ to: "/", label: "Overview" }, { to: "/findings", label: "Findings" }, { label: `${app} · ${scanId}` }]}
        title={`${app} — scan results`} sub={d ? `Run ${scanId} · ${d.status}` : undefined}
        actions={<button className="btn primary" type="button" data-testid="open-publish" onClick={openPublish}>
          Publish to GitHub…</button>} />
      <ErrorNote error={run.error ?? findings.error} />
      {d && (
        <div className="cols-3 mb">
          <Metric label="Findings" value={SEVS.reduce((n, s) => n + d.counts[s], 0)}>
            <div className="row gap-sm">{SEVS.map((s) => (
              <span key={s}><Tag kind={SEV_TAG[s]} testid={`count-${s}`}>{d.counts[s]}</Tag> {s}</span>))}</div>
            {findings.data && grouped.size < findings.data.length &&
              <div className="faint" data-testid="distinct-count">in {grouped.size} distinct problems</div>}
          </Metric>
          <Metric label="How much was tested" value={d.coverage.routes_tested} small="routes">
            <div className="faint">{d.coverage.rules} rules</div>
            {(d.coverage.truncated ?? []).length > 0 &&
              <div className="faint" data-testid="truncated-rules">
                {d.coverage.truncated!.length === 1 ? "1 check" : `${d.coverage.truncated!.length} checks`} cut short by
                {" "}its time limit: {d.coverage.truncated!.map((t) => t.name ? `${t.name} (${t.id})` : t.id).join(", ")}</div>}
          </Metric>
          <Metric label="Compared with last time" value="">
            {d.compared === "none"
              ? <p className="faint" data-testid="compared-note">Not compared with an earlier run: only the latest run is compared before it’s reported.</p>
              : <>
                <div className="row gap-sm">{STATES.map((s) => (
                  <span key={s}><Tag kind={STATUS_TAG[s]} testid={`lifecycle-${s}`}>{d.lifecycle[s]}</Tag> {LABEL[s] ?? s}</span>))}</div>
                {d.compared === "preview" &&
                  <p className="faint mt" data-testid="compared-note">Not recorded yet: publishing records this comparison.</p>}
              </>}
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
                <tbody>{rows.map(({ f, n }) => (
                  <tr key={f.fingerprint} data-testid="findings-row">
                    <td><Tag kind={SEV_TAG[f.severity] ?? "d"}>{f.severity}</Tag></td>
                    <td><Link to={`/apps/${enc(app)}/runs/${enc(scanId)}/findings/${enc(f.fingerprint)}`}>{f.title}</Link>
                      {n > 1 && <> <Tag kind="d" testid="findings-copies">×{n}</Tag></>}</td>
                    <td className="mono">{f.endpoint}</td>
                    <td className="mono">{f.parameter ?? "—"}</td>
                    <td><div className="row gap-sm">
                      <Tag kind={STATUS_TAG[f.status] ?? "d"} testid={`status-${f.status}`}>{LABEL[f.status] ?? f.status}</Tag>
                      {f.suppression && (f.suppression.expired
                        ? <Tag kind="warn" testid="suppression-expired">set-aside expired {f.suppression.expires}</Tag>
                        : <Tag kind="c" testid="suppression-status">{f.suppression.status === "proposed" ? "set-aside proposed" : "set aside"}</Tag>)}
                    </div></td>
                  </tr>))}</tbody>
              </table></div>)}
          </Card>
        </div>
        <aside className="help-panel" aria-label="Publish">
          <Command text={command} />
        </aside>
      </div>
      <dialog ref={dialog} className="dialog" aria-labelledby="publish-title" data-testid="publish-dialog">
        <div className="head"><h2 id="publish-title">Publish to GitHub</h2>
          <button className="btn ghost" type="button" data-testid="publish-close" aria-label="Close" onClick={closePublish}>✕</button></div>
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
      </dialog>
    </>
  );
}

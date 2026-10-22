import { Link } from "react-router-dom";
import { Card, ErrorNote, Loading, Metric, STATUS_TAG, Tag, TierTag, TitleBar, when } from "../components/ui";
import type { AppSummary, System } from "../types";
import { useApi } from "../useApi";
import { enc } from "../api";

const TASKS: [string, string, string, string][] = [
  ["Security engineer", "Onboard an application", "Answer a few questions; the tool finds the login for you.", "/onboard"],
  ["Security engineer", "Run or watch a scan", "Pick an app, start a scan, and stop safely at any time.", "/apps"],
  ["Developer", "Understand a finding", "What's wrong, how to reproduce it, how to fix it.", "/findings"],
  ["Security engineer", "Change an app's settings", "Every change is shown as a diff before it's saved.", "/apps"],
  ["Approver", "Review what scans may do", "Approvals, disclosed gaps and the audit trail.", "/governance"],
  ["Platform / DevOps", "Schedule scans in CI", "Download a ready workflow for the app's repository.", "/automate"],
];

export default function Overview() {
  const apps = useApi<AppSummary[]>("/api/apps");
  const system = useApi<System>("/api/system");
  return (
    <>
      <TitleBar title="Here's where scanning stands"
        sub="Everything here reads and writes the same files as the dast command line."
        actions={<Link className="btn primary" to="/onboard">Onboard an app</Link>} />
      <div className="layout">
        <div className="stack">
          <div className="cols-3">
            <Metric label="Applications" value={apps.data?.length ?? "—"} />
            <Metric label="ZAP" value={system.data ? (system.data.zap.reachable ? "Reachable" : "Not answering") : "—"}>
              <div className="faint">{system.data?.zap.url}</div>
            </Metric>
            <Metric label="AI provider" value={system.data ? (system.data.ai.available ? "Available" : "Not set up") : "—"}>
              <div className="faint">{system.data?.ai.provider}</div>
            </Metric>
          </div>
          <Card title="What would you like to do?">
            <div className="body tiles">
              {TASKS.map(([who, what, desc, to]) => (
                <Link key={what} className="card tile" to={to}>
                  <span className="who">{who}</span><b>{what}</b><span className="muted">{desc}</span>
                </Link>
              ))}
            </div>
          </Card>
          <Card title="Applications and their latest run">
            {apps.loading && <Loading what="applications" />}
            <ErrorNote error={apps.error} />
            {apps.data && (apps.data.length === 0
              ? <p className="empty">No applications yet. <Link to="/onboard">Onboard the first one.</Link></p>
              : <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table>
                  <thead><tr><th>Application</th><th>Environment</th><th>Latest run</th><th>Status</th></tr></thead>
                  <tbody>{apps.data.map((a) => (
                    <tr key={a.app_id}>
                      <td><Link to={`/apps/${enc(a.app_id)}/settings`}><b>{a.app_id}</b></Link></td>
                      <td>{a.environment_class ?? "—"}</td>
                      <td>{a.latest_run
                        ? <Link to={`/apps/${enc(a.app_id)}/runs/${enc(a.latest_run.scan_id)}/results`}>{a.latest_run.scan_id}</Link>
                        : "never scanned"}</td>
                      <td>{a.latest_run ? <Tag kind={STATUS_TAG[a.latest_run.status] ?? "d"}>{a.latest_run.status}</Tag> : "—"}</td>
                    </tr>))}</tbody>
                </table></div>)}
          </Card>
        </div>
        <aside className="help-panel" aria-label="Help">
          <Card title="How settings are grouped">
            <div className="body legend">
              <div><TierTag tier="A" /><span>The scan can't run without it, and there's no safe default.</span></div>
              <div><TierTag tier="B" /><span>Has a sensible default. Change it only if you need to.</span></div>
              <div><TierTag tier="C" /><span>Someone else decides: it changes what a scan may do.</span></div>
              <div><TierTag tier="D" /><span>A safety rule, or something the tool works out for you.</span></div>
            </div>
          </Card>
          <Card title="Updated"><div className="body"><p>{when(new Date().toISOString())}</p></div></Card>
        </aside>
      </div>
    </>
  );
}

import { Link } from "react-router-dom";
import { Card, ErrorNote, Loading, STATUS_TAG, Tag, TitleBar } from "../components/ui";
import type { AppSummary } from "../types";
import { useApi } from "../useApi";
import { enc } from "../api";

// Apps, runs, findings and automation all start from the list of applications.
export default function Apps({ purpose }: { purpose: "apps" | "runs" | "findings" | "automate" }) {
  const apps = useApi<AppSummary[]>("/api/apps");
  const titles = {
    apps: ["Applications", "Open an app to see its settings or start a scan."],
    runs: ["Runs", "The latest run of each application. Open one to watch it or see its results."],
    findings: ["Findings", "What each application's latest scan found."],
    automate: ["Automation", "Choose an application to get a CI workflow for it."],
  }[purpose];
  return (
    <>
      <TitleBar title={titles[0]} sub={titles[1]} />
      <Card>
        {apps.loading && <Loading what="applications" />}
        <ErrorNote error={apps.error} />
        {apps.data && (
          <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table>
            <thead><tr><th>Application</th><th>Address</th><th>Latest run</th><th>Open</th></tr></thead>
            <tbody>{apps.data.map((a) => {
              const run = a.latest_run;
              const base = `/apps/${enc(a.app_id)}`;
              return (
                <tr key={a.app_id}>
                  <td><b>{a.app_id}</b> <span className="faint">{a.environment_class}</span></td>
                  <td className="mono">{a.base_url}</td>
                  <td>{run ? <Tag kind={STATUS_TAG[run.status] ?? "d"}>{run.status}</Tag> : "never scanned"}</td>
                  <td><div className="row gap-sm">
                    {purpose === "apps" && <Link to={`${base}/settings`}>Settings</Link>}
                    {purpose === "automate" && <Link to={`${base}/automate`}>Get workflow</Link>}
                    {(purpose === "runs" || purpose === "apps") && run &&
                      <Link to={`${base}/runs/${enc(run.scan_id)}/progress`}>Run {run.scan_id}</Link>}
                    {(purpose === "findings" || purpose === "apps") && run &&
                      <Link to={`${base}/runs/${enc(run.scan_id)}/results`}>Results</Link>}
                  </div></td>
                </tr>);
            })}</tbody>
          </table></div>)}
      </Card>
    </>
  );
}

import { useParams } from "react-router-dom";
import { enc } from "../api";
import { Card, ErrorNote, Loading, TitleBar } from "../components/ui";
import { useApi } from "../useApi";

const RESULTS: [string, string][] = [["0", "Scan was healthy and the gate passed"],
  ["1", "New finding at or above the gate, or the scan wasn't healthy"],
  ["2", "Refused or misconfigured"], ["3", "AI was required but unavailable"]];

export default function Automate() {
  const { app = "" } = useParams();
  const wf = useApi<{ path: string; content: string }>(`/api/apps/${enc(app)}/workflow`);
  function download() {
    if (!wf.data) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([wf.data.content], { type: "text/yaml" }));
    a.download = wf.data.path.split("/").pop() ?? "dast.yml";
    a.click();
    URL.revokeObjectURL(a.href);
  }
  return (
    <>
      <TitleBar crumbs={[{ to: "/", label: "Overview" }, { to: "/automate", label: "Automation" }, { label: app }]}
        title={`Run ${app} scans automatically`}
        sub="The UI doesn't schedule anything. It gives you a workflow for the app's own repository."
        actions={<>
          <button className="btn" type="button" onClick={() => wf.data && navigator.clipboard?.writeText(wf.data.content)}>Copy</button>
          <button className="btn primary" type="button" onClick={download} disabled={!wf.data}>Download workflow</button>
        </>} />
      <div className="layout">
        <div className="stack">
          {wf.loading && <Loading what="the workflow" />}
          <ErrorNote error={wf.error} />
          {wf.data && <Card title={wf.data.path}><pre data-testid="workflow-yaml" tabIndex={0}>{wf.data.content}</pre></Card>}
        </div>
        <aside className="help-panel" aria-label="What the result means">
          <Card title="What the result means">
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table><tbody>
              {RESULTS.map(([c, m]) => <tr key={c}><td className="mono">{c}</td><td>{m}</td></tr>)}
            </tbody></table></div>
          </Card>
          <section className="card"><div className="band d"><span className="dot" aria-hidden="true" />Installation settings</div>
            <div className="body"><p>The package mirror, the corporate CA bundle and the pinned scanner image are set once by the platform team. They never appear while someone runs a scan.</p></div>
          </section>
        </aside>
      </div>
    </>
  );
}

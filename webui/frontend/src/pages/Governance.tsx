import { Card, ErrorNote, Loading, Metric, Tag, TitleBar, when } from "../components/ui";
import type { Governance as G } from "../types";
import { useApi } from "../useApi";

const show = (v: unknown) => (typeof v === "object" ? JSON.stringify(v) : String(v));

export default function Governance() {
  const g = useApi<G>("/api/governance");
  if (g.loading && !g.data) return <Loading what="governance" />;
  if (g.error) return <ErrorNote error={g.error} />;
  const d = g.data!;
  const undecided = d.gaps.filter((x) => x.kind === "posture" && !x.decided);
  return (
    <>
      <TitleBar crumbs={[{ to: "/", label: "Overview" }, { label: "Governance" }]} title="Governance"
        sub="What scans may do, what they deliberately don't test, and who did what. Read-only: approvals happen by review of app.yaml." />
      <div className="cols-3 mb">
        <Metric label="Approved settings" value={d.approvals.length} />
        <Metric label="Known gaps in testing" value={d.gaps.length} small={`${undecided.length} undecided`} />
        <Metric label="Audit entries" value={d.audit.length} />
      </div>
      <div className="layout">
        <div className="stack">
          <section className="card"><div className="band c"><span className="dot" aria-hidden="true" />Settings that needed approval</div>
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table>
              <thead><tr><th>Application</th><th>Setting</th><th>Value</th><th>Approved by</th><th>When</th></tr></thead>
              <tbody>{d.approvals.map((a) => (
                <tr key={`${a.app_id}:${a.path}`} data-testid="approval-row">
                  <td>{a.app_id}</td><td className="mono">{a.path}</td><td className="value-display">{show(a.value)}</td>
                  <td>{a.approved_by ?? <span className="faint">not committed yet</span>}</td>
                  <td className="nowrap">{when(a.approved_at)}</td></tr>))}</tbody>
            </table></div></section>
          <Card title="What scans deliberately don't test" note="each one is disclosed">
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table>
              <thead><tr><th>Where</th><th>Kind</th><th>Gap</th><th>Decided</th></tr></thead>
              <tbody>{d.gaps.map((x, i) => (
                <tr key={i} data-testid="gaps-row"><td>{x.app_id === "*" ? "All apps" : x.app_id}</td>
                  <td>{x.kind.replace("_", " ")}</td><td className="mono-block">{x.item}</td>
                  <td>{x.decided ? <Tag kind="ok">decided</Tag> : <Tag kind="warn">not decided</Tag>}</td></tr>))}</tbody>
            </table></div>
          </Card>
          <Card title="Audit trail" note="every scan, refusal and decision, newest first">
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table>
              <thead><tr><th>When</th><th>Who</th><th>Application</th><th>What</th></tr></thead>
              <tbody>{d.audit.slice(0, 300).map((e, i) => (
                <tr key={i} data-testid="audit-row"><td className="nowrap mono">{e.ts.replace("T", " ").slice(0, 19)}</td>
                  <td>{e.actor}</td><td>{e.app_id ?? "—"}</td><td className="mono-block">{e.event}</td></tr>))}</tbody>
            </table></div>
          </Card>
        </div>
        <aside className="help-panel" aria-label="Environment registry">
          <Card title="Environment registry">
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table>
              <thead><tr><th>Host</th><th>Type</th></tr></thead>
              <tbody>{Object.entries(d.registry.hosts).map(([h, c]) => <tr key={h}><td className="mono">{h}</td><td>{c}</td></tr>)}</tbody>
            </table></div>
            <div className="foot">Always refused: {d.registry.prod_patterns.join(" ")}</div>
          </Card>
        </aside>
      </div>
    </>
  );
}

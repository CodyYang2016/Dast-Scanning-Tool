import { useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, ApiError, enc } from "../api";
import { Card, ErrorNote, STATUS_TAG, Tag, TitleBar } from "../components/ui";
import type { Job, Refusal, RunDetail } from "../types";
import { useApi } from "../useApi";

type Ev = { ts?: string; event: string; [k: string]: unknown };
const STAGES: [string, string, string][] = [
  ["preflight", "Safety checks", "In scope, registered, not production"],
  ["auth", "Sign in", "Signed in and verified"],
  ["scan", "Scan", "Spider and active scan"],
  ["normalize", "Organise results", "Remove secrets, group duplicates"],
  ["coverage", "Check coverage", "What was and wasn't tested"],
];

function describe(e: Ev): string {
  const rest = Object.entries(e).filter(([k]) => !["ts", "scan_id", "app_id", "event", "actor"].includes(k))
    .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`).join(" ");
  return rest ? `${e.event} — ${rest}` : e.event;
}

export default function Progress() {
  const { app = "", scanId = "" } = useParams();
  const [params] = useSearchParams();
  const jobId = params.get("job");
  const [events, setEvents] = useState<Ev[]>([]);
  const [job, setJob] = useState<Job | null>(null);
  const [problem, setProblem] = useState<ApiError | null>(null);
  const run = useApi<RunDetail>(`/api/apps/${enc(app)}/runs/${enc(scanId)}`);

  useEffect(() => {
    setEvents([]);
    if (typeof EventSource === "undefined") return;
    const es = new EventSource(`/api/apps/${enc(app)}/runs/${enc(scanId)}/events`);
    es.onmessage = (m) => { try { setEvents((prev) => [...prev, JSON.parse(m.data)]); } catch { /* not JSON */ } };
    es.addEventListener("end", () => es.close());
    es.onerror = () => es.close();
    return () => es.close();
  }, [app, scanId]);

  useEffect(() => {
    if (!jobId) return;
    let live = true;
    const tick = async () => {
      try {
        const j = await api.get<Job>(`/api/jobs/${enc(jobId)}`);
        if (!live) return;
        setJob(j);
        if (j.status !== "running") run.reload();
        else setTimeout(tick, 1000);
      } catch (e) { if (live) setProblem(e as ApiError); }
    };
    tick();
    return () => { live = false; };
  }, [jobId]); // eslint-disable-line react-hooks/exhaustive-deps

  const status = job?.status === "running" ? "running" : run.data?.status ?? "running";
  const states = useMemo(() => {
    const seen = new Set(events.map((e) => e.event));
    const done = (k: string) => {
      if (status === "complete") return true;
      if (k === "preflight") return seen.has("preflight") && seen.has("auth");
      if (k === "auth") return seen.has("auth") && [...seen].some((s) => s.startsWith("scan"));
      return false;
    };
    let current = false;
    return STAGES.map(([k]) => {
      if (done(k)) return "done";
      if (!current && status === "running") { current = true; return "now"; }
      return "todo";
    });
  }, [events, status]);

  const abort = [...events].reverse().find((e) => e.event === "abort");
  const refusal: Refusal | null = job?.refusal ?? (abort ? {
    kind: String(abort.kind ?? "abort"), message: String(abort.reason ?? "The run stopped before scanning."),
    fix: String(abort.hint ?? "See the run's events below."),
  } : null);

  async function stop() {
    if (!jobId) return;
    try { await api.post(`/api/jobs/${enc(jobId)}/stop`); setJob(await api.get<Job>(`/api/jobs/${enc(jobId)}`)); run.reload(); }
    catch (e) { setProblem(e as ApiError); }
  }

  return (
    <>
      <TitleBar crumbs={[{ to: "/", label: "Overview" }, { to: "/runs", label: "Runs" }, { label: `${app} · ${scanId}` }]}
        title={<>{app} <Tag kind={STATUS_TAG[status] ?? "d"}>{status}</Tag></>}
        sub={job ? `Started by ${job.actor} · ${job.command}` : `Run ${scanId}`}
        actions={<>
          {status === "complete" && <Link className="btn primary" to={`/apps/${enc(app)}/runs/${enc(scanId)}/results`}>See results</Link>}
          {jobId && job?.status === "running" &&
            <button className="btn danger" type="button" data-testid="stop-run" onClick={stop}>Stop scan</button>}
        </>} />
      {refusal && <ErrorNote testid="refusal" error={refusal} />}
      <ErrorNote error={problem} />
      <div className="layout mt">
        <div className="stack">
          <Card>
            <div className="body"><ol className="timeline steps-nav">
              {STAGES.map(([k, title, desc], i) => (
                <li key={k} className="tl" data-testid={`run-stage-${k}`} data-state={states[i]}>
                  <div className="n" aria-hidden="true">{states[i] === "done" ? "✓" : i + 1}</div>
                  <b>{title}</b><p>{desc}</p>
                  <span className="sr-only">{states[i] === "done" ? "done" : states[i] === "now" ? "in progress" : "not started"}</span>
                </li>))}
            </ol></div>
          </Card>
          <Card title="Activity" note="from the run's audit log">
            {events.length === 0
              ? <p className="empty">No events yet.</p>
              : <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table>
                  <thead><tr><th>Time</th><th>What happened</th></tr></thead>
                  <tbody>{[...events].reverse().slice(0, 200).map((e, i) => (
                    <tr key={i}><td className="nowrap mono">{e.ts ? e.ts.slice(11, 19) : ""}</td><td className="mono-block">{describe(e)}</td></tr>
                  ))}</tbody>
                </table></div>}
          </Card>
        </div>
        <aside className="help-panel" aria-label="About stopping">
          <Card title="If you stop the scan">
            <div className="body">
              <p>It's recorded as <b>stopped</b>, not failed.</p>
              <p>Pages it didn't reach are marked <b>not tested</b>, never fixed.</p>
            </div>
          </Card>
        </aside>
      </div>
    </>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, enc } from "../api";
import { Card, Command, ErrorNote, Loading, Tag, TierBand, TitleBar, when } from "../components/ui";
import type { Governance, Job, SettingField, Settings as SettingsT, Tier } from "../types";
import { useApi } from "../useApi";

type Draft = Record<string, string>;

// Settings with a fixed set of values get a list to choose from rather than free text.
const CHOICES: Record<string, [string, string][]> = {
  environment_class: [["dev", "Development (dev)"], ["test", "Test"], ["staging", "Staging"]],
  "auth.mode": [["form", "A username and password form"], ["seeded", "SSO or MFA (a person signs in once)"]],
  "scan.policy.attack_strength": [["low", "Low"], ["medium", "Medium"], ["high", "High"], ["insane", "Insane"], ["default", "ZAP default"]],
  "scan.policy.alert_threshold": [["off", "Off"], ["low", "Low"], ["medium", "Medium"], ["high", "High"], ["default", "ZAP default"]],
  "explore.write_mode": [["deny", "No"], ["allow", "Yes"]],
};

const isScalarList = (v: unknown) => Array.isArray(v) && v.every((x) => typeof x !== "object" || x === null);

function toText(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (isScalarList(v)) return (v as unknown[]).join("\n");
  if (typeof v === "object") return JSON.stringify(v, null, 2);
  return String(v);
}

function parse(original: unknown, text: string): unknown {
  if (typeof original === "number") return text.trim() === "" ? null : Number(text);
  if (typeof original === "boolean") return text === "true";
  if (isScalarList(original)) return text.split("\n").map((s) => s.trim()).filter(Boolean);
  if (original !== null && typeof original === "object") return JSON.parse(text);
  return text;
}

function FieldRow({ f, draft, setDraft, error }: {
  f: SettingField; draft: Draft; setDraft: (d: Draft) => void; error?: ApiError | null;
}) {
  const id = `setting-input-${f.path}`;
  const errorId = `setting-error-${f.path}`;
  const invalid = error ? { "aria-invalid": true, "aria-describedby": errorId } : {};
  const text = f.path in draft ? draft[f.path] : toText(f.value);
  const changed = f.path in draft;
  const multiline = Array.isArray(f.value) || (f.value !== null && typeof f.value === "object");
  let control;
  if (!f.editable) {
    control = <div className="value-display">{toText(f.value) || "—"}</div>;
  } else if (CHOICES[f.path]) {
    control = (
      <select id={id} value={text} {...invalid} onChange={(e) => setDraft({ ...draft, [f.path]: e.target.value })}>
        {CHOICES[f.path].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>);
  } else if (typeof f.value === "boolean") {
    control = (
      <select id={id} value={text} {...invalid} onChange={(e) => setDraft({ ...draft, [f.path]: e.target.value })}>
        <option value="true">Yes</option><option value="false">No</option>
      </select>);
  } else if (multiline) {
    control = <textarea id={id} value={text} {...invalid} rows={Math.min(8, text.split("\n").length + 1)}
      onChange={(e) => setDraft({ ...draft, [f.path]: e.target.value })} />;
  } else {
    control = <input id={id} type={typeof f.value === "number" ? "number" : "text"} value={text} {...invalid}
      onChange={(e) => setDraft({ ...draft, [f.path]: e.target.value })} />;
  }
  return (
    <div className="field" data-testid={`setting-${f.path}`}>
      <div className="label">
        {f.editable ? <label htmlFor={id}><b>{f.label}</b></label> : <b>{f.label}</b>}
        <span>{f.path}</span>
      </div>
      <div className="value">
        {control}
        {error && <div className="field-error" id={errorId} role="alert"><b>{error.message}</b>
          {error.fix && <span> {error.fix}</span>}</div>}
        {f.missing && <div className="help"><Tag kind="warn" testid="setting-missing">Not in app.yaml yet</Tag>
          {" "}Required: fill it in and save to add it.</div>}
        {f.secret && (
          <div className="help">{f.secret.set
            ? <Tag kind="ok">{f.secret.name} is set</Tag>
            : <Tag kind="warn">{f.secret.name} isn't set in this shell</Tag>} · only the name is stored</div>)}
        {f.help && <div className="help">{f.help}</div>}
        {changed && <div className="help"><Tag kind="warn">Changed, not saved</Tag></div>}
      </div>
    </div>
  );
}

export default function Settings() {
  const { app = "" } = useParams();
  const navigate = useNavigate();
  const settings = useApi<SettingsT>(`/api/apps/${enc(app)}/settings`);
  const gov = useApi<Governance>("/api/governance");
  const [draft, setDraft] = useState<Draft>({});
  const [diff, setDiff] = useState<string | null>(null);
  const [problem, setProblem] = useState<ApiError | { message: string; fix: string | null } | null>(null);
  const [saved, setSaved] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [startRefusal, setStartRefusal] = useState<ApiError | null>(null);
  // What the running job is: a scan goes to its run; an author job (Record the login, or
  // Sign in (SSO)) stays here and ends with the login recorded (QA-12).
  const [jobKind, setJobKind] = useState<"scan" | "author" | null>(null);
  const [recorded, setRecorded] = useState(false);
  const advanced = useRef<HTMLDetailsElement>(null);
  const worked = useRef<HTMLDetailsElement>(null);
  // A refused change that names its setting is shown beside that setting, not only at the top (QA-4).
  const fieldError = problem instanceof ApiError && problem.field ? problem : null;
  useEffect(() => {
    if (!fieldError?.field) return;
    const tier = settings.data?.fields.find((x) => x.path === fieldError.field)?.tier;
    if (tier === "B" && advanced.current) advanced.current.open = true;
    if (tier === "D" && worked.current) worked.current.open = true;
    document.getElementById(`setting-input-${fieldError.field}`)?.focus();
  }, [fieldError, settings.data]);
  const rowError = (path: string) => (fieldError?.field === path ? fieldError : null);

  useEffect(() => { setDraft({}); setDiff(null); setProblem(null); }, [app]);

  const byTier = useMemo(() => {
    const groups: Record<Tier, SettingField[]> = { A: [], B: [], C: [], D: [] };
    settings.data?.fields.forEach((f) => groups[f.tier].push(f));
    return groups;
  }, [settings.data]);

  const approvals = useMemo(() => Object.fromEntries((gov.data?.approvals ?? [])
    .filter((a) => a.app_id === app).map((a) => [a.path, a])), [gov.data, app]);

  const mode = settings.data?.fields.find((f) => f.path === "auth.mode")?.value;

  function changes(): Record<string, unknown> | null {
    const out: Record<string, unknown> = {};
    for (const f of settings.data?.fields ?? []) {
      if (!(f.path in draft)) continue;
      try { out[f.path] = parse(f.value, draft[f.path]); }
      catch { setProblem({ message: `${f.label} isn't valid JSON.`, fix: null }); return null; }
    }
    return out;
  }

  async function preview() {
    const c = changes();
    if (!c || !settings.data) return;
    setProblem(null); setSaved(false);
    try {
      const r = await api.post<{ diff: string }>(`/api/apps/${enc(app)}/settings/preview`, { etag: settings.data.etag, changes: c });
      setDiff(r.diff);
    } catch (e) { setProblem(e as ApiError); setDiff(null); }
  }

  async function save() {
    const c = changes();
    if (!c || !settings.data) return;
    setProblem(null);
    try {
      const r = await api.put<{ diff: string }>(`/api/apps/${enc(app)}/settings`, { etag: settings.data.etag, changes: c });
      setDiff(r.diff); setDraft({}); setSaved(true); settings.reload(); gov.reload();
    } catch (e) { setProblem(e as ApiError); }
  }

  async function runScan() {
    setProblem(null); setStartRefusal(null); setRecorded(false); setJobKind("scan");
    try {
      const started = await api.post<Job>(`/api/apps/${enc(app)}/jobs`, { command: "scan", options: {} });
      setJob(started);
    } catch (e) { setStartRefusal(e as ApiError); }
  }

  async function signIn() {
    setProblem(null); setStartRefusal(null); setRecorded(false); setJobKind("author");
    try { setJob(await api.post<Job>(`/api/onboard/${enc(app)}/sign-in`)); }
    catch (e) { setProblem(e as ApiError); }
  }

  // A form login is recorded by `dast author <app>`, which a scan needs first (QA-12).
  async function recordLogin() {
    setProblem(null); setStartRefusal(null); setRecorded(false); setJobKind("author");
    try { setJob(await api.post<Job>(`/api/apps/${enc(app)}/jobs`, { command: "author", options: {} })); }
    catch (e) { setStartRefusal(e as ApiError); }
  }

  // Follow a started job: go to its run once it has one; show a refusal if it ends without.
  useEffect(() => {
    if (!job || job.status !== "running") return;
    const t = setInterval(async () => {
      const j = await api.get<Job>(`/api/jobs/${enc(job.job_id)}`);
      if (j.scan_id && j.status === "running") {
        clearInterval(t);
        navigate(`/apps/${enc(app)}/runs/${enc(j.scan_id)}/progress?job=${enc(j.job_id)}`);
      } else if (j.status !== "running") {
        clearInterval(t); setJob(j);
        if (jobKind === "author") {
          if (j.status === "succeeded") { setRecorded(true); settings.reload(); }
        } else if (j.scan_id && !j.refusal) navigate(`/apps/${enc(app)}/runs/${enc(j.scan_id)}/results`);
      }
    }, 700);
    return () => clearInterval(t);
  }, [job, app, navigate, jobKind]); // eslint-disable-line react-hooks/exhaustive-deps

  if (settings.loading && !settings.data) return <Loading what="settings" />;
  if (settings.error) return <ErrorNote error={settings.error} />;
  const s = settings.data!;
  const pending = Object.keys(draft).length;

  return (
    <>
      <TitleBar crumbs={[{ to: "/", label: "Overview" }, { to: "/apps", label: "Apps" }, { label: app }]}
        title={`${app} — settings`} sub={<>Saved in <code>security/dast/{app}/app.yaml</code></>}
        actions={<>
          <Link className="btn" to={`/apps/${enc(app)}/automate`}>Automate</Link>
          {mode === "seeded"
            ? <button className="btn" type="button" onClick={signIn} disabled={job?.status === "running"}>Sign in (SSO)</button>
            : <button className="btn" type="button" onClick={recordLogin} disabled={job?.status === "running"}>Record the login</button>}
          <button className="btn primary" type="button" onClick={runScan}
            disabled={job?.status === "running"}>Run a scan</button>
        </>} />
      {job?.status === "running" && <div className="alert info mb" role="status">
        <b>{jobKind === "author" ? "Recording the login…" : "Starting…"}</b><span>{job.command}</span></div>}
      {recorded && <div className="alert ok mb" role="status" data-testid="login-recorded">
        <b>Login recorded.</b><span>You can run a scan now.</span></div>}
      {s.login_recorded === false && mode !== "seeded" && !recorded && job?.status !== "running" &&
        <div className="alert warn mb" data-testid="login-not-recorded">
          <b>This app's login hasn't been recorded yet.</b>
          <span>Record it before running a scan: the tool signs in with the test account and saves the steps.</span>
          <div><button className="btn primary" type="button" onClick={recordLogin}>Record the login</button></div>
        </div>}
      {startRefusal && <ErrorNote testid="refusal" error={startRefusal} />}
      {job?.refusal && <ErrorNote testid="refusal" error={job.refusal} />}
      {job && jobKind === "scan" && job.status !== "running" && !job.refusal && !job.scan_id &&
        <ErrorNote testid="refusal" error={{ message: `The job ${job.status} before a run started.`,
          fix: "Open its log from the run list, or try again." }} />}
      <ErrorNote error={fieldError ? { message: "1 setting needs attention.", fix: "The reason is shown under it." } : problem} />
      <div className="layout mt">
        <div className="stack">
          <section className="card"><TierBand tier="A" />
            <div className="fields">{byTier.A.map((f) => <FieldRow key={f.path} f={f} draft={draft} setDraft={setDraft} error={rowError(f.path)} />)}</div>
          </section>
          <section className="card"><TierBand tier="B" />
            <details ref={advanced}>
              <summary>Advanced · {byTier.B.length} settings</summary>
              <div className="fields">{byTier.B.map((f) => <FieldRow key={f.path} f={f} draft={draft} setDraft={setDraft} error={rowError(f.path)} />)}</div>
            </details>
          </section>
          <section className="card"><TierBand tier="C" />
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Table, scrolls sideways"><table>
              <thead><tr><th>Setting</th><th>Current</th><th>Approved by</th><th>When</th></tr></thead>
              <tbody>{byTier.C.map((f) => (
                <tr key={f.path} data-testid={`setting-${f.path}`}>
                  <td><b>{f.label}</b><div className="faint mono">{f.path}</div></td>
                  <td className="value-display">{toText(f.value)}</td>
                  <td>{approvals[f.path]?.approved_by ?? <span className="faint">not committed yet</span>}</td>
                  <td className="nowrap">{when(approvals[f.path]?.approved_at)}</td>
                </tr>))}</tbody>
            </table></div>
            <div className="foot">To change one of these, open a pull request on <code>app.yaml</code>; Governance reviews it there.</div>
          </section>
          <section className="card"><TierBand tier="D" />
            <details ref={worked}>
              <summary>Worked out by the tool · {byTier.D.length} settings</summary>
              <div className="fields">{byTier.D.map((f) => <FieldRow key={f.path} f={f} draft={draft} setDraft={setDraft} error={rowError(f.path)} />)}</div>
            </details>
            <div className="foot">Always on: production is refused, out-of-scope requests are blocked before they're sent, and an untested page is never reported as fixed.</div>
          </section>
        </div>
        <aside className="help-panel" aria-label="Changes">
          <Card title={pending ? `${pending} unsaved change${pending > 1 ? "s" : ""}` : "No unsaved changes"}>
            {diff && <pre className="diff" data-testid="diff-preview" tabIndex={0}>{diff}</pre>}
            {saved && <div className="body"><span className="tag ok">Saved</span></div>}
            <div className="foot row">
              <button className="btn" type="button" onClick={() => { setDraft({}); setDiff(null); }} disabled={!pending}>Discard</button>
              <button className="btn" type="button" onClick={preview} disabled={!pending}>Preview</button>
              <span className="spacer" />
              <button className="btn primary" type="button" data-testid="save-settings" onClick={save} disabled={!pending}>Save</button>
            </div>
          </Card>
          <Command text={s.command} />
        </aside>
      </div>
    </>
  );
}

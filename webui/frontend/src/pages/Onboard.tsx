import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, ApiError, enc } from "../api";
import { Card, Command, ErrorNote, Tag, TitleBar } from "../components/ui";
import type { Job, System } from "../types";
import { useApi } from "../useApi";

// Only the tier A onboarding questions (ui_acceptance_criteria.md §4). Data is durable until an
// app owner attests otherwise, so "never touched" is always asked here.
type Form = {
  app_id: string; base_url: string; environment_class: "dev" | "test" | "staging";
  allow: string; exclude: string; mode: "form" | "seeded"; login_url: string;
  user_env: string; pass_env: string; routes: string;
};
type Proposal = { mode: string; problem?: string | null; steps: unknown[]; proof: Record<string, unknown>; authenticated_routes: string[] };
const STEPS = ["Application", "Where & what", "Login", "Pages to test"];

const hostOf = (url: string) => { try { return new URL(url).hostname; } catch { return ""; } };
const envName = (app: string) => app.replace(/-/g, "_").toUpperCase();

function SecretStatus({ name, path }: { name: string; path: string }) {
  const [set, setSet] = useState<boolean | null>(null);
  useEffect(() => {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) { setSet(null); return; }
    let live = true;
    api.get<{ set: boolean }>(`/api/secrets/${enc(name)}`).then((s) => live && setSet(s.set)).catch(() => live && setSet(null));
    return () => { live = false; };
  }, [name]);
  return (
    <span data-testid={`onboard-secret-status-${path}`}>
      {set === null ? <Tag kind="d">not checked</Tag> : set ? <Tag kind="ok">set in this shell</Tag>
        : <Tag kind="warn">not set in this shell</Tag>}
    </span>);
}

export default function Onboard() {
  const navigate = useNavigate();
  const [f, setF] = useState<Form>({ app_id: "", base_url: "", environment_class: "dev", allow: "", exclude: "",
    mode: "form", login_url: "", user_env: "", pass_env: "", routes: "" });
  const [refusal, setRefusal] = useState<ApiError | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [message, setMessage] = useState("");
  const [proposal, setProposal] = useState<Proposal | null>(null);

  // The step is mirrored in the URL (?step=2), so the browser's back and forward arrows move
  // through the wizard (QA-2). It's held in state too: the router applies a URL change as a
  // low-priority render, and the page must show the new step the moment Continue is clicked.
  // Back and forward are read from the browser's own popstate event, which fires even when the
  // router hasn't rendered the step just pushed. A step the form can't be on yet falls back to
  // the furthest one it can.
  const [, setParams] = useSearchParams();
  const [step, setStepNow] = useState(0);
  const furthest = !f.app_id || !f.base_url ? 0 : proposal ? 3 : 2;
  const furthestNow = useRef(furthest);
  furthestNow.current = furthest;
  const urlFor = (n: number): Record<string, string> => (n === 0 ? {} : { step: String(n + 1) });
  const setStep = (n: number, replace = false) => {
    setStepNow(n);
    setParams(urlFor(n), { replace });
  };
  useEffect(() => {
    const fromUrl = () => {
      const asked = Math.max(0, (Number(new URLSearchParams(window.location.search).get("step")) || 1) - 1);
      const allowed = Math.min(asked, furthestNow.current);
      setStepNow(allowed);
      if (allowed !== asked) setParams(urlFor(allowed), { replace: true });
    };
    fromUrl();                       // an address typed or bookmarked with ?step=N
    window.addEventListener("popstate", fromUrl);
    return () => window.removeEventListener("popstate", fromUrl);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // What step 1 last filled in by itself. A field still holding that is refreshed when the id or
  // address changes; one the person edited is left alone (QA-8).
  const prefilled = useRef({ allow: "", user_env: "", pass_env: "" });
  const [busy, setBusy] = useState(false);
  const set = (k: keyof Form) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  // With an AI provider the UI discovers the login, through ZAP when it's answering (QA-14).
  const system = useApi<System>("/api/system");
  const discovery = system.data?.ai.available
    ? ` --discover${system.data.zap.reachable ? ` --zap-proxy ${system.data.zap.url}` : ""}` : "";
  const command = `python -m dast onboard ${f.app_id || "<app>"} --base-url ${f.base_url || "<address>"} ` +
    `--environment-class ${f.environment_class} --auth ${f.mode} --login-url ${f.login_url || "/login"}${discovery}`;

  async function next() {
    setRefusal(null);
    setBusy(true);
    try {
      if (step === 0) {
        // Move on at once and check in the background; a refusal brings the person back here.
        const auto = { allow: hostOf(f.base_url), user_env: `${envName(f.app_id)}_USER`, pass_env: `${envName(f.app_id)}_PASS` };
        const last = prefilled.current;
        const fill = (k: keyof typeof auto, current: string) => (!current || current === last[k] ? auto[k] : current);
        setF((x) => ({ ...x, allow: fill("allow", x.allow), user_env: fill("user_env", x.user_env), pass_env: fill("pass_env", x.pass_env) }));
        prefilled.current = auto;
        setStep(1);
        try {
          await api.post("/api/onboard/check", { app_id: f.app_id, base_url: f.base_url, environment_class: f.environment_class });
        } catch (e) { navigate(-1); throw e; }   // undo the optimistic step, not add another
      } else if (step === 1) {
        setStep(2);
      } else if (step === 2) {
        const r = await api.post<{ job_id: string; mode: string; message: string }>("/api/onboard", {
          app_id: f.app_id, base_url: f.base_url, environment_class: f.environment_class, auth: f.mode,
          login_url: f.login_url || "/login", user_env: f.user_env, pass_env: f.pass_env });
        setMessage(r.message);
        setJob(await api.get<Job>(`/api/jobs/${enc(r.job_id)}`));
      }
    } catch (e) { setRefusal(e as ApiError); }
    finally { setBusy(false); }
  }

  // Wait for `dast onboard` to finish, then show what it proposed.
  useEffect(() => {
    if (!job || job.status !== "running") return;
    const t = setInterval(async () => {
      const j = await api.get<Job>(`/api/jobs/${enc(job.job_id)}`);
      if (j.status === "running") return;
      clearInterval(t);
      setJob(j);
      if (j.status !== "succeeded") {
        setRefusal(new ApiError(422, { message: "Onboarding didn't finish.", fix: "Check the address and login page, then try again." }));
        return;
      }
      const p = await api.get<Proposal>(`/api/onboard/${enc(f.app_id)}/proposal`);
      setProposal(p);
      setF((x) => ({ ...x, routes: x.routes || p.authenticated_routes.join("\n") }));
      setStep(3);
    }, 700);
    return () => clearInterval(t);
  }, [job, f.app_id]);

  async function confirm() {
    setRefusal(null);
    try {
      const routes = f.routes.split("\n").map((s) => s.trim()).filter(Boolean);
      await api.post(`/api/onboard/${enc(f.app_id)}/confirm`, { proof_confirmed: true, authenticated_routes: routes });
      const s = await api.get<{ etag: string }>(`/api/apps/${enc(f.app_id)}/settings`);
      const changes: Record<string, unknown> = { "scope.allow": f.allow.split(/[\s,]+/).filter(Boolean) };
      const exclude = f.exclude.split("\n").map((x) => x.trim()).filter(Boolean);
      if (exclude.length) changes["scope.exclude"] = exclude;
      try { await api.put(`/api/apps/${enc(f.app_id)}/settings`, { etag: s.etag, changes }); } catch { /* shown on the settings page */ }
      navigate(`/apps/${enc(f.app_id)}/settings`);
    } catch (e) { setRefusal(e as ApiError); }
  }

  const proofText = proposal ? JSON.stringify(proposal.proof) : "";
  return (
    <>
      <TitleBar crumbs={[{ to: "/", label: "Overview" }, { label: "Onboard" }]}
        title={f.app_id ? `Onboard ${f.app_id}` : "Onboard an application"}
        sub={`Step ${step + 1} of ${STEPS.length} · ${STEPS[step]}. Only what the tool can't work out itself.`} />
      <Card className="mb"><div className="body"><ol className="timeline steps-nav">
        {STEPS.map((s, i) => (
          <li key={s} className="tl" data-state={i < step ? "done" : i === step ? "now" : "todo"}>
            <div className="n" aria-hidden="true">{i < step ? "✓" : i + 1}</div><b>{s}</b>
          </li>))}
      </ol></div></Card>
      <div className="layout">
        <div className="stack">
          <section className="card" data-testid="onboard-step">
            <div className="band a"><span className="dot" aria-hidden="true" />Required <small>— the tool can't scan without these</small></div>
            <div className="body stack">
              {step === 0 && <>
                <label className="stacked"><span>Application id</span>
                  <input data-testid="onboard-field-app_id" value={f.app_id} onChange={set("app_id")} placeholder="orders-portal" /></label>
                <label className="stacked"><span>Address (as the scanner reaches it)</span>
                  <input data-testid="onboard-field-base_url" value={f.base_url} onChange={set("base_url")} placeholder="https://orders.test.example.internal" /></label>
                <label className="stacked"><span>Environment</span>
                  <select data-testid="onboard-field-environment_class" value={f.environment_class} onChange={set("environment_class")}>
                    <option value="dev">Development</option><option value="test">Test</option><option value="staging">Staging</option></select></label>
              </>}
              {step === 1 && <>
                <label className="stacked"><span>Hosts in scope (the attack boundary)</span>
                  <input data-testid="onboard-field-scope.allow" value={f.allow} onChange={set("allow")} /></label>
                <label className="stacked"><span>Never touched: endpoints that reach real people or partners (one per line)</span>
                  <textarea data-testid="onboard-field-scope.exclude" value={f.exclude} onChange={set("exclude")} rows={3}
                    placeholder={"/api/notify/email\n/api/payments/"} /></label>
                <p className="faint">This app's data is treated as durable until its owner attests otherwise, so the scan stays off these.</p>
              </>}
              {step === 2 && <>
                <fieldset data-testid="onboard-field-auth.mode" className="cols-2">
                  <legend className="sr-only">How people sign in</legend>
                  <label className={`choice ${f.mode === "form" ? "on" : ""}`}><b><input type="radio" name="mode" value="form"
                    checked={f.mode === "form"} onChange={() => setF({ ...f, mode: "form" })} /> A username and password form</b>
                    <span className="muted">The tool fills the form in, every scan.</span></label>
                  <label className={`choice ${f.mode === "seeded" ? "on" : ""}`}><b><input type="radio" name="mode" value="seeded"
                    checked={f.mode === "seeded"} onChange={() => setF({ ...f, mode: "seeded" })} /> SSO or MFA</b>
                    <span className="muted">A person signs in once in a browser window.</span></label>
                </fieldset>
                <label className="stacked"><span>Login page</span>
                  <input data-testid="onboard-field-auth.login_url" value={f.login_url} onChange={set("login_url")} placeholder="/login" /></label>
                <div className="cols-2">
                  <label className="stacked"><span>Test account username is kept in (variable name) <SecretStatus name={f.user_env} path="auth.credentials.email_env" /></span>
                    <input data-testid="onboard-field-auth.credentials.email_env" value={f.user_env} onChange={set("user_env")} /></label>
                  <label className="stacked"><span>Test account password is kept in (variable name) <SecretStatus name={f.pass_env} path="auth.credentials.password_env" /></span>
                    <input data-testid="onboard-field-auth.credentials.password_env" value={f.pass_env} onChange={set("pass_env")} /></label>
                </div>
                <div className="alert info"><b>The tool never sees or saves the password itself.</b>
                  <span>Only the variable's name goes in the settings file. Set the variable in the shell that started the UI.</span></div>
                {job?.status === "running" && <p role="status">{message}</p>}
              </>}
              {step === 3 && proposal && <>
                {proposal.mode === "skeleton" ? (
                  <div className="alert warn" role="status">
                    <b>{proposal.problem ? "Discovery couldn't verify how to tell you're signed in." : "No AI provider, so the login wasn't discovered."}</b>
                    {proposal.problem && <span className="mono-block">{proposal.problem}</span>}
                    <span>The app will be saved with a starting point. Before scanning, set its login steps and
                      its signed-in check under Settings → "Worked out by the tool".</span>
                  </div>
                ) : (
                  <>
                    <p>{message}</p>
                    <div className="alert warn">
                      <b>One question for you</b>
                      <span>After signing in, the tool checks <code>{proofText}</code>. Does that only hold when someone is signed in?</span>
                    </div>
                  </>
                )}
                <label className="stacked"><span>Pages to test (one per line, at least one signed-in page)</span>
                  <textarea data-testid="onboard-field-record.authenticated_routes" value={f.routes} onChange={set("routes")} rows={3} /></label>
                <div className="row">
                  <button className="btn primary" type="button" data-testid="proof-confirm" onClick={confirm}>
                    {proposal.mode === "skeleton" ? "Save the starting point" : "Yes, save this app"}</button>
                  <button className="btn" type="button" onClick={() => setStep(2)}>No, go back</button>
                </div>
              </>}
              <ErrorNote error={refusal} testid="onboard-refusal" />
            </div>
            <div className="foot row">
              <button className="btn" type="button" onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0}>Back</button>
              <span className="spacer" />
              {step < 3
                ? <button className="btn primary" type="button" data-testid="onboard-continue" onClick={next}
                    disabled={busy || job?.status === "running"}>
                    {step === 2 ? (job?.status === "running" ? "Checking the login…" : "Check the login") : "Continue"}</button>
                : <button className="btn" type="button" data-testid="onboard-continue"
                    onClick={() => document.querySelector<HTMLElement>("[data-testid='proof-confirm']")?.focus()}>
                    Answer the question above</button>}
            </div>
          </section>
        </div>
        <aside className="help-panel" aria-label="Help">
          <Card title="What this means"><div className="body">
            <p><b>Why the signed-in check matters.</b> During a scan the tool keeps checking it. If it stops holding, the session was lost: the tool signs in again or stops, rather than reporting "nothing found".</p>
            <p><b>Why SSO is different.</b> Single sign-on and MFA can't be automated safely, so a person signs in once and the session is reused until it expires.</p>
          </div></Card>
          <Command text={command} />
        </aside>
      </div>
    </>
  );
}

import type { ReactNode } from "react";
import { Link, NavLink } from "react-router-dom";
import type { ApiError } from "../api";
import type { Tier } from "../types";

const NAV: [string, string, string][] = [
  ["/", "Overview", "nav-overview"], ["/onboard", "Onboard", "nav-onboard"],
  ["/apps", "Apps", "nav-apps"], ["/runs", "Runs", "nav-runs"],
  ["/findings", "Findings", "nav-findings"], ["/governance", "Governance", "nav-governance"],
  ["/automate", "Automation", "nav-automation"],
];

export function Layout({ actor, children }: { actor?: string; children: ReactNode }) {
  return (
    <>
      <a className="skip-link" href="#main">Skip to content</a>
      <header className="appbar">
        <div className="logo"><i aria-hidden="true" />DAST Workspace</div>
        <nav aria-label="Main">
          {NAV.map(([to, label, id]) => (
            <NavLink key={to} to={to} end={to === "/"} data-testid={id}
              className={({ isActive }) => (isActive ? "on" : "")}>{label}</NavLink>
          ))}
        </nav>
        <div className="me">{actor ? <>Signed in as <b>{actor}</b> · this machine only</> : null}</div>
      </header>
      <main id="main" className="page">{children}</main>
    </>
  );
}

export function TitleBar({ crumbs, title, sub, actions }: {
  crumbs?: { to?: string; label: string }[]; title: ReactNode; sub?: ReactNode; actions?: ReactNode;
}) {
  return (
    <>
      {crumbs && (
        <nav aria-label="Breadcrumb" className="crumbs">
          {crumbs.map((c, i) => (
            <span key={i}>{i > 0 && " / "}{c.to ? <Link to={c.to}>{c.label}</Link> : c.label}</span>
          ))}
        </nav>
      )}
      <div className="titlebar">
        <div><h1>{title}</h1>{sub && <p className="sub">{sub}</p>}</div>
        {actions && <div className="actions">{actions}</div>}
      </div>
    </>
  );
}

export function Card({ title, note, children, className = "" }: {
  title?: ReactNode; note?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {title && <div className="head"><h2>{title}</h2>{note && <span className="note">{note}</span>}</div>}
      {children}
    </section>
  );
}

const TIER_WORDS: Record<Tier, [string, string]> = {
  A: ["Required", "no safe default; the scan won't start without these"],
  B: ["Optional", "sensible defaults; change only if you need to"],
  C: ["Needs approval", "changes what a scan may do; changed by review of app.yaml, not here"],
  D: ["Always on", "safety rules, and things the tool works out for you"],
};
const TIER_CLASS: Record<Tier, string> = { A: "a", B: "b", C: "c", D: "d" };

export function TierBand({ tier }: { tier: Tier }) {
  const [name, note] = TIER_WORDS[tier];
  return (
    <div className={`band ${TIER_CLASS[tier]}`} data-testid={`tier-band-${tier}`}>
      <span className="dot" aria-hidden="true" />{name} <small>— {note}</small>
    </div>
  );
}

export function TierTag({ tier }: { tier: Tier }) {
  return <span className={`tag ${TIER_CLASS[tier]}`}>{TIER_WORDS[tier][0]}</span>;
}

export function Tag({ kind, children, testid }: { kind: string; children: ReactNode; testid?: string }) {
  return <span className={`tag ${kind}`} data-testid={testid}>{children}</span>;
}

export const STATUS_TAG: Record<string, string> = {
  new: "bad", open: "warn", resolved: "ok", not_scanned: "d", suppressed: "c",
  running: "run", complete: "ok", succeeded: "ok", stopped: "warn", aborted: "bad", failed: "bad",
};

export function ErrorNote({ error, testid }: { error: { message: string; fix?: string | null } | ApiError | null; testid?: string }) {
  if (!error) return null;
  return (
    <div className="alert bad" role="alert" data-testid={testid}>
      <b>{error.message}</b>
      {error.fix && <span>{error.fix}</span>}
    </div>
  );
}

export function Command({ text }: { text: string }) {
  return (
    <Card title="Same thing on the command line">
      <pre data-testid="equivalent-command" tabIndex={0}>{text}</pre>
    </Card>
  );
}

export function Loading({ what }: { what: string }) {
  return <p className="empty" role="status">Loading {what}…</p>;
}

export function Metric({ label, value, small, testid, children }: {
  label: string; value: ReactNode; small?: ReactNode; testid?: string; children?: ReactNode;
}) {
  return (
    <div className="card metric">
      <div className="label">{label}</div>
      <div className="value" data-testid={testid}>{value}{small && <small> {small}</small>}</div>
      {children}
    </div>
  );
}

export const when = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";

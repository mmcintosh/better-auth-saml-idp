import { type ReactNode, useState } from "react";

export function Card({ title, subtitle, actions, children }: { title: string; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>{title}</h2>
          {subtitle ? <p className="muted">{subtitle}</p> : null}
        </div>
        {actions ? <div className="row">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

export function Pill({ tone = "neutral", children }: { tone?: "ok" | "warn" | "bad" | "neutral" | "info"; children: ReactNode }) {
  return <span className={`pill ${tone}`}>{children}</span>;
}

/** A value with a copy button: entity IDs and URLs that go into an SP's settings. */
export function Copy({ value, href }: { value: string; href?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="copy">
      {href ? <a href={value} target="_blank" rel="noreferrer"><code>{value}</code></a> : <code>{value}</code>}
      <button type="button" className="ghost small" onClick={() => void navigator.clipboard.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); })}>
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint ? <small className="muted">{hint}</small> : null}
    </label>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function KeyValue({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

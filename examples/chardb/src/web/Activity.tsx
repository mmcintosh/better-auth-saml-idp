import { useState } from "react";
import type { Notify } from "./App.tsx";
import { orgName, useTenants } from "./data.ts";
import { type Me, saml, shortDate, useLoad } from "./lib.ts";
import { Card, Empty, Pill } from "./ui.tsx";

interface AuditEvent { type: string; at: string; spId: string | null; userId: string | null; code: string | null; tenantId: string | null; details: Record<string, unknown> | null }

const TONE: Record<string, "ok" | "bad" | "info" | "neutral"> = { "assertion.issued": "ok", denied: "bad", logout: "info", "session.ended": "neutral", "tenant.changed": "info", "service-provider.changed": "info" };

/** The plugin's audit log (GET /saml-idp/audit), newest first; a tenant's admins see only their tenants'. */
export function Activity({ me }: { me: Me; notify: Notify }) {
  const t = useTenants(me);
  const scopes: [string, string][] = [
    ...(me.samlAdmin ? ([["*", "All"], ["", "Root IdP"]] as [string, string][]) : []),
    ...(t.data?.tenants ?? []).map((x) => [x.organizationId, orgName(t.data?.organizations, x.organizationId)] as [string, string]),
  ];
  const [picked, setPicked] = useState<string | null>(null);
  const scope = picked ?? scopes[0]?.[0] ?? null;
  const [before, setBefore] = useState<string[]>([]);
  const page = before[before.length - 1];
  const events = useLoad(async () => {
    if (scope === null) return [] as AuditEvent[];
    const q = new URLSearchParams({ limit: "25" });
    if (scope !== "*") q.set("tenantId", scope);
    if (page) q.set("before", page);
    return (await saml(`/audit?${q}`)).events as AuditEvent[];
  }, [scope, page]);

  // Until the tenants this user can see are known, the scopes (and so the page) aren't either.
  if (t.loading && !t.data) return <p className="muted">Loading…</p>;
  if (!t.loading && scopes.length === 0)
    return (
      <>
        <header className="page-head"><h1>Activity</h1></header>
        <p className="notice">The audit log is for the host's SAML admins, and for the owners and admins of a tenant's organization (their tenant's events only).</p>
      </>
    );

  return (
    <>
      <header className="page-head">
        <h1>Activity</h1>
        <p className="muted">The plugin's audit log, stored in CharDB: assertions issued, refusals with their reason, logouts, ended sessions, and every change to tenants, keys and SPs with who made it.</p>
      </header>
      <div className="tabs">
        {scopes.map(([id, label]) => <button type="button" key={id || "root"} className={scope === id ? "tab active" : "tab"} onClick={() => { setPicked(id); setBefore([]); }}>{label}</button>)}
      </div>
      <Card title="Events" actions={<button type="button" className="ghost" onClick={() => events.reload()}>Refresh</button>}>
        {events.error ? <p className="error">{events.error}</p> : null}
        {events.data?.length === 0 ? <Empty>No events{page ? " before this point" : " yet"}.</Empty> : null}
        {events.data?.length ? (
          <table className="table">
            <thead><tr><th>When</th><th>Event</th>{scope === "*" ? <th>IdP</th> : null}<th>SP</th><th>User</th><th>Detail</th></tr></thead>
            <tbody>
              {events.data.map((e, i) => (
                <tr key={`${e.at}-${i}`}>
                  <td className="nowrap">{shortDate(e.at)}</td>
                  <td><Pill tone={TONE[e.type] ?? "neutral"}>{e.type}</Pill></td>
                  {scope === "*" ? <td>{orgName(t.data?.organizations, e.tenantId)}</td> : null}
                  <td><code>{e.spId ?? ""}</code></td>
                  <td>{e.userId ? <code className="small" title={e.userId}>{e.userId.slice(0, 8)}…</code> : null}</td>
                  <td className="small">{detail(e)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
        <div className="row top">
          {before.length ? <button type="button" className="ghost" onClick={() => setBefore(before.slice(0, -1))}>Newer</button> : null}
          {events.data?.length === 25 ? <button type="button" className="ghost" onClick={() => setBefore([...before, events.data?.[24]?.at ?? ""])}>Older</button> : null}
        </div>
      </Card>
    </>
  );
}

function detail(e: AuditEvent): string {
  const d = e.details ?? {};
  const parts = [e.code, d.action, d.kid && `key ${d.kid}`, d.forced && "forced", d.delegated && "by a tenant admin", d.initiatedBy && `${d.initiatedBy}-initiated`, d.detail, d.reason];
  return parts.filter(Boolean).map(String).join(" · ");
}

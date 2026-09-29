import { useState } from "react";
import type { Notify } from "./App.tsx";
import { orgName, useTenants } from "./data.ts";
import { call, type Me, saml, shortDate, useAction, useLoad } from "./lib.ts";
import { Card, Empty, Field, Pill } from "./ui.tsx";

interface SpRecord {
  id: string;
  entityId: string;
  source: "code" | "database";
  enabled: boolean;
  valid: boolean;
  issues: string[];
  warnings: string[];
  config?: Record<string, unknown>;
  tenantId?: string | null;
  updatedAt?: string;
}

/** "*": every SP (host admins); "": the root IdP's; else a tenant's organization id. */
type Scope = string;

export function ServiceProviders({ me, notify }: { me: Me; notify: Notify }) {
  const t = useTenants(me);
  const tenants = t.data?.tenants ?? [];
  const scopes: [Scope, string][] = [
    ...(me.samlAdmin ? ([["*", "All"], ["", "Root IdP"]] as [Scope, string][]) : []),
    ...tenants.map((x) => [x.organizationId, orgName(t.data?.organizations, x.organizationId)] as [Scope, string]),
  ];
  const [picked, setScope] = useState<Scope | null>(null);
  const scope = picked ?? scopes[0]?.[0] ?? null;
  const sps = useLoad(async () => {
    if (scope === null) return [] as SpRecord[];
    return (await saml(`/service-providers${scope === "*" ? "" : `?tenantId=${encodeURIComponent(scope)}`}`)).serviceProviders as SpRecord[];
  }, [scope]);
  const { busy, run } = useAction(notify);
  const [editing, setEditing] = useState<{ mode: "create" | "update"; id: string; json: string; enabled: boolean } | null>(null);
  const [newId, setNewId] = useState("");
  const [xml, setXml] = useState("");
  const [convertWarnings, setConvertWarnings] = useState<string[]>([]);

  const tenantOfScope = scope && scope !== "*" ? scope : undefined;
  const open = (mode: "create" | "update", id: string, config: object, enabled: boolean) => setEditing({ mode, id, json: JSON.stringify(config, null, 2), enabled });

  async function save() {
    if (!editing) return;
    let config: unknown;
    try {
      config = JSON.parse(editing.json);
    } catch (e) {
      return notify(`The configuration isn't valid JSON: ${(e as Error).message}`, "err");
    }
    const ok = await run(
      () => (editing.mode === "create" ? saml("/service-providers/create", { serviceProvider: config, enabled: editing.enabled }) : saml("/service-providers/update", { id: editing.id, serviceProvider: config, enabled: editing.enabled })),
      `Saved ${editing.id}.`,
    );
    if (ok) {
      setEditing(null);
      sps.reload();
    }
  }

  async function convert() {
    await run(async () => {
      const r = await call<{ serviceProvider: Record<string, unknown>; encryptionCertificates?: string[]; warnings?: string[] }>("/api/demo/from-metadata", { id: newId, xml });
      const config: Record<string, unknown> = { ...r.serviceProvider, attributes: r.serviceProvider.attributes ?? { email: "email", name: "name" } };
      if (tenantOfScope) config.tenant = tenantOfScope;
      if (r.encryptionCertificates?.[0]) config.encryption = { certificate: r.encryptionCertificates[0] };
      setConvertWarnings(r.warnings ?? []);
      open("create", newId, config, true);
    }, "Converted. Review the configuration, then save.");
  }

  // Until the tenants this user can see are known, the scopes (and so the page) aren't either.
  if (t.loading && !t.data) return <p className="muted">Loading…</p>;
  if (!t.loading && scopes.length === 0)
    return (
      <>
        <header className="page-head"><h1>Service providers</h1></header>
        <p className="notice">Service providers are managed by the host's SAML admins, and by the owners and admins of a tenant's organization (delegation). You're neither yet: an organization you administer must first be made a tenant.</p>
      </>
    );

  return (
    <>
      <header className="page-head">
        <h1>Service providers</h1>
        <p className="muted">
          The apps users sign in to. Stored in CharDB through the plugin's registry API; an SP belongs to the root IdP or to one tenant, and signs in only through it.
          {me.samlAdmin ? "" : " As a tenant's administrator you see and change only your tenants' SPs, with user fields limited to email, name and id."}
        </p>
      </header>
      <div className="tabs">
        {scopes.map(([id, label]) => (
          <button type="button" key={id || "root"} className={scope === id ? "tab active" : "tab"} onClick={() => setScope(id)}>{label}</button>
        ))}
      </div>
      <Card title={scopes.find(([id]) => id === scope)?.[1] ?? ""} actions={<button type="button" className="ghost" onClick={() => sps.reload()}>Refresh</button>}>
        {sps.error ? <p className="error">{sps.error}</p> : null}
        {sps.data?.length === 0 ? <Empty>No service providers here yet.</Empty> : null}
        {sps.data?.length ? (
          <table className="table">
            <thead><tr><th>ID</th><th>Entity ID</th>{scope === "*" ? <th>IdP</th> : null}<th>Status</th><th /></tr></thead>
            <tbody>
              {sps.data.map((sp) => (
                <tr key={sp.id}>
                  <td><code>{sp.id}</code>{sp.updatedAt ? <div className="muted small">updated {shortDate(sp.updatedAt)}</div> : null}</td>
                  <td className="break"><code>{sp.entityId}</code></td>
                  {scope === "*" ? <td>{orgName(t.data?.organizations, sp.tenantId)}</td> : null}
                  <td>
                    <Pill tone={!sp.valid ? "bad" : sp.enabled ? "ok" : "neutral"}>{!sp.valid ? "invalid" : sp.enabled ? "active" : "disabled"}</Pill>
                    {[...sp.issues.map((x) => ["bad", x]), ...sp.warnings.map((x) => ["warn", x])].map(([k, x]) => <div key={x} className={`note ${k}`}>{x}</div>)}
                  </td>
                  <td className="right nowrap">
                    {sp.config?.allowIdpInitiated === true && sp.enabled && sp.valid ? <a className="button ghost small" href={`/api/auth/saml2/idp/init?sp=${encodeURIComponent(sp.id)}`}>Sign in</a> : null}
                    {sp.source === "database" ? (
                      <>
                        <button type="button" className="ghost small" onClick={() => open("update", sp.id, sp.config ?? {}, sp.enabled)}>Edit</button>
                        <button type="button" className="ghost small" disabled={busy} onClick={() => void run(() => saml("/service-providers/update", { id: sp.id, enabled: !sp.enabled }), `${sp.enabled ? "Disabled" : "Enabled"} ${sp.id}.`).then(() => sps.reload())}>{sp.enabled ? "Disable" : "Enable"}</button>
                        <button type="button" className="ghost small danger-text" disabled={busy} onClick={() => confirm(`Delete ${sp.id}? Sign-ins to it stop at once.`) && void run(() => saml("/service-providers/delete", { id: sp.id }), `Deleted ${sp.id}.`).then(() => sps.reload())}>Delete</button>
                      </>
                    ) : <span className="muted small">in code</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </Card>

      {editing ? (
        <Card title={editing.mode === "create" ? `New: ${editing.id}` : `Edit ${editing.id}`} subtitle="The same shape as a serviceProviders entry (JSON, no functions).">
          <textarea className="code" spellCheck={false} value={editing.json} onChange={(e) => setEditing({ ...editing, json: e.target.value })} />
          <label className="check"><input type="checkbox" checked={editing.enabled} onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })} /> Enabled</label>
          {convertWarnings.length ? <ul className="warnings">{convertWarnings.map((w) => <li key={w}>{w}</li>)}</ul> : null}
          <div className="row"><button type="button" disabled={busy} onClick={() => void save()}>Save</button><button type="button" className="ghost" onClick={() => setEditing(null)}>Cancel</button></div>
        </Card>
      ) : (
        <Card title="Add a service provider" subtitle={tenantOfScope ? `In ${scopes.find(([id]) => id === scope)?.[1]}.` : scope === "" || scope === "*" ? "At the root IdP (host admins)." : undefined}>
          <Field label="ID" hint="Letters, digits, - and _"><input value={newId} onChange={(e) => setNewId(e.target.value)} placeholder="salesforce" /></Field>
          <Field label="The SP's metadata XML" hint="Most SPs offer a “download metadata” link. It's converted into a configuration you review before saving.">
            <textarea className="code short" spellCheck={false} value={xml} onChange={(e) => setXml(e.target.value)} placeholder="<md:EntityDescriptor …" />
          </Field>
          <div className="row">
            <button type="button" disabled={busy || !/^[A-Za-z0-9_-]{1,64}$/.test(newId) || !xml.trim()} onClick={() => void convert()}>Convert</button>
            <button type="button" className="ghost" disabled={!/^[A-Za-z0-9_-]{1,64}$/.test(newId)} onClick={() => open("create", newId, { id: newId, entityId: "", acsUrls: [""], attributes: { email: "email" }, ...(tenantOfScope ? { tenant: tenantOfScope } : {}) }, true)}>Start from JSON</button>
          </div>
        </Card>
      )}
    </>
  );
}

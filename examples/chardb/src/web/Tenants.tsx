import { type FormEvent, type ReactElement, useState } from "react";
import type { Notify } from "./App.tsx";
import { type Tenant, type TenantKey, useTenants } from "./data.ts";
import { type Me, saml, shortDate, useAction } from "./lib.ts";
import { Card, Copy, Empty, Field, KeyValue, Pill } from "./ui.tsx";

const KEY_TONE: Record<TenantKey["state"], "ok" | "info" | "neutral" | "warn"> = { active: "ok", next: "info", previous: "neutral", retired: "neutral" };

export function Tenants({ me, notify }: { me: Me; notify: Notify }) {
  const t = useTenants(me);
  const { busy, run } = useAction(notify);
  const [orgId, setOrgId] = useState("");
  const [key, setKey] = useState("");
  const tenants = t.data?.tenants ?? [];
  // Organizations with a real owner: an anonymous user's organization (CharDB's generated app allows
  // them) has no one to manage it, and the IdP never signs anonymous users in.
  const unused = (t.data?.organizations ?? []).filter((o) => !tenants.some((x) => x.organizationId === o.id));
  const realOwner = (o: { owners?: string[] }) => (o.owners ?? []).some((e) => e.includes("@"));
  const candidates = unused.filter(realOwner);
  const ownerless = unused.filter((o) => !realOwner(o));

  async function create(e: FormEvent) {
    e.preventDefault();
    if (await run(() => saml("/tenants/create", { organizationId: orgId, tenantKey: key }), `Tenant ${key} created, with its own signing key.`)) {
      setOrgId("");
      setKey("");
      t.reload();
    }
  }

  return (
    <>
      <header className="page-head">
        <h1>Tenants</h1>
        <p className="muted">
          A tenant is an organization with its own IdP identity. Its <b>tenant key</b> is in its entity ID and URLs, which SPs pin, so it never changes.
          Each tenant signs with its own RSA 3072 key, stored in CharDB encrypted with <code>BETTER_AUTH_SECRET</code> and bound to the tenant.
        </p>
      </header>
      {t.error ? <p className="error">{t.error}</p> : null}
      {me.samlAdmin ? (
        <Card title="Make an organization a tenant" subtitle="Host admins only. Generating its key takes about half a second of CPU.">
          <form className="inline" onSubmit={create}>
            <Field label="Organization">
              <select required value={orgId} onChange={(e) => { setOrgId(e.target.value); setKey(t.data?.organizations.find((o) => o.id === e.target.value)?.slug ?? ""); }}>
                <option value="">Choose…</option>
                {candidates.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
            </Field>
            <Field label="Tenant key" hint="Letters, digits, - and _">
              <input required pattern="[A-Za-z0-9_-]{1,64}" value={key} onChange={(e) => setKey(e.target.value)} placeholder="acme" />
            </Field>
            <button type="submit" disabled={busy || !orgId || !key}>{busy ? "Generating a key…" : "Create tenant"}</button>
          </form>
          {candidates.length === 0 && !t.loading ? <p className="muted small">No organization to offer: every one with a real owner is already a tenant. Create one on the Organizations page.</p> : null}
          {ownerless.length ? <p className="muted small">Not offered, as no signed-up user owns them: {ownerless.map((o) => o.name).join(", ")}.</p> : null}
        </Card>
      ) : (
        <p className="notice">Tenants and their keys are managed by the host's admins. As an owner or admin of a tenant's organization you can see it here, and manage its service providers.</p>
      )}
      {tenants.length === 0 && !t.loading ? <Empty>No tenants to show.</Empty> : null}
      {tenants.map((x) => (
        <TenantCard key={x.organizationId} tenant={x} name={t.data?.organizations.find((o) => o.id === x.organizationId)?.name ?? x.tenantKey} me={me} notify={notify} reload={t.reload} />
      ))}
    </>
  );
}

function TenantCard({ tenant: x, name, me, notify, reload }: { tenant: Tenant; name: string; me: Me; notify: Notify; reload: () => void }) {
  const { busy, run } = useAction(notify);
  const act = (path: string, body: object, done: string) => void run(() => saml(path, { organizationId: x.organizationId, ...body }), done).then((ok) => ok && reload());
  const keys = (x.keys ?? []).filter((k) => k.state !== "retired");
  const has = (s: TenantKey["state"]) => keys.some((k) => k.state === s);
  const next = keys.find((k) => k.state === "next");
  const early = next?.activatableAt ? new Date(next.activatableAt) > new Date() : false;
  return (
    <Card
      title={name}
      subtitle={<>tenant key <code>{x.tenantKey}</code> · created {shortDate(x.createdAt)}</>}
      actions={
        <>
          <Pill tone={x.enabled ? "ok" : "neutral"}>{x.enabled ? "enabled" : "disabled"}</Pill>
          {me.samlAdmin ? (
            <>
              <button type="button" className="ghost" disabled={busy} onClick={() => act("/tenants/update", { enabled: !x.enabled }, `${x.enabled ? "Disabled" : "Enabled"} ${x.tenantKey}.`)}>{x.enabled ? "Disable" : "Enable"}</button>
              <button type="button" className="danger" disabled={busy} onClick={() => confirm(`Delete tenant ${x.tenantKey}? Its key is retired for good: no tenant can have its URLs again. Its SPs must be deleted first.`) && act("/tenants/delete", {}, `Deleted ${x.tenantKey}.`)}>Delete</button>
            </>
          ) : null}
        </>
      }
    >
      <KeyValue
        rows={[
          ["Entity ID", <Copy key="e" value={x.entityId} />],
          ["Single sign-on URL", <Copy key="s" value={x.ssoUrl} />],
          ...(x.sloUrl ? [["Single logout URL", <Copy key="l" value={x.sloUrl} />] as [string, ReactElement]] : []),
          ["Metadata", <Copy key="m" value={x.metadataUrl} href />],
        ]}
      />
      <h3>Signing keys <span className="muted small">({x.signing === "own" ? "signs with its own key" : "signs with the shared key"})</span></h3>
      <table className="table">
        <thead><tr><th>State</th><th>Key id</th><th>Created</th><th>Certificate expires</th><th /></tr></thead>
        <tbody>
          {keys.map((k) => (
            <tr key={k.kid}>
              <td><Pill tone={KEY_TONE[k.state]}>{k.state}</Pill></td>
              <td><code>{k.kid}</code></td>
              <td>{shortDate(k.createdAt)}</td>
              <td>{shortDate(k.notAfter)}</td>
              <td className="muted small">
                {k.state === "next" ? `published; activatable ${k.activatableAt ? shortDate(k.activatableAt) : "now"}` : k.state === "active" ? "signs assertions and metadata" : "still published, no longer signs"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {x.warnings?.length ? <ul className="warnings">{x.warnings.map((w) => <li key={w}>{w}</li>)}</ul> : null}
      {me.samlAdmin ? (
        <div className="row top">
          {!has("next") ? <button type="button" disabled={busy} onClick={() => act("/tenants/keys/rotate", {}, "Published a next key. SPs pick it up from the metadata; activate it once they have.")}>{busy ? "Generating…" : "Rotate: publish a next key"}</button> : null}
          {next ? <button type="button" disabled={busy || early} title={early ? "SPs get 24 hours to fetch the new certificate" : undefined} onClick={() => act("/tenants/keys/activate", {}, "The next key signs now.")}>Activate next key</button> : null}
          {next && early ? <button type="button" className="danger" disabled={busy} onClick={() => confirm("Activate before SPs have had 24 hours to fetch the new certificate? SPs that haven't will reject sign-ins until they do. Meant for a leaked key.") && act("/tenants/keys/activate", { force: true }, "The next key signs now (forced).")}>Activate now (forced)</button> : null}
          {has("previous") ? <button type="button" className="ghost" disabled={busy} onClick={() => act("/tenants/keys/retire", {}, "The previous key is no longer published; its private key is erased.")}>Retire previous key</button> : null}
        </div>
      ) : null}
    </Card>
  );
}

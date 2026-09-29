import { useState } from "react";
import type { Notify } from "./App.tsx";
import { orgName, useTenants } from "./data.ts";
import { type Me, saml, useAction, useLoad } from "./lib.ts";
import { Card, Copy, KeyValue, Pill } from "./ui.tsx";

/** The demo SP (src/demo.ts) in one IdP identity: "" is the root, else a tenant key. */
const demoSp = (origin: string, tenantKey: string, organizationId?: string) => ({
  id: `demo-sp-${tenantKey || "root"}`,
  entityId: `${origin}/demo-sp/${tenantKey || "root"}`,
  acsUrls: [`${origin}/demo-sp/acs`],
  allowIdpInitiated: true,
  attributes: { email: "email", name: "name", firstName: { field: "name", part: "first" }, lastName: { field: "name", part: "last" } },
  ...(organizationId ? { tenant: organizationId } : {}),
});

export function TryIt({ me, notify }: { me: Me; notify: Notify }) {
  const t = useTenants(me);
  const origin = new URL(me.idp).origin;
  const identities: { key: string; label: string; organizationId?: string }[] = [
    ...(me.samlAdmin ? [{ key: "", label: "Root IdP" }] : []),
    ...(t.data?.tenants ?? []).filter((x) => x.enabled).map((x) => ({ key: x.tenantKey, label: orgName(t.data?.organizations, x.organizationId), organizationId: x.organizationId })),
  ];
  const [picked, setPicked] = useState<string | null>(null);
  const [manualKey, setManualKey] = useState("");
  const current = identities.find((i) => i.key === (picked ?? identities[0]?.key)) ?? null;
  const sp = current ? demoSp(origin, current.key, current.organizationId) : null;
  const registered = useLoad(async () => {
    if (!sp) return null;
    try {
      return (await saml(`/service-providers/get?id=${encodeURIComponent(sp.id)}`)).serviceProvider as { enabled: boolean };
    } catch {
      return null;
    }
  }, [sp?.id]);
  const { busy, run } = useAction(notify);

  // Until the tenants this user can see are known, the scopes (and so the page) aren't either.
  if (t.loading && !t.data) return <p className="muted">Loading…</p>;
  return (
    <>
      <header className="page-head">
        <h1>Try it</h1>
        <p className="muted">
          A built-in <b>demo SP</b> (served by this Worker at <code>/demo-sp</code>) that you can register in any IdP identity you manage, then sign in to.
          It shows the Response it receives. You need to be signed in here, and for a tenant, a member of its organization.
        </p>
      </header>
      {identities.length ? (
        <div className="tabs">
          {identities.map((i) => <button type="button" key={i.key || "root"} className={current?.key === i.key ? "tab active" : "tab"} onClick={() => setPicked(i.key)}>{i.label}</button>)}
        </div>
      ) : null}
      {current && sp ? (
        <Card
          title={`Demo SP in ${current.label}`}
          actions={registered.data ? <Pill tone={registered.data.enabled ? "ok" : "neutral"}>{registered.data.enabled ? "registered" : "disabled"}</Pill> : <Pill tone="warn">not registered</Pill>}
        >
          <KeyValue
            rows={[
              ["SP entity ID", <Copy key="e" value={sp.entityId} />],
              ["ACS URL", <Copy key="a" value={sp.acsUrls[0] ?? ""} />],
              ["IdP it signs in through", <Copy key="i" value={current.key ? `${me.idp}/metadata/${current.key}` : me.idp} />],
            ]}
          />
          {registered.data ? (
            <div className="try">
              <a className="button" href={`${origin}/demo-sp/login?tenant=${encodeURIComponent(current.key)}`}>Sign in, SP-initiated</a>
              <a className="button ghost" href={`${origin}/api/auth/saml2/idp/init?sp=${encodeURIComponent(sp.id)}`}>Sign in, IdP-initiated</a>
              <p className="muted small">
                SP-initiated: the demo SP sends an AuthnRequest to the {current.key ? "tenant's" : "root"} SSO URL; the IdP checks it, records its ID (single use), and posts a signed Response back.
                IdP-initiated: the IdP starts, for SPs that allow it.
              </p>
            </div>
          ) : (
            <div className="try">
              <button type="button" disabled={busy} onClick={() => void run(() => saml("/service-providers/create", { serviceProvider: sp }), "Registered the demo SP.").then(() => registered.reload())}>Register the demo SP here</button>
              <details><summary className="muted small">Its configuration</summary><pre className="code">{JSON.stringify(sp, null, 2)}</pre></details>
            </div>
          )}
        </Card>
      ) : null}
      <Card title="Through another tenant" subtitle="Tenants you don't administer aren't listed; if you're a member of one whose demo SP is registered, sign in by its key.">
        <div className="inline">
          <input aria-label="Tenant key" placeholder="tenant key, e.g. acme" value={manualKey} onChange={(e) => setManualKey(e.target.value)} />
          <a className={`button ${/^[A-Za-z0-9_-]{1,64}$/.test(manualKey) ? "" : "disabled"}`} href={`${origin}/demo-sp/login?tenant=${encodeURIComponent(manualKey)}`}>Sign in</a>
        </div>
        <p className="muted small">Not a member? The IdP refuses with <code>ACCESS_DENIED</code>: membership of the tenant's organization is what a tenant is.</p>
      </Card>
    </>
  );
}

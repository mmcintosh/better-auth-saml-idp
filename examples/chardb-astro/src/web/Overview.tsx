import type { Notify } from "./Gate.tsx";
import { useTenants } from "./data.ts";
import type { Me } from "./lib.ts";
import { Card, Copy, KeyValue, Pill } from "./ui.tsx";

export function Overview({ me, go }: { me: Me; notify: Notify; go: (p: "organizations" | "tenants" | "sps" | "try") => void }) {
  const t = useTenants(me);
  const tenants = t.data?.tenants ?? [];
  return (
    <>
      <header className="page-head">
        <h1>A SAML identity provider on CharDB</h1>
        <p className="muted">
          Better Auth runs on CharDB (sharded SQLite on Durable Objects), and <code>better-auth-saml-idp</code> makes it an identity provider that
          apps like Okta, AWS or Salesforce sign users in with. Every organization can be its own IdP: a <b>tenant</b>, with its own entity ID,
          metadata and signing key.
        </p>
      </header>

      <Card title="The root IdP" subtitle="What a service provider asks for when you set it up.">
        <KeyValue
          rows={[
            ["Entity ID (Issuer)", <Copy key="e" value={me.idp} />],
            ["Single sign-on URL", <Copy key="s" value={`${me.idp}/sso`} />],
            ["Single logout URL", <Copy key="l" value={`${me.idp}/slo`} />],
            ["Metadata", <Copy key="m" value={`${me.idp}/metadata`} href />],
          ]}
        />
      </Card>

      <Card
        title="Tenants"
        subtitle={me.samlAdmin ? "Every tenant of this IdP." : "Tenants of organizations you administer."}
        actions={<button type="button" className="ghost" onClick={() => go("tenants")}>Manage</button>}
      >
        {t.loading && !t.data ? <p className="muted">Loading…</p> : null}
        {tenants.length === 0 && !t.loading ? (
          <p className="muted">{me.samlAdmin ? "None yet. Create an organization, then make it a tenant." : "None you administer. A host admin makes an organization a tenant."}</p>
        ) : (
          <div className="tiles">
            {tenants.map((x) => (
              <div className="tile" key={x.organizationId}>
                <div className="row between">
                  <strong>{t.data?.organizations.find((o) => o.id === x.organizationId)?.name ?? x.tenantKey}</strong>
                  <Pill tone={x.enabled ? "ok" : "neutral"}>{x.enabled ? "enabled" : "disabled"}</Pill>
                </div>
                <small className="muted">{x.signing === "own" ? "signs with its own key" : "signs with the shared key"}</small>
                <a href={x.metadataUrl} target="_blank" rel="noreferrer"><code>…/metadata/{x.tenantKey}</code></a>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Try the whole flow" subtitle="In this browser, without an outside service provider.">
        <ol className="steps">
          <li><button type="button" className="link" onClick={() => go("organizations")}>Create an organization</button> (you become its owner).</li>
          <li>{me.samlAdmin ? <button type="button" className="link" onClick={() => go("tenants")}>Make it a tenant</button> : "A host admin makes it a tenant"}: it gets its own entity ID and a new signing key.</li>
          <li><button type="button" className="link" onClick={() => go("try")}>Register the demo SP</button> in the tenant, then sign in to it: SP- or IdP-initiated.</li>
          <li>The demo SP shows the Response it received: issuer, NameID, attributes, and which published certificate signed it.</li>
          <li>Invite a colleague as the organization's <i>admin</i>: they manage the tenant's SPs themselves (delegation), and see its activity.</li>
        </ol>
      </Card>
    </>
  );
}

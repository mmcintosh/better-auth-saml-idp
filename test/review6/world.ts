// Review 6 helpers: a host with tenants on (organization plugin, registry, SLO), organizations made
// through the adapter, tenants made through the tenant API by an admin. Both runtimes (on workerd
// the organization and tenant tables come from D1 migration 0007). The findings are fixed in D-053.
import { organization } from "better-auth/plugins";
import { expect } from "vitest";
import type { SamlIdpOptions, ServiceProviderConfig } from "../../src/types";
import { AUTH_BASE, createHost, createHostDatabase, type HostDatabase } from "../support/host";
import { authnRequestXml, Browser, redirectUrl, SSO_URL } from "../support/sp";

export const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
export const issuerOf = (xml: string) => /<saml:Issuer>([^<]+)<\/saml:Issuer>/.exec(xml)?.[1];
export const urls = (key: string) => ({
  sso: `${AUTH_BASE}/saml2/idp/sso/${key}`,
  slo: `${AUTH_BASE}/saml2/idp/slo/${key}`,
  metadata: `${AUTH_BASE}/saml2/idp/metadata/${key}`,
});
export const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";

/** An HTTP-Redirect AuthnRequest to `ssoUrl`. */
export async function authn(ssoUrl: string, spec: Parameters<typeof authnRequestXml>[0] = {}) {
  const url = await redirectUrl(authnRequestXml({ destination: ssoUrl, ...spec }).xml);
  return url.replace(SSO_URL, ssoUrl);
}

let n = 0;

export async function world(
  o: { saml?: Partial<SamlIdpOptions>; auth?: Record<string, unknown>; database?: HostDatabase; orgPlugin?: unknown; sps?: (orgs: { a: string; b: string }) => ServiceProviderConfig[] } = {},
) {
  const t = `${Date.now().toString(36)}${n++}`;
  const database = o.database ?? (await createHostDatabase());
  const plugins = [o.orgPlugin ?? organization()];
  const saml = (sps: ServiceProviderConfig[]): Partial<SamlIdpOptions> => ({
    registry: { enabled: true, canManage, cacheSeconds: 0 },
    tenants: { enabled: true, cacheSeconds: 0 },
    singleLogout: { enabled: true },
    serviceProviders: sps,
    ...o.saml,
  });
  const first = await createHost({ database, plugins, saml: saml([]), auth: o.auth });
  const firstCtx = (await first.auth.$context) as any;
  const org = (name: string) => firstCtx.adapter.create({ model: "organization", data: { name, slug: `${name.toLowerCase()}-${t}`, createdAt: new Date() } });
  const orgA = await org("Acme");
  const orgB = await org("Globex");
  const { auth } = await createHost({ database, plugins, saml: saml(o.sps?.({ a: String(orgA.id), b: String(orgB.id) }) ?? []), auth: o.auth });
  const ctx = (await auth.$context) as any;
  const admin = new Browser(auth);
  const adminUser = await admin.signUp();
  await ctx.adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
  const api = (base: string) => (path: string, body?: unknown, as: Browser = admin) =>
    as.fetch(`${AUTH_BASE}/saml-idp/${base}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const tenants = api("tenants");
  const sps = api("service-providers");
  const browser = new Browser(auth);
  const user = await browser.signUp();
  const join = (orgId: string, userId = user.id, role = "member") =>
    ctx.adapter.create({ model: "member", data: { organizationId: orgId, userId, role, createdAt: new Date() } });
  return { auth, ctx, database, admin, browser, user, orgA, orgB, t, org, tenants, sps, join };
}

export async function ok(res: Response | Promise<Response>) {
  const r = await res;
  expect(r.status, await r.clone().text()).toBe(200);
  return (await r.json()) as any;
}

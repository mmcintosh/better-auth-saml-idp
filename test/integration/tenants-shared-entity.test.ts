// Multi-tenant IdP (D-052): one SP entity ID stored in two tenants (AWS, Google use one for every
// customer). Entity IDs are unique per tenant (`lookupKey`), not globally. A database that kept
// the UNIQUE(entityId) constraint from before tenants refuses the second one (the safe
// direction); the multi-tenant guide's table rebuild drops it, and is applied here to D1.
import { organization } from "better-auth/plugins";
import { beforeAll, describe, expect, it } from "vitest";
import { AUTH_BASE, createHost, createHostDatabase, type HostDatabase, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl, SSO_URL } from "../support/sp";

const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";
const json = async (res: Response) => (await res.json()) as any;
const issuer = (xml: string) => /<saml:Issuer>([^<]+)<\/saml:Issuer>/.exec(xml)?.[1];
let n = 0;

/** The guide's SQL for D1/SQLite: rebuild the table without UNIQUE(entity_id). */
const REBUILD = [
  `CREATE TABLE saml_idp_service_providers_new (
     id TEXT PRIMARY KEY NOT NULL, sp_id TEXT NOT NULL UNIQUE, entity_id TEXT NOT NULL, config TEXT NOT NULL,
     enabled INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT,
     tenant_id TEXT NOT NULL DEFAULT '', lookup_key TEXT NOT NULL UNIQUE)`,
  `INSERT INTO saml_idp_service_providers_new (id, sp_id, entity_id, config, enabled, created_at, updated_at, updated_by, tenant_id, lookup_key)
     SELECT id, sp_id, entity_id, config, enabled, created_at, updated_at, updated_by, tenant_id, lookup_key FROM saml_idp_service_providers`,
  "DROP TABLE saml_idp_service_providers",
  "ALTER TABLE saml_idp_service_providers_new RENAME TO saml_idp_service_providers",
  "CREATE INDEX saml_idp_service_providers_entity_idx ON saml_idp_service_providers (entity_id)",
  "CREATE INDEX saml_idp_service_providers_tenant_idx ON saml_idp_service_providers (tenant_id)",
];

async function tenantsHost(database: HostDatabase) {
  const saml = { registry: { enabled: true, canManage, cacheSeconds: 0 }, tenants: { enabled: true, cacheSeconds: 0 }, serviceProviders: [] };
  const { auth } = await createHost({ database, plugins: [organization()], saml });
  const ctx = (await auth.$context) as any;
  const t = `${Date.now().toString(36)}${n++}`;
  const admin = new Browser(auth);
  const adminUser = await admin.signUp();
  await ctx.adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
  const call = (path: string, body: unknown) =>
    admin.fetch(`${AUTH_BASE}/saml-idp${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const orgs = await Promise.all(["a", "b"].map((x) => ctx.adapter.create({ model: "organization", data: { name: x, slug: `${x}-${t}`, createdAt: new Date() } })));
  for (const org of orgs) expect((await call("/tenants/create", { organizationId: org.id })).status).toBe(200);
  const user = new Browser(auth);
  const u = await user.signUp();
  for (const org of orgs) await ctx.adapter.create({ model: "member", data: { organizationId: org.id, userId: u.id, role: "member", createdAt: new Date() } });
  // An entity ID and ACS shared by every customer, unique to this test (one D1 database per file).
  const shared = { entityId: `urn:shared:${t}`, acsUrls: [`https://shared${t}.test/acs`] };
  const sso = (orgId: string) => `${AUTH_BASE}/saml2/idp/sso/${orgId}`;
  const signIn = async (orgId: string) =>
    user.fetch((await redirectUrl(authnRequestXml({ issuer: shared.entityId, acsUrl: shared.acsUrls[0], destination: sso(orgId) }).xml)).replace(SSO_URL, sso(orgId)));
  return { auth, call, orgA: orgs[0].id as string, orgB: orgs[1].id as string, t, shared, signIn };
}

describe("one entity ID in two tenants, stored (D-052)", () => {
  it("a database that kept UNIQUE(entityId) from before tenants refuses the second one: 409, not a silent overwrite", async () => {
    const database = await createHostDatabase();
    if (!isWorkerd) {
      // Upgrade path on SQLite: the table made with tenants off, then the guide's steps (lookupKey
      // by hand, the rest by Better Auth's migrator, which leaves UNIQUE(entityId) in place).
      await createHost({ database, plugins: [organization()], saml: { registry: { enabled: true, canManage }, serviceProviders: [] } });
      (database.db as { exec(sql: string): void }).exec("ALTER TABLE samlIdpServiceProvider ADD COLUMN lookupKey TEXT");
      const { getMigrations } = await import("better-auth/db/migration");
      const { hostOptions } = await import("../support/host");
      const opts = hostOptions(database, { plugins: [organization()], saml: { registry: { enabled: true, canManage }, tenants: { enabled: true }, serviceProviders: [] } });
      await (await getMigrations(opts as any)).runMigrations();
    }
    // On D1, migration 0007 kept the constraint (this runs before the rebuild below).
    const h = await tenantsHost(database);
    expect((await h.call("/service-providers/create", { serviceProvider: { id: `a-${h.t}`, ...h.shared, tenant: h.orgA } })).status).toBe(200);
    const second = await h.call("/service-providers/create", { serviceProvider: { id: `b-${h.t}`, ...h.shared, tenant: h.orgB } });
    expect(second.status).toBe(409);
    expect((await json(second)).code).toBe("SERVICE_PROVIDER_EXISTS");
  });

  describe("without the old constraint", () => {
    beforeAll(async () => {
      if (!isWorkerd) return; // Better Auth's migrator makes the tenants schema without it
      const { env } = await import("cloudflare:test");
      const db = env.DB;
      await db.batch(REBUILD.map((sql) => db.prepare(sql)));
    });

    it("both tenants have it; each tenant's URL signs in with its own Issuer; the administrator is warned", async () => {
      const h = await tenantsHost(await createHostDatabase());
      const a = await json(await h.call("/service-providers/create", { serviceProvider: { id: `a-${h.t}`, ...h.shared, tenant: h.orgA } }));
      const b = await json(await h.call("/service-providers/create", { serviceProvider: { id: `b-${h.t}`, ...h.shared, tenant: h.orgB } }));
      expect(a.serviceProvider).toMatchObject({ tenantId: h.orgA, valid: true });
      expect(b.serviceProvider).toMatchObject({ tenantId: h.orgB, valid: true });
      expect(b.serviceProvider.warnings.join()).toMatch(new RegExp(`same entity ID and an ACS URL as SP a-${h.t} in tenant ${h.orgA}`));
      expect(issuer((await readAutoPost(await h.signIn(h.orgA))).xml)).toBe(`${AUTH_BASE}/saml2/idp/metadata/${h.orgA}`);
      expect(issuer((await readAutoPost(await h.signIn(h.orgB))).xml)).toBe(`${AUTH_BASE}/saml2/idp/metadata/${h.orgB}`);
      // Removing one leaves the other.
      expect((await h.call("/service-providers/delete", { id: `a-${h.t}` })).status).toBe(200);
      expect(/<code>([A-Z_]+)<\/code>/.exec(await (await h.signIn(h.orgA)).text())?.[1]).toBe("UNKNOWN_SERVICE_PROVIDER");
      expect((await h.signIn(h.orgB)).status).toBe(200);
    });

    it("twice in one tenant is still refused, by the lookup key", async () => {
      const h = await tenantsHost(await createHostDatabase());
      expect((await h.call("/service-providers/create", { serviceProvider: { id: `a-${h.t}`, ...h.shared, tenant: h.orgA } })).status).toBe(200);
      const again = await h.call("/service-providers/create", { serviceProvider: { id: `a2-${h.t}`, ...h.shared, tenant: h.orgA } });
      expect(again.status).toBe(409);
      expect((await json(again)).code).toBe("SERVICE_PROVIDER_EXISTS");
      // And at the root: a root SP with the same entity ID is a third, separate SP.
      expect((await h.call("/service-providers/create", { serviceProvider: { id: `r-${h.t}`, ...h.shared } })).status).toBe(200);
    });
  });
});

// Multi-tenant IdP, phase 3 (D-059): an organization's own administrators manage their tenant's
// SPs. Written adversarially: every route is tried across tenants (IDOR), for the root IdP, with
// fields a tenant's administrator may not set, and after a demotion. Both runtimes.
import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import type { TestSamlOptions } from "../support/config";
import { AUTH_BASE, createHost, createHostDatabase, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl, SSO_URL } from "../support/sp";

const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";
let n = 0;

/**
 * Tenants A and B (made by the host's admin), an SP stored in each and one at the root, and:
 * `ownerA` (owner of A), `adminB` (admin of B), `both` (admin of A and B), `memberA` (member of A).
 */
async function world(saml: TestSamlOptions = {}) {
  const t = `${Date.now().toString(36)}${n++}`;
  const database = await createHostDatabase();
  const events: any[] = [];
  const options: TestSamlOptions = {
    registry: { enabled: true, canManage, cacheSeconds: 0 },
    tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, minPublishedSeconds: 0, delegation: {} },
    auditLog: { enabled: true },
    events: { onServiceProviderChanged: (e) => void events.push(e), onTenantChanged: (e) => void events.push(e) },
    serviceProviders: [],
    ...saml,
  };
  const { auth } = await createHost({ database, plugins: [organization()], saml: options });
  const ctx = (await auth.$context) as any;
  const org = (name: string) => ctx.adapter.create({ model: "organization", data: { name, slug: `${name.toLowerCase()}-${t}`, createdAt: new Date() } });
  const [A, B] = [String((await org("Acme")).id), String((await org("Globex")).id)];
  const person = async (roles: [string, string][] = []) => {
    const b = new Browser(auth);
    const u = await b.signUp();
    for (const [orgId, role] of roles) await ctx.adapter.create({ model: "member", data: { organizationId: orgId, userId: u.id, role, createdAt: new Date() } });
    return { b, u };
  };
  const host = await person();
  await ctx.adapter.update({ model: "user", where: [{ field: "id", value: host.u.id }], update: { role: "admin" } });
  const ownerA = await person([[A, "owner"]]);
  const adminB = await person([[B, "admin"]]);
  const both = await person([
    [A, "admin"],
    [B, "member,admin"],
  ]);
  const memberA = await person([[A, "member"]]);
  const call = (b: Browser) => (path: string, body?: unknown) =>
    b.fetch(`${AUTH_BASE}/saml-idp${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  const asHost = call(host.b);
  for (const organizationId of [A, B]) expect((await asHost("/tenants/create", { organizationId })).status).toBe(200);
  const sp = (id: string, tenant?: string, extra: Record<string, unknown> = {}) => ({
    serviceProvider: { id: `${id}-${t}`, entityId: `https://${id}-${t}.test/sp`, acsUrls: [`https://${id}-${t}.test/acs`], ...(tenant ? { tenant } : {}), ...extra },
  });
  for (const [id, tenant] of [["sp-a", A], ["sp-b", B], ["sp-root", undefined]] as const) expect((await asHost("/service-providers/create", sp(id, tenant))).status).toBe(200);
  const ids = { a: `sp-a-${t}`, b: `sp-b-${t}`, root: `sp-root-${t}` };
  return { auth, ctx, t, A, B, ids, sp, events, asHost, ownerA: call(ownerA.b), adminB: call(adminB.b), both: call(both.b), memberA: call(memberA.b), people: { ownerA, adminB, both, memberA, host } };
}

const body = async (res: Response) => (await res.json()) as any;

describe("delegation: a tenant's administrator sees and changes its own tenant's SPs only (D-059)", () => {
  it("list: filtered to its tenant in the query; another tenant's list is refused; several tenants need a tenantId", async () => {
    const w = await world();
    const listed = await body(await w.ownerA("/service-providers"));
    expect(listed.serviceProviders.map((s: any) => s.id)).toEqual([w.ids.a]);
    expect((await w.ownerA(`/service-providers?tenantId=${w.B}`)).status).toBe(403);
    expect((await w.ownerA("/service-providers?tenantId=")).status).toBe(403); // the root IdP's
    expect((await w.both("/service-providers")).status).toBe(400);
    expect((await body(await w.both(`/service-providers?tenantId=${w.B}`))).serviceProviders.map((s: any) => s.id)).toEqual([w.ids.b]);
  });

  it("get, update, delete of another tenant's SP, or the root's, answer 404 and change nothing (no IDOR: spId is global)", async () => {
    const w = await world();
    for (const id of [w.ids.b, w.ids.root]) {
      expect((await w.ownerA(`/service-providers/get?id=${id}`)).status).toBe(404);
      expect((await w.ownerA("/service-providers/update", { id, enabled: false })).status).toBe(404);
      expect((await w.ownerA("/service-providers/update", { id, serviceProvider: { id, entityId: "https://x.test", acsUrls: ["https://x.test/acs"], tenant: w.A } })).status).toBe(404);
      expect((await w.ownerA("/service-providers/delete", { id })).status).toBe(404);
    }
    // This world's SPs (on workerd the D1 database is shared by the file's tests).
    const all = await body(await w.asHost("/service-providers"));
    expect(all.serviceProviders.filter((s: any) => Object.values(w.ids).includes(s.id)).map((s: any) => [s.id, s.enabled]).sort()).toEqual(
      [
        [w.ids.a, true],
        [w.ids.b, true],
        [w.ids.root, true],
      ].sort(),
    );
    // Its own: fine.
    expect((await w.ownerA(`/service-providers/get?id=${w.ids.a}`)).status).toBe(200);
    expect((await w.ownerA("/service-providers/update", { id: w.ids.a, enabled: false })).status).toBe(200);
  });

  it("create: only in its tenant; not at the root, not in another tenant; its tenant can't be changed afterwards", async () => {
    const w = await world();
    expect((await w.ownerA("/service-providers/create", w.sp("new-root"))).status).toBe(403);
    expect((await w.ownerA("/service-providers/create", w.sp("new-b", w.B))).status).toBe(403);
    const made = await w.ownerA("/service-providers/create", w.sp("new-a", w.A));
    expect(made.status).toBe(200);
    expect((await body(made)).serviceProvider.tenantId).toBe(w.A);
    const id = `new-a-${w.t}`;
    const moved = await w.both("/service-providers/update", { id, serviceProvider: { id, entityId: `https://new-a-${w.t}.test/sp`, acsUrls: [`https://new-a-${w.t}.test/acs`], tenant: w.B } });
    expect(moved.status).toBe(400); // an administrator of both still can't move it
    expect(w.events.filter((e) => e.type === "service-provider.changed" && e.delegated).map((e) => [e.action, e.spId, e.tenantId])).toEqual([["created", id, w.A]]);
  });

  it("user fields outside tenants.delegation.userFields are refused, as attributes or NameID; allowed fields and constants pass", async () => {
    const w = await world();
    const tryAttrs = (extra: Record<string, unknown>) => w.ownerA("/service-providers/create", w.sp(`f${Math.random().toString(36).slice(2, 8)}`, w.A, extra));
    for (const bad of [{ attributes: { role: "role" } }, { attributes: { r: { field: "banReason" } } }, { attributes: { groups: { field: "role", split: "," } } }, { nameId: { field: "role" } }]) {
      const res = await tryAttrs(bad);
      expect(res.status, JSON.stringify(bad)).toBe(400);
      expect((await body(res)).issues.join()).toMatch(/isn't one a tenant's administrator may send/);
    }
    expect((await tryAttrs({ attributes: { email: "email", displayName: "name", uid: { field: "id" }, dept: { value: "Sales" } }, nameId: { field: "email" } })).status).toBe(200);
    // The host's own administrators aren't limited.
    expect((await w.asHost("/service-providers/create", w.sp("host-role", w.A, { attributes: { role: "role" } }))).status).toBe(200);
  });

  it("the host can widen userFields; metadata.url is refused unless allowMetadataUrl", async () => {
    const w = await world();
    const withUrl = w.sp("md", w.A, { metadata: { url: "https://md.test/metadata.xml" } });
    const refused = await w.ownerA("/service-providers/create", withUrl);
    expect(refused.status).toBe(400);
    expect((await body(refused)).issues.join()).toMatch(/metadata URL/);
    const open = await world({ tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, minPublishedSeconds: 0, delegation: { allowMetadataUrl: true, userFields: ["email", "role"] } } });
    expect((await open.ownerA("/service-providers/create", open.sp("md", open.A, { metadata: { url: "https://md.test/metadata.xml" }, attributes: { role: "role" } }))).status).toBe(200);
  });

  // Node only: the D1 test schema keeps UNIQUE(entityId), so B's entity ID can't be stored in A there
  // (tenants-shared-entity.test.ts rebuilds that table to cover it).
  it.skipIf(isWorkerd)("records shown to a tenant's administrator carry no warning about another tenant's SP", async () => {
    const w = await world();
    // Same entity ID and ACS URL as B's SP: the host is warned; A's administrator isn't told about B.
    const clone = { serviceProvider: { id: `clone-${w.t}`, entityId: `https://sp-b-${w.t}.test/sp`, acsUrls: [`https://sp-b-${w.t}.test/acs`], tenant: w.A } };
    const made = await body(await w.ownerA("/service-providers/create", clone));
    expect(JSON.stringify(made.serviceProvider.warnings)).not.toContain(w.ids.b);
    expect(made.serviceProvider.warnings).toEqual([]);
    const asSeenByHost = await body(await w.asHost(`/service-providers/get?id=clone-${w.t}`));
    expect(asSeenByHost.serviceProvider.warnings.join()).toMatch(/same entity ID and an ACS URL/);
  });
});

describe("delegation: who counts, decided on every request (D-059)", () => {
  it("a member without an administrator role, and a user outside the organization, get nothing", async () => {
    const w = await world();
    expect((await w.memberA("/service-providers")).status).toBe(403);
    expect((await w.memberA("/service-providers/create", w.sp("m", w.A))).status).toBe(403);
    expect((await w.adminB(`/service-providers/get?id=${w.ids.a}`)).status).toBe(404);
  });

  it("a demoted administrator loses access at once (memberships are read from the database, not the session)", async () => {
    const w = await world();
    expect((await w.ownerA("/service-providers")).status).toBe(200);
    await w.ctx.adapter.update({ model: "member", where: [{ field: "userId", value: w.people.ownerA.u.id }], update: { role: "member" } });
    expect((await w.ownerA("/service-providers")).status).toBe(403);
    expect((await w.ownerA("/service-providers/update", { id: w.ids.a, enabled: false })).status).toBe(403);
  });

  it("a disabled tenant gives its administrators nothing; enabled again, it does", async () => {
    const w = await world();
    expect((await w.asHost("/tenants/update", { organizationId: w.A, enabled: false })).status).toBe(200);
    expect((await w.ownerA("/service-providers")).status).toBe(403);
    expect((await w.asHost("/tenants/update", { organizationId: w.A, enabled: true })).status).toBe(200);
    expect((await w.ownerA("/service-providers")).status).toBe(200);
  });

  it("a session impersonating the administrator is refused", async () => {
    const w = await world();
    await w.ctx.adapter.update({ model: "session", where: [{ field: "userId", value: w.people.ownerA.u.id }], update: { impersonatedBy: w.people.host.u.id } });
    expect((await w.ownerA("/service-providers")).status).toBe(403);
  });

  it("custom roles: only the configured ones delegate", async () => {
    const w = await world({ tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, minPublishedSeconds: 0, delegation: { roles: ["sso-admin"] } } });
    expect((await w.ownerA("/service-providers")).status).toBe(403);
    await w.ctx.adapter.update({ model: "member", where: [{ field: "userId", value: w.people.memberA.u.id }], update: { role: "member,sso-admin" } });
    expect((await body(await w.memberA("/service-providers"))).serviceProviders.map((s: any) => s.id)).toEqual([w.ids.a]);
  });
});

describe("delegation: what stays with the host (D-059)", () => {
  it("tenants and their keys: a tenant's administrator may read its own tenant and certificates, and change nothing", async () => {
    const w = await world();
    const own = await body(await w.ownerA(`/tenants/get?organizationId=${w.A}`));
    expect(own.tenant.organizationId).toBe(w.A);
    expect(JSON.stringify(own)).not.toMatch(/PRIVATE KEY|encryptedPrivateKey/);
    expect((await w.ownerA(`/tenants/keys?organizationId=${w.A}`)).status).toBe(200);
    expect((await w.ownerA(`/tenants/get?organizationId=${w.B}`)).status).toBe(404);
    expect((await w.ownerA(`/tenants/keys?organizationId=${w.B}`)).status).toBe(404);
    expect((await w.ownerA("/tenants")).status).toBe(403);
    for (const [path, b] of [
      ["/tenants/create", { organizationId: w.A }],
      ["/tenants/update", { organizationId: w.A, enabled: false }],
      ["/tenants/delete", { organizationId: w.A }],
      ["/tenants/keys/rotate", { organizationId: w.A }],
      ["/tenants/keys/activate", { organizationId: w.A }],
      ["/tenants/keys/retire", { organizationId: w.A }],
    ] as const)
      expect((await w.ownerA(path, b)).status, path).toBe(403);
  });

  it("delegation needs per-tenant keys: with a shared key it's a startup error", async () => {
    await expect(
      createHost({
        database: await createHostDatabase(),
        plugins: [organization()],
        saml: { registry: { enabled: true, canManage }, tenants: { enabled: true, delegation: {} } },
      }),
    ).rejects.toThrow(/tenants.delegation: requires tenants.keys: "per-tenant"/);
  });

  it("with delegation only (no canManage, no permissions) the registry exists for tenants' administrators, and nobody else manages", async () => {
    const database = await createHostDatabase();
    const { auth } = await createHost({
      database,
      plugins: [organization()],
      saml: { registry: { enabled: true, cacheSeconds: 0 }, tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, delegation: {} } },
    });
    const b = new Browser(auth);
    await b.signUp();
    const res = await b.fetch(`${AUTH_BASE}/saml-idp/service-providers`);
    expect(res.status).toBe(403); // mounted, and refused: not an administrator of any tenant
  });
});

describe("delegation: the audit view (D-059)", () => {
  it("a tenant's administrator reads its tenant's events only, filtered in the query; the host reads any", async () => {
    const w = await world();
    await w.ownerA("/service-providers/update", { id: w.ids.a, enabled: false });
    await w.adminB("/service-providers/update", { id: w.ids.b, enabled: false });
    await new Promise((r) => setTimeout(r, 50)); // audit rows are written in the background
    const mine = await body(await w.ownerA("/audit"));
    expect(mine.events.length).toBeGreaterThan(0);
    expect(new Set(mine.events.map((e: any) => e.tenantId))).toEqual(new Set([w.A]));
    expect(mine.events.find((e: any) => e.type === "service-provider.changed")?.details).toMatchObject({ action: "disabled", spId: w.ids.a, delegated: true });
    expect((await w.ownerA(`/audit?tenantId=${w.B}`)).status).toBe(403);
    expect((await w.ownerA("/audit?tenantId=")).status).toBe(403);
    expect((await w.memberA("/audit")).status).toBe(403);
    const hostView = await body(await w.asHost(`/audit?tenantId=${w.B}`));
    expect(new Set(hostView.events.map((e: any) => e.tenantId))).toEqual(new Set([w.B]));
    const root = await body(await w.asHost("/audit?tenantId="));
    expect(root.events.every((e: any) => e.tenantId === null)).toBe(true);
  });

  it("a delegated SP signs in its members under its tenant's own key", async () => {
    const w = await world();
    const id = `deleg-sp-${w.t}`;
    const sp = { id, entityId: `https://${id}.test/sp`, acsUrls: [`https://${id}.test/acs`], tenant: w.A };
    expect((await w.ownerA("/service-providers/create", { serviceProvider: sp })).status).toBe(200);
    const sso = `${AUTH_BASE}/saml2/idp/sso/${w.A}`;
    const url = (await redirectUrl(authnRequestXml({ destination: sso, issuer: sp.entityId, acsUrl: sp.acsUrls[0] }).xml)).replace(SSO_URL, sso);
    const { xml } = await readAutoPost(await w.people.memberA.b.fetch(url));
    expect(/<saml:Issuer>([^<]+)</.exec(xml)?.[1]).toBe(`${AUTH_BASE}/saml2/idp/metadata/${w.A}`);
    const cert = (await body(await w.asHost(`/tenants/get?organizationId=${w.A}`))).tenant.keys[0].certificate as string;
    expect(xml).toContain(cert.replace(/-----[^-]+-----|\s+/g, "").slice(0, 60));
  });
});

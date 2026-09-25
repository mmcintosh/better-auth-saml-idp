// Registry API with Better Auth admin-plugin access control (D-031).
import { createAccessControl } from "better-auth/plugins/access";
import { adminAc, defaultStatements, userAc } from "better-auth/plugins/admin/access";
import { beforeEach, describe, expect, it } from "vitest";
import { samlIdpStatements } from "../../src/access";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { Browser } from "../support/sp";

const ac = createAccessControl({ ...defaultStatements, ...samlIdpStatements });
const roles = {
  admin: ac.newRole({ ...adminAc.statements, samlServiceProvider: ["list", "read", "create", "update", "delete"] }),
  user: ac.newRole({ ...userAc.statements }),
  auditor: ac.newRole({ samlServiceProvider: ["list", "read"] }),
};

let n = 0;
let tag = "";
beforeEach(() => {
  tag = `${Date.now().toString(36)}${n++}`;
});
const stored = () => ({ id: `p-${tag}`, entityId: `https://p${tag}.test/sp`, acsUrls: [`https://p${tag}.test/acs`] });

async function host(o: { adminOptions?: Record<string, unknown>; registry?: Record<string, unknown> } = {}) {
  const { auth } = await createHost({
    adminOptions: o.adminOptions ?? { ac, roles },
    saml: { serviceProviders: [{ id: "code-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }], registry: { enabled: true, permissions: true, ...o.registry } as any },
  });
  const as = async (role: string, extra: Record<string, unknown> = {}) => {
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const ctx = (await auth.$context) as any;
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role, ...extra } });
    return { browser, user };
  };
  return { auth, as };
}
const call = (b: Browser, path: string, body?: unknown) =>
  b.fetch(`${AUTH_BASE}/saml2/idp/service-providers${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

describe("registry: admin-plugin permissions", () => {
  it("each action needs its own grant: admin can do everything, an auditor can only list and read", async () => {
    const { as } = await host();
    const { browser: admin } = await as("admin");
    expect((await call(admin, "/create", { serviceProvider: stored() })).status).toBe(200);
    const { browser: auditor } = await as("auditor");
    expect((await call(auditor, "")).status).toBe(200);
    expect((await call(auditor, `/get?id=p-${tag}`)).status).toBe(200);
    expect((await call(auditor, "/create", { serviceProvider: { ...stored(), id: `q-${tag}`, entityId: `https://q${tag}.test/sp` } })).status).toBe(403);
    expect((await call(auditor, "/delete", { id: `p-${tag}` })).status).toBe(403);
    const { browser: user } = await as("user");
    expect((await call(user, "")).status).toBe(403);
  });

  it("multi-role users: any role granting the action is enough", async () => {
    const { as } = await host();
    const { browser } = await as("user,auditor");
    expect((await call(browser, "")).status).toBe(200);
  });

  it("the admin plugin's default roles grant nothing on this resource; adminUserIds does", async () => {
    const { as } = await host({ adminOptions: {} });
    const { browser } = await as("admin");
    expect((await call(browser, "")).status).toBe(403);
    const withIds = await createHost({ saml: { serviceProviders: [], registry: { enabled: true, permissions: true } as any }, adminOptions: {} });
    const b = new Browser(withIds.auth);
    const u = await b.signUp();
    const ctx = (await withIds.auth.$context) as any;
    const plugin = ctx.options.plugins.find((p: any) => p.id === "admin");
    plugin.options.adminUserIds = [u.id];
    expect((await call(b, "")).status).toBe(200);
  });

  it("with canManage too, both must allow", async () => {
    const { as } = await host({ registry: { canManage: () => false } });
    const { browser } = await as("admin");
    expect((await call(browser, "")).status).toBe(403);
  });
});

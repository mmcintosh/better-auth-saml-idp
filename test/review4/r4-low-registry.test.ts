// Review 4, Low items on the registry API.
//   L3: manager() trusted the session's copy of the user: a user banned by a database edit, or an
//       admin demoted while sessions live in secondary storage, kept managing SPs.
//   L8: view() reported valid:true for rows the directory ignores (columns edited by hand).
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, BASE_URL, createHost } from "../support/host";
import { Browser } from "../support/sp";

const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";
const CODE_SP = { id: "code-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] as [string] };
let n = 0;
const tag = () => `${Date.now().toString(36)}${n++}`;
const api = (browser: Browser, path: string, body?: unknown) =>
  browser.fetch(`${AUTH_BASE}/saml2/idp/service-providers${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", origin: BASE_URL },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

function memoryStorage() {
  const m = new Map<string, string>();
  return {
    get: async (k: string) => m.get(k) ?? null,
    set: async (k: string, v: string) => void m.set(k, v),
    delete: async (k: string) => void m.delete(k),
  };
}

describe("R4-L3: registry decisions use the user as the database has it now", () => {
  it("a user banned by a database edit loses registry access at once", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [CODE_SP], registry: { enabled: true, canManage } } });
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const ctx = await auth.$context;
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin" } });
    expect((await api(browser, "")).status).toBe(200);
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { banned: true } });
    expect((await api(browser, "")).status).toBe(403);
  });

  it("an admin demoted in the database loses access, even while secondary storage still says admin", async () => {
    const { auth } = await createHost({
      cloudflare: { geolocationTracking: false },
      auth: { secondaryStorage: memoryStorage() },
      saml: { serviceProviders: [CODE_SP], registry: { enabled: true, canManage } },
    });
    const ctx = await auth.$context;
    const browser = new Browser(auth);
    const user = await browser.signUp();
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin" } });
    // Sign in again so the stored session snapshot carries role=admin.
    const signIn = await browser.fetch(`${AUTH_BASE}/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: user.email, password: "correct-horse-battery" }),
    });
    expect(signIn.status).toBe(200);
    expect((await api(browser, "")).status).toBe(200);
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "user" } });
    const res = await api(browser, "/create", { serviceProvider: { id: `p${tag()}`, entityId: `https://p${tag()}.test/sp`, acsUrls: ["https://p.test/acs"] } });
    expect(res.status).toBe(403);
  });
});

describe("R4-L8: the API reports a row valid only if sign-in would use it", () => {
  it("a row whose entityId column no longer matches its config is reported invalid, with the reason", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [CODE_SP], registry: { enabled: true, canManage, cacheSeconds: 0 } } });
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const ctx = await auth.$context;
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin" } });
    const id = `p${tag()}`;
    expect((await api(browser, "/create", { serviceProvider: { id, entityId: `https://${id}.test/sp`, acsUrls: [`https://${id}.test/acs`] } })).status).toBe(200);
    await ctx.adapter.update({ model: "samlIdpServiceProvider", where: [{ field: "spId", value: id }], update: { entityId: "https://other.test/sp" } });
    const v = (await (await api(browser, `/get?id=${id}`)).json()) as { serviceProvider: { valid: boolean; issues: string[] } };
    expect(v.serviceProvider.valid).toBe(false);
    expect(v.serviceProvider.issues.join(" ")).toMatch(/don't match the config/);
  });
});

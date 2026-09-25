// Database-backed SP registry (D-027): lifecycle through the API, the security boundaries,
// and isolates sharing one database.
import { beforeEach, describe, expect, inject, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, BASE_URL, createHost, createHostDatabase, type HostDatabase } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const keys = inject("keys");
// Unique names per test: on workerd one D1 database is shared by the whole file.
let n = 0;
let NEW_SP = "";
let NEW_ACS = "";
let SP_ID = "";
beforeEach(() => {
  n++;
  const tag = `${Date.now().toString(36)}${n}`;
  SP_ID = `stored-${tag}`;
  NEW_SP = `https://stored${tag}.test/sp`;
  NEW_ACS = `https://stored${tag}.test/acs`;
});
const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";

async function host(o: { registry?: Record<string, unknown> | false; database?: HostDatabase; logs?: string[]; auth?: Record<string, unknown> } = {}) {
  const { auth, database } = await createHost({
    database: o.database,
    saml: {
      serviceProviders: [{ id: "code-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }],
      ...(o.registry === false ? {} : { registry: { enabled: true, canManage, ...o.registry } as any }),
    },
    auth: { logger: { level: "info", log: (_l: string, m: string) => o.logs?.push(m) }, ...o.auth },
  });
  return { auth, database };
}

async function admin(auth: any, role = "admin") {
  const browser = new Browser(auth);
  const user = await browser.signUp();
  const ctx = await auth.$context;
  await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role } });
  return { browser, user };
}

const api = (browser: Browser, path: string, body?: unknown, origin = BASE_URL) =>
  browser.fetch(`${AUTH_BASE}/saml2/idp/service-providers${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", ...(origin ? { origin } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
const json = async (res: Response) => (await res.json()) as any;
const stored = (over: Record<string, unknown> = {}) => ({ id: SP_ID, entityId: NEW_SP, acsUrls: [NEW_ACS], ...over });

/** Sign in to the stored SP; returns the IdP's answer (auto-POST page or error page). */
async function ssoTo(browser: Browser, issuer = NEW_SP, acsUrl = NEW_ACS) {
  return browser.fetch(await redirectUrl(authnRequestXml({ issuer, acsUrl }).xml));
}
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe("SP registry: lifecycle", () => {
  it("an admin creates an SP and users can sign in to it at once; attributes come from a stored map", async () => {
    const { auth } = await host();
    const { browser } = await admin(auth);
    expect(await code(await ssoTo(browser))).toBe("UNKNOWN_SERVICE_PROVIDER");
    const res = await api(browser, "/create", { serviceProvider: stored({ attributes: { mail: "email", org: { value: "Acme" } } }) });
    expect(res.status).toBe(200);
    expect((await json(res)).serviceProvider).toMatchObject({ id: SP_ID, entityId: NEW_SP, source: "database", enabled: true, valid: true });
    const form = await readAutoPost(await ssoTo(browser));
    expect(form.action).toBe(NEW_ACS);
    expect(form.xml).toContain('Name="org"');
    expect(form.xml).toContain(`<saml:Audience>${NEW_SP}</saml:Audience>`);
  });

  it("lists code and stored SPs; gets one", async () => {
    const { auth } = await host();
    const { browser } = await admin(auth);
    await api(browser, "/create", { serviceProvider: stored() });
    const list = (await json(await api(browser, ""))).serviceProviders;
    expect(list[0]).toMatchObject({ id: "code-sp", source: "code" });
    expect(list.some((s: any) => s.id === SP_ID && s.source === "database")).toBe(true);
    expect((await json(await api(browser, `/get?id=${SP_ID}`))).serviceProvider.config).toMatchObject(stored());
    expect((await api(browser, "/get?id=nope")).status).toBe(404);
  });

  it("update replaces the config (the old ACS URL stops working); the id can't change", async () => {
    const { auth } = await host({ registry: { cacheSeconds: 0 } });
    const { browser } = await admin(auth);
    await api(browser, "/create", { serviceProvider: stored() });
    const upd = await api(browser, "/update", { id: SP_ID, serviceProvider: stored({ acsUrls: ["https://stored.test/acs2"] }) });
    expect(upd.status).toBe(200);
    expect(await code(await ssoTo(browser))).toBe("ACS_URL_NOT_ALLOWED");
    expect((await readAutoPost(await ssoTo(browser, NEW_SP, "https://stored.test/acs2"))).action).toBe("https://stored.test/acs2");
    const renamed = await api(browser, "/update", { id: SP_ID, serviceProvider: stored({ id: `${SP_ID}-o` }) });
    expect(renamed.status).toBe(400);
  });

  it("disable and delete take effect", async () => {
    const { auth } = await host();
    const { browser } = await admin(auth);
    await api(browser, "/create", { serviceProvider: stored() });
    await api(browser, "/update", { id: SP_ID, serviceProvider: stored(), enabled: false });
    expect(await code(await ssoTo(browser))).toBe("UNKNOWN_SERVICE_PROVIDER");
    await api(browser, "/update", { id: SP_ID, serviceProvider: stored(), enabled: true });
    expect((await ssoTo(browser)).status).toBe(200);
    expect((await api(browser, "/delete", { id: SP_ID })).status).toBe(200);
    expect(await code(await ssoTo(browser))).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect((await api(browser, "/delete", { id: SP_ID })).status).toBe(404);
  });

  it("a strict SP accepts a Response for a stored SP with required signed requests", async () => {
    const { auth } = await host();
    const { browser } = await admin(auth);
    const sp = stored({ requireSignedAuthnRequests: true, spCertificate: keys.sp.certificate });
    expect((await api(browser, "/create", { serviceProvider: sp })).status).toBe(200);
    const unsigned = await browser.fetch(await redirectUrl(authnRequestXml({ issuer: NEW_SP, acsUrl: NEW_ACS }).xml));
    expect(await code(unsigned)).toBe("UNSIGNED_SAML_REQUEST");
    const signed = await browser.fetch(await redirectUrl(authnRequestXml({ issuer: NEW_SP, acsUrl: NEW_ACS }).xml, { sign: true }));
    expect(signed.status).toBe(200);
  });
});

describe("SP registry: validation", () => {
  it.each([
    ["http ACS URL", () => stored({ acsUrls: ["http://stored.test/acs"] }), /acsUrls/],
    ["a function-only option", () => stored({ authorize: "() => true" }), /authorize|Unrecognized/],
    ["an unknown option", () => stored({ nope: 1 }), /nope|Unrecognized/],
    ["a bad attribute map", () => stored({ attributes: { a: { field: "x", part: "middle" } } }), /part/],
    ["a bad certificate", () => stored({ spCertificate: "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----" }), /spCertificate/],
  ])("rejects %s with its issues", async (_, sp, re) => {
    const { auth } = await host();
    const { browser } = await admin(auth);
    const res = await api(browser, "/create", { serviceProvider: sp() });
    expect(res.status).toBe(400);
    const body = await json(res);
    expect(body.code).toBe("INVALID_SERVICE_PROVIDER");
    expect(body.issues.join("\n")).toMatch(re);
  });

  it("duplicates → 409; ids and entity IDs of SPs in code → 409", async () => {
    const { auth } = await host();
    const { browser } = await admin(auth);
    await api(browser, "/create", { serviceProvider: stored() });
    const dupId = await api(browser, "/create", { serviceProvider: stored({ entityId: `${NEW_SP}/x` }) });
    const dupEntity = await api(browser, "/create", { serviceProvider: stored({ id: `${SP_ID}-o` }) });
    expect([dupId.status, (await json(dupId)).code]).toEqual([409, "SERVICE_PROVIDER_EXISTS"]);
    expect([dupEntity.status, (await json(dupEntity)).code]).toEqual([409, "SERVICE_PROVIDER_EXISTS"]);
    const codeId = await api(browser, "/create", { serviceProvider: stored({ id: "code-sp", entityId: `${NEW_SP}/y` }) });
    const codeEntity = await api(browser, "/create", { serviceProvider: stored({ id: `${SP_ID}-z`, entityId: SP_ENTITY_ID }) });
    expect([codeId.status, (await json(codeId)).code]).toEqual([409, "SERVICE_PROVIDER_IN_CODE"]);
    expect([codeEntity.status, (await json(codeEntity)).code]).toEqual([409, "SERVICE_PROVIDER_IN_CODE"]);
  });
});

describe("SP registry: who may manage it", () => {
  it("not mounted without canManage", async () => {
    const { auth } = await host({ registry: { canManage: undefined } });
    const { browser } = await admin(auth);
    expect((await api(browser, "")).status).toBe(404);
  });

  it("signed out → 401; a non-admin → 403", async () => {
    const { auth } = await host();
    expect((await api(new Browser(auth), "")).status).toBe(401);
    const { browser } = await admin(auth, "user");
    const res = await api(browser, "/create", { serviceProvider: stored() });
    expect([res.status, (await json(res)).code]).toEqual([403, "REGISTRY_NOT_ALLOWED"]);
  });

  it("a demoted admin loses access at once (the user is re-read from the database)", async () => {
    const { auth } = await host();
    const { browser, user } = await admin(auth);
    expect((await api(browser, "")).status).toBe(200);
    const ctx = await auth.$context;
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "user" } });
    expect((await api(browser, "")).status).toBe(403);
  });

  it("with Better Auth's cookie cache on, a demoted admin still loses access at once", async () => {
    const { auth } = await host({ auth: { session: { cookieCache: { enabled: true, maxAge: 300 } } } });
    const { browser, user } = await admin(auth);
    // Refresh the session so the cookie cache holds the admin role.
    await browser.fetch(`${AUTH_BASE}/get-session`);
    expect((await api(browser, "")).status).toBe(200);
    const ctx = await auth.$context;
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "user" } });
    expect((await browser.fetch(`${AUTH_BASE}/get-session`)).status).toBe(200); // cached: still "admin" here
    expect((await api(browser, "")).status).toBe(403);
  });

  it("an impersonated session can't manage SPs, even an admin's", async () => {
    const { auth } = await host();
    const { browser, user } = await admin(auth);
    const ctx = await auth.$context;
    await ctx.adapter.update({ model: "session", where: [{ field: "userId", value: user.id }], update: { impersonatedBy: "someone" } });
    expect((await api(browser, "")).status).toBe(403);
  });

  it("mutations keep Better Auth's origin check", async () => {
    // Better Auth turns origin checks off under test unless told otherwise.
    const { auth } = await host({ auth: { advanced: { database: { validateSchema: true }, disableOriginCheck: false } } });
    const { browser } = await admin(auth);
    expect((await api(browser, "/create", { serviceProvider: stored() }, "https://evil.example")).status).toBe(403);
  });

  it("canManage throwing denies", async () => {
    const { auth } = await host({ registry: { canManage: () => { throw new Error("boom"); } } });
    const { browser } = await admin(auth);
    expect((await api(browser, "")).status).toBe(403);
  });
});

describe("SP registry: storage and caching", () => {
  it("another instance on the same database sees a new SP after its cache expires (0 s here)", async () => {
    const database = await createHostDatabase();
    const a = await host({ database });
    const b = await host({ database, registry: { cacheSeconds: 0 } });
    const { browser } = await admin(a.auth);
    const other = new Browser(b.auth);
    await other.signUp();
    expect(await code(await ssoTo(other))).toBe("UNKNOWN_SERVICE_PROVIDER");
    await api(browser, "/create", { serviceProvider: stored() });
    expect((await ssoTo(other)).status).toBe(200);
  });

  it("with caching, another instance may keep a miss for up to cacheSeconds", async () => {
    const database = await createHostDatabase();
    const a = await host({ database });
    const b = await host({ database, registry: { cacheSeconds: 60 } });
    const { browser } = await admin(a.auth);
    const other = new Browser(b.auth);
    await other.signUp();
    expect(await code(await ssoTo(other))).toBe("UNKNOWN_SERVICE_PROVIDER");
    await api(browser, "/create", { serviceProvider: stored() });
    expect(await code(await ssoTo(other))).toBe("UNKNOWN_SERVICE_PROVIDER"); // cached miss (documented)
  });

  it("a row edited by hand into an invalid config is ignored and reported, never used", async () => {
    const logs: string[] = [];
    const { auth } = await host({ logs, registry: { cacheSeconds: 0 } });
    const { browser } = await admin(auth);
    await api(browser, "/create", { serviceProvider: stored() });
    const ctx = await auth.$context;
    await ctx.adapter.update({ model: "samlIdpServiceProvider", where: [{ field: "spId", value: SP_ID }], update: { config: JSON.stringify(stored({ acsUrls: ["http://evil.example/acs"] })) } });
    expect(await code(await ssoTo(browser))).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(logs.some((m) => m.includes(`SP ${SP_ID} no longer validates`))).toBe(true);
    expect((await json(await api(browser, `/get?id=${SP_ID}`))).serviceProvider).toMatchObject({ valid: false });
  });

  it("the table only exists in the schema when the registry is enabled", async () => {
    const without = await host({ registry: false });
    const ctx = await without.auth.$context;
    const plugin = ctx.options.plugins?.find((p: any) => p.id === "saml-idp") as any;
    expect(Object.keys(plugin.schema)).toEqual(["samlIdpSeenRequest"]);
  });
});

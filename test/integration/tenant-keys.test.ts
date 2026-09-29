// Multi-tenant IdP, phase 2 (D-058): a signing key per tenant. Both runtimes: on workerd the key
// table comes from D1 migration 0008, and every key here is generated there (RSA 3072).
import { X509Certificate } from "node:crypto";
import { organization } from "better-auth/plugins";
import { describe, expect, inject, it } from "vitest";
import { parseDoc, verifyEnveloped } from "../../src/cli/saml";
import { decryptTenantKey, encryptTenantKey, generateTenantKey, stateKeyOf, TENANT_KEY_MODEL, TenantKeyError, TenantKeyStore } from "../../src/saml/tenant-keys";
import type { ServiceProviderConfig } from "../../src/types";
import type { TestSamlOptions } from "../support/config";
import { AUTH_BASE, createHost, createHostDatabase, type HostDatabase } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl, SSO_URL } from "../support/sp";

const keys = inject("keys");
const SECRET = "test-secret-that-is-at-least-32-characters-long";
const SP = { entityId: "https://sp.tenant-keys.test/metadata", acs: "https://sp.tenant-keys.test/acs" };
const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";
const urls = (key: string) => ({ sso: `${AUTH_BASE}/saml2/idp/sso/${key}`, metadata: `${AUTH_BASE}/saml2/idp/metadata/${key}` });
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const certsIn = (xml: string) => [...xml.matchAll(/<(?:ds:)?X509Certificate>([^<]+)</g)].map((m) => m[1]!.replace(/\s+/g, ""));
const b64 = (pem: string) => pem.replace(/-----[^-]+-----|\s+/g, "");
let n = 0;
/** The same browser (its cookie jar) talking to another host on the same database. */
const onHost = (b: Browser, auth: Browser["auth"]): Browser => Object.assign(Object.create(Browser.prototype), b, { auth });

/** Did this certificate sign the Response and its Assertion? */
function signedWith(xml: string, cert: string): boolean {
  const doc = parseDoc(xml);
  const response = doc.documentElement;
  const assertion = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")[0];
  return verifyEnveloped(xml, doc, response, [cert]).valid === true && verifyEnveloped(xml, doc, assertion, [cert]).valid === true;
}

/**
 * Two tenants, A and B, each with an SP in code (the same entity ID in both), a member signed in,
 * and an admin. `keys` picks the mode; hosts share `database`, so a second host sees the same rows.
 */
async function world(o: { saml?: TestSamlOptions; database?: HostDatabase; auth?: Record<string, unknown> } = {}) {
  const t = `${Date.now().toString(36)}${n++}`;
  const database = o.database ?? (await createHostDatabase());
  const events: any[] = [];
  const saml = (sps: ServiceProviderConfig[]): TestSamlOptions => ({
    registry: { enabled: true, canManage, cacheSeconds: 0 },
    tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, minPublishedSeconds: 0 },
    auditLog: { enabled: true },
    events: { onTenantChanged: (e) => void events.push(e) },
    serviceProviders: sps,
    ...o.saml,
  });
  const first = await createHost({ database, plugins: [organization()], saml: saml([]), auth: o.auth });
  const firstCtx = (await first.auth.$context) as any;
  const org = (name: string) => firstCtx.adapter.create({ model: "organization", data: { name, slug: `${name.toLowerCase()}-${t}`, createdAt: new Date() } });
  const [orgA, orgB] = [await org("Acme"), await org("Globex")];
  const sps: ServiceProviderConfig[] = [
    { id: `a-${t}`, entityId: SP.entityId, acsUrls: [SP.acs], tenant: String(orgA.id) },
    { id: `b-${t}`, entityId: SP.entityId, acsUrls: [SP.acs], tenant: String(orgB.id) },
  ];
  const host = async (extra: TestSamlOptions = {}, auth = o.auth) => {
    const { auth: a } = await createHost({ database, plugins: [organization()], saml: { ...saml(sps), ...extra }, auth });
    return a;
  };
  const auth = await host();
  const ctx = (await auth.$context) as any;
  const admin = new Browser(auth);
  const adminUser = await admin.signUp();
  await ctx.adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
  const api = (as: Browser) => (path: string, body?: unknown) =>
    as.fetch(`${AUTH_BASE}/saml-idp/tenants${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  const browser = new Browser(auth);
  const user = await browser.signUp();
  for (const o of [orgA, orgB]) await ctx.adapter.create({ model: "member", data: { organizationId: o.id, userId: user.id, role: "member", createdAt: new Date() } });
  /** A sign-in at the tenant's URL as the member (`b`: the member's browser, possibly on another host). */
  /** A member of A and B, signed in on another host (its own cookies: another secret signs them). */
  const memberOn = async (a: Browser["auth"]) => {
    const b = new Browser(a);
    const u = await b.signUp();
    for (const o of [orgA, orgB]) await ctx.adapter.create({ model: "member", data: { organizationId: o.id, userId: u.id, role: "member", createdAt: new Date() } });
    return b;
  };
  const signIn = async (key: string, b = browser) => {
    const url = (await redirectUrl(authnRequestXml({ destination: urls(key).sso, issuer: SP.entityId, acsUrl: SP.acs }).xml)).replace(SSO_URL, urls(key).sso);
    return b.fetch(url);
  };
  return { auth, ctx, host, admin, api, tenants: api(admin), browser, user, orgA, orgB, t, events, database, signIn, memberOn };
}

const json = async (res: Response) => {
  const body = (await res.json()) as any;
  if (res.status !== 200) throw new Error(`${res.status} ${JSON.stringify(body)}`);
  return body;
};

describe("tenant signing keys: storage (D-058)", () => {
  it("a key round-trips; a ciphertext moved to another tenant or kid, or made for another purpose, is refused", async () => {
    const { privateKeyPem } = generateTenantKey("unit");
    const sealed = await encryptTenantKey(SECRET, "org-a", "k1", privateKeyPem);
    expect(sealed).not.toContain("PRIVATE KEY");
    expect(await decryptTenantKey(SECRET, { tenantId: "org-a", kid: "k1", encryptedPrivateKey: sealed })).toBe(privateKeyPem);
    await expect(decryptTenantKey(SECRET, { tenantId: "org-b", kid: "k1", encryptedPrivateKey: sealed })).rejects.toThrow(TenantKeyError);
    await expect(decryptTenantKey(SECRET, { tenantId: "org-a", kid: "k2", encryptedPrivateKey: sealed })).rejects.toThrow(/belongs to another row/);
    await expect(decryptTenantKey("another-secret-of-at-least-32-characters!!", { tenantId: "org-a", kid: "k1", encryptedPrivateKey: sealed })).rejects.toThrow(/can't be decrypted/);
    // Anything else Better Auth seals with the same secret isn't a tenant key.
    const { symmetricEncrypt } = await import("better-auth/crypto");
    const other = await symmetricEncrypt({ key: SECRET, data: JSON.stringify({ tenantId: "org-a", kid: "k1", privateKeyPem }) });
    await expect(decryptTenantKey(SECRET, { tenantId: "org-a", kid: "k1", encryptedPrivateKey: other })).rejects.toThrow(/belongs to another row/);
  });

  it("each isolate caches a tenant's keys for cacheSeconds: a rotation elsewhere is seen once that time is up, or at once after a local write", async () => {
    const rows: any[] = [];
    const adapter = { findMany: async () => rows.map((r) => ({ ...r })) };
    let now = 1_000_000;
    const store = new TenantKeyStore(60_000, () => now);
    const shared = { certificate: "SHARED", additionalCertificates: [] } as any;
    const key = generateTenantKey("cache");
    const row = async (kid: string, state: "next" | "active") => ({
      id: kid,
      tenantId: "org",
      kid,
      state,
      stateKey: stateKeyOf("org", state),
      encryptedPrivateKey: await encryptTenantKey(SECRET, "org", kid, key.privateKeyPem),
      certificate: key.certificate,
      notAfter: new Date(),
      createdAt: new Date(),
    });
    expect((await store.signing(adapter, SECRET, "org", shared)).certificate).toBe("SHARED");
    rows.push(await row("k1", "active")); // another isolate activated a key
    expect((await store.signing(adapter, SECRET, "org", shared)).certificate).toBe("SHARED"); // cached
    now += 60_001;
    expect((await store.signing(adapter, SECRET, "org", shared)).certificate).toBe(key.certificate);
    rows.length = 0;
    store.invalidate(); // a write in this isolate
    expect((await store.signing(adapter, SECRET, "org", shared)).certificate).toBe("SHARED");
  });

  it("generated keys are RSA 3072 with a two-year certificate for the tenant", () => {
    const { certificate } = generateTenantKey("acme");
    const cert = new X509Certificate(certificate);
    expect(cert.publicKey.asymmetricKeyDetails?.modulusLength).toBe(3072);
    expect(cert.subject).toContain("saml-idp tenant acme");
    const days = (new Date(cert.validTo).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(725);
    expect(days).toBeLessThan(735);
  });
});

describe("tenant signing keys: per tenant (D-058)", () => {
  it("a new tenant gets its own key at once: its metadata publishes it, its Responses verify with it and not with the shared or the other tenant's", async () => {
    const w = await world();
    const a = (await json(await w.tenants("/create", { organizationId: w.orgA.id }))).tenant;
    const b = (await json(await w.tenants("/create", { organizationId: w.orgB.id }))).tenant;
    expect(a.signing).toBe("own");
    expect(a.keys).toHaveLength(1);
    expect(a.keys[0]).toMatchObject({ state: "active" });
    expect(a.keys[0]).not.toHaveProperty("encryptedPrivateKey");
    const certA = a.keys[0].certificate as string;
    const certB = b.keys[0].certificate as string;
    expect(certA).not.toBe(certB);

    const md = await (await w.auth.handler(new Request(urls(w.orgA.id).metadata))).text();
    expect(certsIn(md)).toEqual([b64(certA)]);
    expect(certsIn(md)).not.toContain(b64(keys.idp.certificate));

    const form = await readAutoPost(await w.signIn(w.orgA.id));
    expect(signedWith(form.xml, certA)).toBe(true);
    expect(signedWith(form.xml, keys.idp.certificate)).toBe(false);
    expect(signedWith(form.xml, certB)).toBe(false);
    const formB = await readAutoPost(await w.signIn(w.orgB.id));
    expect(signedWith(formB.xml, certB)).toBe(true);
    expect(signedWith(formB.xml, certA)).toBe(false);

    // Stored sealed: no PEM in the table.
    const rows = (await w.ctx.adapter.findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: w.orgA.id }] })) as any[];
    expect(rows).toHaveLength(1);
    expect(rows[0].encryptedPrivateKey).not.toContain("PRIVATE KEY");
  });

  it("rotation: rotate publishes the next certificate; activate switches the signing key and keeps the old one published; retire removes it and erases its private key", async () => {
    const w = await world();
    const created = (await json(await w.tenants("/create", { organizationId: w.orgA.id }))).tenant;
    const first = created.keys[0].certificate as string;
    const rotated = (await json(await w.tenants("/keys/rotate", { organizationId: w.orgA.id }))).tenant;
    const next = rotated.keys.find((k: any) => k.state === "next");
    expect(next.activatableAt).toBeDefined();
    let md = await (await w.auth.handler(new Request(urls(w.orgA.id).metadata))).text();
    expect(certsIn(md)).toEqual([b64(first), b64(next.certificate)]);
    expect(signedWith((await readAutoPost(await w.signIn(w.orgA.id))).xml, first)).toBe(true);

    // A second rotation before activation is refused: one next key at a time.
    expect((await w.tenants("/keys/rotate", { organizationId: w.orgA.id })).status).toBe(409);

    const activated = (await json(await w.tenants("/keys/activate", { organizationId: w.orgA.id }))).tenant;
    expect(activated.keys.map((k: any) => k.state)).toEqual(["active", "previous"]);
    md = await (await w.auth.handler(new Request(urls(w.orgA.id).metadata))).text();
    expect(certsIn(md)).toEqual([b64(next.certificate), b64(first)]);
    const after = (await readAutoPost(await w.signIn(w.orgA.id))).xml;
    expect(signedWith(after, next.certificate)).toBe(true);
    expect(signedWith(after, first)).toBe(false);

    const retired = (await json(await w.tenants("/keys/retire", { organizationId: w.orgA.id }))).tenant;
    expect(retired.keys.map((k: any) => k.state)).toEqual(["active", "retired"]);
    md = await (await w.auth.handler(new Request(urls(w.orgA.id).metadata))).text();
    expect(certsIn(md)).toEqual([b64(next.certificate)]);
    const rows = (await w.ctx.adapter.findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: w.orgA.id }] })) as any[];
    expect(rows.find((r) => r.state === "retired").encryptedPrivateKey).toBe("");
    expect((await w.tenants("/keys/retire", { organizationId: w.orgA.id })).status).toBe(409);
    expect(w.events.map((e) => e.action)).toEqual(["created", "key.rotated", "key.activated", "key.retired"]);
  });

  it("activation waits for minPublishedSeconds unless forced, and a forced activation is marked in the event and the audit log", async () => {
    const w = await world({ saml: { tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, minPublishedSeconds: 3600 } } });
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    await json(await w.tenants("/keys/rotate", { organizationId: w.orgA.id }));
    const early = await w.tenants("/keys/activate", { organizationId: w.orgA.id });
    expect(early.status).toBe(409);
    const body = (await early.json()) as any;
    expect(body.code).toBe("TENANT_SIGNING_KEY_TOO_NEW");
    expect(new Date(body.activatableAt).getTime()).toBeGreaterThan(Date.now() + 3500_000);
    const forced = (await json(await w.tenants("/keys/activate", { organizationId: w.orgA.id, force: true }))).tenant;
    expect(forced.keys.map((k: any) => k.state)).toEqual(["active", "previous"]);
    const event = w.events.find((e) => e.action === "key.activated");
    expect(event).toMatchObject({ type: "tenant.changed", forced: true, tenantId: w.orgA.id });
    // This tenant's rows (on workerd the D1 database is shared by the file's tests).
    const audit = ((await w.ctx.adapter.findMany({ model: "samlIdpAuditEvent", where: [{ field: "tenantId", value: w.orgA.id }] })) as any[]).filter((r) => r.type === "tenant.changed");
    expect(audit.map((r) => JSON.parse(r.details).action).sort()).toEqual(["created", "key.activated", "key.rotated"]);
    expect(JSON.parse(audit.find((r) => JSON.parse(r.details).action === "key.activated").details)).toMatchObject({ forced: true, userId: expect.any(String) });
  });

  it("an uploaded key must be a matching RSA pair; a bad one is refused and nothing is stored", async () => {
    const w = await world();
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    const mismatch = await w.tenants("/keys/rotate", { organizationId: w.orgA.id, privateKey: keys.idp.privateKey, certificate: keys.sp.certificate });
    expect(mismatch.status).toBe(400);
    expect(((await mismatch.json()) as any).code).toBe("INVALID_TENANT_SIGNING_KEY");
    expect((await w.tenants("/keys/rotate", { organizationId: w.orgA.id, privateKey: keys.idp.privateKey })).status).toBe(400);
    const uploaded = (await json(await w.tenants("/keys/rotate", { organizationId: w.orgA.id, privateKey: keys.idpNext.privateKey, certificate: keys.idpNext.certificate }))).tenant;
    expect(uploaded.keys.find((k: any) => k.state === "next").certificate).toBe(keys.idpNext.certificate);
  });

  it("key routes need the manager, and exist only with per-tenant keys", async () => {
    const w = await world();
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    const member = w.api(w.browser);
    expect((await member("/keys/rotate", { organizationId: w.orgA.id })).status).toBe(403);
    expect((await member(`/keys?organizationId=${w.orgA.id}`)).status).toBe(403);
    expect((await w.tenants(`/keys?organizationId=nobody-${w.t}`)).status).toBe(404);
    const shared = await w.host({ tenants: { enabled: true, keys: "shared", cacheSeconds: 0 } });
    expect((await new Browser(shared).fetch(`${AUTH_BASE}/saml-idp/tenants/keys/rotate`, { method: "POST" })).status).toBe(404);
  });
});

describe("tenant signing keys: never another key (D-058)", () => {
  it("a key that can't be decrypted refuses sign-in (INTERNAL_ERROR) and metadata (500); nothing is signed with the shared key", async () => {
    const w = await world();
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    await w.ctx.adapter.update({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: w.orgA.id }], update: { encryptedPrivateKey: "garbage" } });
    const res = await w.signIn(w.orgA.id);
    expect(res.status).toBe(500);
    expect(await code(res)).toBe("INTERNAL_ERROR");
    expect(await res.text()).not.toContain("SAMLResponse");
    expect((await w.auth.handler(new Request(urls(w.orgA.id).metadata))).status).toBe(500);
  });

  it("tenant A's sealed key copied into tenant B's row is refused: B never signs with A's key", async () => {
    const w = await world();
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    await json(await w.tenants("/create", { organizationId: w.orgB.id }));
    const [rowA] = (await w.ctx.adapter.findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: w.orgA.id }] })) as any[];
    await w.ctx.adapter.update({
      model: TENANT_KEY_MODEL,
      where: [{ field: "tenantId", value: w.orgB.id }],
      update: { encryptedPrivateKey: rowA.encryptedPrivateKey, certificate: rowA.certificate },
    });
    const res = await w.signIn(w.orgB.id);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("SAMLResponse");
  });

  it("with no active key but keys of its own before (an activation cut short), a tenant refuses rather than use the shared key", async () => {
    const w = await world();
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    await w.ctx.adapter.update({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: w.orgA.id }], update: { state: "previous", stateKey: `previous:${w.t}` } });
    const res = await w.signIn(w.orgA.id);
    expect(res.status).toBe(500);
    expect(await code(res)).toBe("INTERNAL_ERROR");
  });
});

describe("tenant signing keys: moving from the shared key (D-058)", () => {
  it("a tenant made with shared keys keeps signing with the shared key; rotate + activate move it to its own, with the shared certificate published as previous", async () => {
    // Tenants made before per-tenant keys: the same database, first with keys: "shared". (The
    // schema is created up front with the key table, as the upgrade's migration would add it.)
    const database = await createHostDatabase();
    await createHost({ database, plugins: [organization()], saml: { registry: { enabled: true, canManage }, tenants: { enabled: true, keys: "per-tenant" }, auditLog: { enabled: true } } });
    const w = await world({ database, saml: { tenants: { enabled: true, keys: "shared", cacheSeconds: 0 } } });
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    const auth = await w.host({ tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, minPublishedSeconds: 0 } });
    const browser = onHost(w.browser, auth);
    const tenants = w.api(onHost(w.admin, auth));

    const before = (await json(await tenants(`/get?organizationId=${w.orgA.id}`))).tenant;
    expect(before.signing).toBe("shared");
    expect(before.keys).toEqual([]);
    expect(signedWith((await readAutoPost(await w.signIn(w.orgA.id, browser))).xml, keys.idp.certificate)).toBe(true);

    const next = (await json(await tenants("/keys/rotate", { organizationId: w.orgA.id }))).tenant.keys[0];
    let md = await (await auth.handler(new Request(urls(w.orgA.id).metadata))).text();
    expect(certsIn(md)).toEqual([b64(keys.idp.certificate), b64(next.certificate)]);
    // Still the shared key until activation.
    expect(signedWith((await readAutoPost(await w.signIn(w.orgA.id, browser))).xml, keys.idp.certificate)).toBe(true);

    const after = (await json(await tenants("/keys/activate", { organizationId: w.orgA.id }))).tenant;
    expect(after.signing).toBe("own");
    expect(after.keys.map((k: any) => [k.state, k.kid === "shared"])).toEqual([
      ["active", false],
      ["previous", true],
    ]);
    md = await (await auth.handler(new Request(urls(w.orgA.id).metadata))).text();
    expect(certsIn(md)).toEqual([b64(next.certificate), b64(keys.idp.certificate)]);
    const xml = (await readAutoPost(await w.signIn(w.orgA.id, browser))).xml;
    expect(signedWith(xml, next.certificate)).toBe(true);
    expect(signedWith(xml, keys.idp.certificate)).toBe(false);

    // Retiring the shared "previous" only stops publishing it; the root IdP keeps its key.
    await json(await tenants("/keys/retire", { organizationId: w.orgA.id }));
    md = await (await auth.handler(new Request(urls(w.orgA.id).metadata))).text();
    expect(certsIn(md)).toEqual([b64(next.certificate)]);
    const rootMd = await (await auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`))).text();
    expect(certsIn(rootMd)).toContain(b64(keys.idp.certificate));
  });

  it("the key-encryption secret rotates with Better Auth's secrets: an older version still decrypts; dropped, the tenant refuses", async () => {
    const v1 = "first-secret-version-at-least-32-characters";
    const v2 = "second-secret-version-at-least-32-characters";
    const w = await world({ auth: { secrets: [{ version: 1, value: v1 }] } });
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    const cert = (await json(await w.tenants(`/get?organizationId=${w.orgA.id}`))).tenant.keys[0].certificate;
    const both = await w.host({}, { secrets: [{ version: 2, value: v2 }, { version: 1, value: v1 }] });
    const b1 = await w.memberOn(both);
    expect(signedWith((await readAutoPost(await w.signIn(w.orgA.id, b1))).xml, cert)).toBe(true);
    const onlyNew = await w.host({}, { secrets: [{ version: 2, value: v2 }] });
    const b2 = await w.memberOn(onlyNew);
    const res = await w.signIn(w.orgA.id, b2);
    expect(res.status).toBe(500);
  });

  it("tenants.keyEncryptionSecret seals keys instead of Better Auth's secret", async () => {
    const own = "a-dedicated-key-encryption-secret-32+chars";
    const w = await world({ saml: { tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, minPublishedSeconds: 0, keyEncryptionSecret: own } } });
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    const [row] = (await w.ctx.adapter.findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: w.orgA.id }] })) as any[];
    expect(await decryptTenantKey(own, row)).toContain("PRIVATE KEY");
    await expect(decryptTenantKey(SECRET, row)).rejects.toThrow(TenantKeyError);
  });

  it("deleting a tenant deletes its keys", async () => {
    const w = await world();
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    await json(await w.tenants("/keys/rotate", { organizationId: w.orgA.id }));
    // A host without the tenant's SPs in code: a tenant with SPs can't be deleted.
    const bare = w.api(onHost(w.admin, await w.host({ serviceProviders: [] })));
    await json(await bare("/delete", { organizationId: w.orgA.id }));
    expect(await w.ctx.adapter.findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: w.orgA.id }] })).toEqual([]);
    expect(w.events.at(-1)).toMatchObject({ action: "deleted", tenantId: w.orgA.id });
  });
});

describe("review 7: key rows over time (D-060)", () => {
  it("R7-1: many rotations keep a bounded number of rows (the newest retired ones), and the tenant keeps signing", async () => {
    const w = await world();
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    for (let i = 0; i < 8; i++) {
      await json(await w.tenants("/keys/rotate", { organizationId: w.orgA.id }));
      await json(await w.tenants("/keys/activate", { organizationId: w.orgA.id }));
    }
    const rows = (await w.ctx.adapter.findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: w.orgA.id }], limit: 1000 })) as any[];
    expect(rows.filter((r) => r.state === "retired").length).toBeLessThanOrEqual(5);
    expect(rows.filter((r) => r.state === "active")).toHaveLength(1);
    const active = rows.find((r) => r.state === "active");
    expect(signedWith((await readAutoPost(await w.signIn(w.orgA.id))).xml, active.certificate)).toBe(true);
  });

  it("R7-2: a tenant key whose certificate expires within 30 days, or has expired, is flagged in its record", async () => {
    const { generateKeyPairSync } = await import("node:crypto");
    const { selfSignedCertificate } = await import("../../src/saml/certificate");
    const w = await world();
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const shortLived = selfSignedCertificate(privateKey, { commonName: "short", days: 10 });
    await json(await w.tenants("/keys/rotate", { organizationId: w.orgA.id, privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(), certificate: shortLived }));
    const record = (await json(await w.tenants("/keys/activate", { organizationId: w.orgA.id }))).tenant;
    expect(record.warnings.join()).toMatch(/expires on .* \(within 30 days\)/);
    const fresh = (await json(await w.tenants(`/get?organizationId=${w.orgB.id}`).then(async (r) => (r.status === 404 ? w.tenants("/create", { organizationId: w.orgB.id }) : r)))).tenant;
    expect(fresh.warnings).toEqual([]);
  });

  it("R7-3: listing tenants reads their own key rows, however many other key rows there are", async () => {
    const w = await world();
    // Rows of no listed tenant (left by hand, or another app), written first.
    for (let i = 0; i < 160; i++)
      await w.ctx.adapter.create({
        model: TENANT_KEY_MODEL,
        data: { tenantId: `ghost-${w.t}`, kid: `g${i}`, state: "retired", stateKey: `retired:ghost-${w.t}-${i}`, encryptedPrivateKey: "", certificate: "x", notAfter: new Date(), createdAt: new Date(), activatedAt: null },
      });
    await json(await w.tenants("/create", { organizationId: w.orgA.id }));
    const listed = (await json(await w.tenants(""))).tenants.find((t: any) => t.organizationId === w.orgA.id);
    expect(listed.signing).toBe("own");
    expect(listed.keys).toHaveLength(1);
  });
});

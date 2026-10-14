// The root IdP's managed signing key (D-080): generated the first time it's needed, stored encrypted
// in samlIdpTenantKey under the reserved owner, rotated like a tenant's key, and never replaced by
// another key when it can't be used. Both runtimes: on workerd the table comes from D1 migration
// 0008, and the database is shared by this file's tests, so each one starts by clearing the rows.
import { X509Certificate } from "node:crypto";
import { organization } from "better-auth/plugins";
import { describe, expect, inject, it } from "vitest";
import { parseDoc, verifyEnveloped } from "../../src/cli/saml";
import { resolveOptions, SamlIdpConfigError } from "../../src/options";
import { decryptTenantKey, FAILED_RETRY_MS, GENERATED_KEY_BITS, ROOT_KEY_OWNER, stateKeyOf, TENANT_KEY_MODEL, TenantKeyStore } from "../../src/saml/tenant-keys";
import { baseOptions, type TestSamlOptions } from "../support/config";
import { AUTH_BASE, createHost, createHostDatabase, type HostDatabase } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const keys = inject("keys");
const SECRET = "test-secret-that-is-at-least-32-characters-long";
const SP = { id: "managed-sp", entityId: "https://sp.managed-key.test/metadata", acs: "https://sp.managed-key.test/acs" };
const METADATA = `${AUTH_BASE}/saml2/idp/metadata`;
const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";
const certsIn = (xml: string) => [...xml.matchAll(/<(?:ds:)?X509Certificate>([^<]+)</g)].map((m) => m[1]!.replace(/\s+/g, ""));
const b64 = (pem: string) => pem.replace(/-----[^-]+-----|\s+/g, "");
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

/** Did this certificate sign the Response and its Assertion? */
function signedWith(xml: string, cert: string): boolean {
  const doc = parseDoc(xml);
  const assertion = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")[0];
  return verifyEnveloped(xml, doc, doc.documentElement, [cert]).valid === true && verifyEnveloped(xml, doc, assertion, [cert]).valid === true;
}

const json = async (res: Response) => {
  const body = (await res.json()) as any;
  if (res.status !== 200) throw new Error(`${res.status} ${JSON.stringify(body)}`);
  return body;
};

/**
 * A host with a managed key and an SP in code, an admin, and a user signed in. Hosts made with
 * `host()` share the database, so they see the same key rows.
 */
async function world(o: { saml?: TestSamlOptions; database?: HostDatabase; plugins?: any[] } = {}) {
  const database = o.database ?? (await createHostDatabase());
  const events: any[] = [];
  const saml = (extra: TestSamlOptions = {}): TestSamlOptions => ({
    signing: { managed: true, minPublishedSeconds: 0 },
    registry: { enabled: true, canManage, cacheSeconds: 0 },
    auditLog: { enabled: true },
    events: { onSigningKeyChanged: (e) => void events.push(e) },
    serviceProviders: [{ id: SP.id, entityId: SP.entityId, acsUrls: [SP.acs] }],
    ...o.saml,
    ...extra,
  });
  const host = async (extra: TestSamlOptions = {}) => (await createHost({ database, plugins: o.plugins, saml: saml(extra) })).auth;
  const auth = await host();
  const ctx = (await auth.$context) as any;
  // Every test starts with no root key (on workerd the file's tests share one D1 database).
  await ctx.adapter.deleteMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: ROOT_KEY_OWNER }] });
  const admin = new Browser(auth);
  const adminUser = await admin.signUp();
  await ctx.adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
  const browser = new Browser(auth);
  await browser.signUp();
  const api = (as: Browser) => (path: string, body?: unknown) =>
    as.fetch(`${AUTH_BASE}/saml-idp/signing-keys${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  const rows = async () => ((await ctx.adapter.findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: ROOT_KEY_OWNER }] })) as any[]).filter((r) => r.tenantId === ROOT_KEY_OWNER);
  const metadata = async (a = auth) => (await a.handler(new Request(METADATA))).text();
  /** A sign-in as the user: the auto-POSTed Response. */
  const signIn = async (b = browser) => b.fetch(await redirectUrl(authnRequestXml({ issuer: SP.entityId, acsUrl: SP.acs }).xml));
  return { auth, ctx, host, database, admin, api, keys: api(admin), browser, events, rows, metadata, signIn };
}

describe("managed signing key: the first key (D-080)", () => {
  it("is generated the first time the IdP needs it: stored encrypted and active, published in the metadata, and signing", async () => {
    const w = await world();
    expect(await w.rows()).toEqual([]);
    const md = await w.metadata();
    const [row] = await w.rows();
    expect(row).toMatchObject({ state: "active", stateKey: stateKeyOf(ROOT_KEY_OWNER, "active"), updatedBy: null });
    expect(certsIn(md)).toEqual([b64(row.certificate)]);
    // Sealed to the root owner and its kid, under Better Auth's secret.
    expect(row.encryptedPrivateKey).not.toContain("PRIVATE KEY");
    const pem = await decryptTenantKey(SECRET, row);
    expect(pem).toContain("PRIVATE KEY");
    const cert = new X509Certificate(row.certificate);
    expect((cert.publicKey.asymmetricKeyDetails?.modulusLength ?? 0)).toBe(GENERATED_KEY_BITS);
    // Named after the IdP's host, so admins can tell it apart in SP consoles.
    expect(cert.subject).toContain("CN=saml-idp auth.test");
    const { xml } = await readAutoPost(await w.signIn());
    expect(signedWith(xml, row.certificate)).toBe(true);
    // Reported, without an acting user.
    expect(w.events).toEqual([expect.objectContaining({ type: "signing-key.changed", action: "key.generated", kid: row.kid })]);
    expect(w.events[0].userId).toBeUndefined();
  });

  it("another host on the same database uses the stored key and never makes another; concurrent first requests leave one key", async () => {
    const w = await world();
    const other = await w.host();
    // Two hosts, several requests each, all before any key exists.
    const pages = await Promise.all([...Array.from({ length: 4 }, () => w.metadata()), ...Array.from({ length: 4 }, () => w.metadata(other))]);
    const rows = await w.rows();
    expect(rows).toHaveLength(1);
    for (const md of pages) expect(certsIn(md)).toEqual([b64(rows[0].certificate)]);
    const third = await w.host();
    expect(certsIn(await w.metadata(third))).toEqual([b64(rows[0].certificate)]);
    expect(await w.rows()).toHaveLength(1);
  });

  it("listing the keys makes the first one too, so a setup step can make it before any SP asks", async () => {
    const w = await world();
    const listed = await json(await w.keys(""));
    expect(listed.keys.map((k: any) => k.state)).toEqual(["active"]);
    expect(listed.keys[0]).not.toHaveProperty("encryptedPrivateKey");
    expect(listed.warnings).toEqual([]);
    expect(await w.rows()).toHaveLength(1);
  });

  it("signing.keyEncryptionSecret seals the key instead of Better Auth's secret", async () => {
    const own = "a-signing-key-secret-of-at-least-32-characters";
    const w = await world({ saml: { signing: { managed: true, minPublishedSeconds: 0, keyEncryptionSecret: own } } });
    await w.metadata();
    const [row] = await w.rows();
    expect(await decryptTenantKey(own, row)).toContain("PRIVATE KEY");
    await expect(decryptTenantKey(SECRET, row)).rejects.toThrow(/can't be decrypted/);
  });
});

describe("managed signing key: bringing a key along (D-080)", () => {
  it("initialKey is stored as the first key instead of a generated one, so SPs that trust it keep working; once stored, it's ignored", async () => {
    const initialKey = { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate };
    const w = await world({ saml: { signing: { managed: true, minPublishedSeconds: 0, initialKey } } });
    const md = await w.metadata();
    const [row] = await w.rows();
    expect(b64(row.certificate)).toBe(b64(keys.idp.certificate));
    expect(certsIn(md)).toEqual([b64(keys.idp.certificate)]);
    expect(await decryptTenantKey(SECRET, row)).toBe(keys.idp.privateKey);
    expect(signedWith((await readAutoPost(await w.signIn())).xml, keys.idp.certificate)).toBe(true);
    expect(w.events).toEqual([expect.objectContaining({ type: "signing-key.changed", action: "key.imported", kid: row.kid })]);
    // Another initial key changes nothing once a key is stored.
    const other = await w.host({ signing: { managed: true, initialKey: { privateKey: keys.idpNext.privateKey, certificate: keys.idpNext.certificate } } });
    expect(certsIn(await w.metadata(other))).toEqual([b64(keys.idp.certificate)]);
    expect(await w.rows()).toHaveLength(1);
  });

  it("an initialKey that none of the stored keys is does nothing, and says so once", async () => {
    const w = await world();
    await w.metadata(); // a generated key is stored
    const warnings: string[] = [];
    const late = await w.host({ signing: { managed: true, initialKey: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate } } });
    const ctx = (await late.$context) as any;
    const original = ctx.logger.warn;
    ctx.logger.warn = (m: string, ...rest: unknown[]) => {
      warnings.push(String(m));
      return original.call(ctx.logger, m, ...rest);
    };
    await w.metadata(late);
    await w.metadata(late);
    expect(certsIn(await w.metadata(late))).not.toContain(b64(keys.idp.certificate));
    expect(warnings.filter((m) => m.includes("signing.initialKey is none of the stored signing keys"))).toHaveLength(1);
  });

  it("initialKey is checked at startup like a key given as PEM", () => {
    const mismatch = () => resolveOptions(baseOptions({ signing: { managed: true, initialKey: { privateKey: keys.idp.privateKey, certificate: keys.sp.certificate } } }));
    expect(mismatch).toThrow(SamlIdpConfigError);
    try {
      mismatch();
    } catch (e) {
      expect((e as SamlIdpConfigError).message).toContain("signing.initialKey.certificate: does not match signing.initialKey.privateKey");
    }
  });
});

describe("managed signing key: rotation (D-080)", () => {
  it("rotate publishes the next certificate; activate switches the signing key and keeps the old one published; retire removes it and erases its private key", async () => {
    const w = await world();
    const first = (await json(await w.keys(""))).keys[0].certificate as string;
    const rotated = await json(await w.keys("/rotate", {}));
    expect(rotated.keys.map((k: any) => k.state)).toEqual(["next", "active"]);
    const next = rotated.keys[0];
    expect(certsIn(await w.metadata())).toEqual([b64(first), b64(next.certificate)]);
    expect(signedWith((await readAutoPost(await w.signIn())).xml, first)).toBe(true);
    // One next key at a time.
    expect((await w.keys("/rotate", {})).status).toBe(409);

    const activated = await json(await w.keys("/activate", {}));
    expect(activated.keys.map((k: any) => k.state)).toEqual(["active", "previous"]);
    expect(certsIn(await w.metadata())).toEqual([b64(next.certificate), b64(first)]);
    const after = (await readAutoPost(await w.signIn())).xml;
    expect(signedWith(after, next.certificate)).toBe(true);
    expect(signedWith(after, first)).toBe(false);

    const retired = await json(await w.keys("/retire", {}));
    expect(retired.keys.map((k: any) => k.state)).toEqual(["active", "retired"]);
    expect(certsIn(await w.metadata())).toEqual([b64(next.certificate)]);
    expect((await w.rows()).find((r) => r.state === "retired").encryptedPrivateKey).toBe("");
    expect((await w.keys("/retire", {})).status).toBe(409);
    expect(w.events.map((e) => e.action)).toEqual(["key.generated", "key.rotated", "key.activated", "key.retired"]);
    expect(w.events.slice(1).every((e) => typeof e.userId === "string")).toBe(true);
  });

  it("activation waits for minPublishedSeconds (24 hours by default) unless forced; a forced activation is marked in the event and the audit log", async () => {
    const w = await world({ saml: { signing: { managed: true } } });
    await json(await w.keys("/rotate", {}));
    const early = await w.keys("/activate", {});
    expect(early.status).toBe(409);
    const body = (await early.json()) as any;
    expect(body.code).toBe("SIGNING_KEY_TOO_NEW");
    expect(new Date(body.activatableAt).getTime()).toBeGreaterThan(Date.now() + 86_000_000);
    expect((await json(await w.keys("/activate", { force: true }))).keys.map((k: any) => k.state)).toEqual(["active", "previous"]);
    const event = w.events.find((e) => e.action === "key.activated");
    expect(event).toMatchObject({ type: "signing-key.changed", forced: true });
    // This activation's row (on workerd the audit table is shared by the file's tests).
    const audit = ((await w.ctx.adapter.findMany({ model: "samlIdpAuditEvent", where: [{ field: "type", value: "signing-key.changed" }] })) as any[]).map((r) => JSON.parse(r.details));
    expect(audit.find((d) => d.action === "key.activated" && d.kid === event.kid)).toMatchObject({ forced: true, userId: expect.any(String) });
  });

  it("an uploaded key must be a matching RSA pair; a bad one is refused and nothing is stored", async () => {
    const w = await world();
    const mismatch = await w.keys("/rotate", { privateKey: keys.idp.privateKey, certificate: keys.sp.certificate });
    expect(mismatch.status).toBe(400);
    expect(((await mismatch.json()) as any).code).toBe("INVALID_SIGNING_KEY");
    expect((await w.keys("/rotate", { privateKey: keys.idp.privateKey })).status).toBe(400);
    expect((await w.rows()).filter((r) => r.state === "next")).toEqual([]);
    const uploaded = await json(await w.keys("/rotate", { privateKey: keys.idpNext.privateKey, certificate: keys.idpNext.certificate }));
    expect(uploaded.keys.find((k: any) => k.state === "next").certificate).toBe(keys.idpNext.certificate);
  });

  it("the routes need a host manager, and exist only with a managed key", async () => {
    const w = await world();
    const member = w.api(w.browser);
    expect((await member("")).status).toBe(403);
    expect((await member("/rotate", {})).status).toBe(403);
    // A user who isn't a manager makes no key by asking.
    expect(await w.rows()).toEqual([]);
    const given = await w.host({ signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate } });
    expect((await new Browser(given).fetch(`${AUTH_BASE}/saml-idp/signing-keys/rotate`, { method: "POST" })).status).toBe(404);
  });
});

describe("managed signing key: never another key (D-080)", () => {
  it("a stored key that can't be decrypted refuses metadata (500) and sign-in; no new key is made in its place", async () => {
    const w = await world();
    await w.metadata();
    await w.ctx.adapter.update({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: ROOT_KEY_OWNER }], update: { encryptedPrivateKey: "garbage" } });
    const res = await w.auth.handler(new Request(METADATA));
    expect(res.status).toBe(500);
    const signIn = await w.signIn();
    expect(await code(signIn)).toBe("INTERNAL_ERROR");
    expect(await signIn.text()).not.toContain("SAMLResponse");
    expect(await w.rows()).toHaveLength(1);
  });

  it("with no active key but keys of its own (an activation cut short), it refuses rather than make a new one; activate finishes it", async () => {
    const w = await world();
    await json(await w.keys("/rotate", {}));
    const active = (await w.rows()).find((r) => r.state === "active");
    await w.ctx.adapter.update({ model: TENANT_KEY_MODEL, where: [{ field: "id", value: active.id }], update: { state: "previous", stateKey: stateKeyOf(ROOT_KEY_OWNER, "previous") } });
    expect((await w.auth.handler(new Request(METADATA))).status).toBe(500);
    expect(await w.rows()).toHaveLength(2);
    const finished = await json(await w.keys("/activate", {}));
    expect(finished.keys.map((k: any) => k.state)).toEqual(["active", "previous"]);
    expect((await w.auth.handler(new Request(METADATA))).status).toBe(200);
  });
});

describe("managed signing key: recovering (D-080)", () => {
  it("a key that can't be decrypted is replaced by rotate, a forced activate and retire, none of which needs to decrypt it", async () => {
    const w = await world({ saml: { signing: { managed: true } } }); // 24-hour wait: the forced activation skips it
    await w.metadata();
    await w.ctx.adapter.update({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: ROOT_KEY_OWNER }], update: { encryptedPrivateKey: "garbage" } });
    expect((await w.auth.handler(new Request(METADATA))).status).toBe(500);
    const next = (await json(await w.keys("/rotate", {}))).keys.find((k: any) => k.state === "next");
    expect((await json(await w.keys("/activate", { force: true }))).keys.map((k: any) => k.state)).toEqual(["active", "previous"]);
    expect(signedWith((await readAutoPost(await w.signIn())).xml, next.certificate)).toBe(true);
    await json(await w.keys("/retire", {}));
    expect(certsIn(await w.metadata())).toEqual([b64(next.certificate)]);
  });
});

describe("managed signing key: more root paths (D-080)", () => {
  it("signed metadata and IdP-initiated sign-in use the managed key", async () => {
    const w = await world({ saml: { signMetadata: true, serviceProviders: [{ id: SP.id, entityId: SP.entityId, acsUrls: [SP.acs], allowIdpInitiated: true }] } });
    const md = await w.metadata();
    const [row] = await w.rows();
    const doc = parseDoc(md);
    expect(verifyEnveloped(md, doc, doc.documentElement, [row.certificate]).valid).toBe(true);
    const { xml } = await readAutoPost(await w.browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=${SP.id}`));
    expect(signedWith(xml, row.certificate)).toBe(true);
  });

  it("with the row cache on, a rotation is seen at once by the host that made it", async () => {
    const w = await world({ saml: { registry: { enabled: true, canManage, cacheSeconds: 60 } } });
    const first = certsIn(await w.metadata()); // caches the rows
    const next = (await json(await w.keys("/rotate", {}))).keys.find((k: any) => k.state === "next");
    expect(certsIn(await w.metadata())).toEqual([...first, b64(next.certificate)]);
    await json(await w.keys("/activate", {}));
    expect(certsIn(await w.metadata())[0]).toBe(b64(next.certificate));
    expect(signedWith((await readAutoPost(await w.signIn())).xml, next.certificate)).toBe(true);
  });
});

describe("managed signing key: the store (D-080)", () => {
  const initial = { privateKeyPem: keys.idp.privateKey, certificate: keys.idp.certificate };
  /** An in-memory key table: with or without the UNIQUE state key, or failing every write. */
  const table = (o: { unique?: boolean; failCreate?: boolean } = {}) => {
    const rows: any[] = [];
    const counts = { creates: 0 };
    const adapter = {
      findMany: async ({ where }: any) => rows.filter((r) => r.tenantId === where[0].value).map((r) => ({ ...r })),
      create: async ({ data }: any) => {
        const id = `row${++counts.creates}`; // before any await: concurrent writes get their own ids
        await Promise.resolve();
        if (o.failCreate) throw new Error("no such table: samlIdpTenantKey");
        if (o.unique !== false && rows.some((r) => r.stateKey === data.stateKey)) throw new Error("UNIQUE constraint failed");
        const row = { id, ...data };
        rows.push(row);
        return row;
      },
      delete: async ({ where }: any) => {
        const i = rows.findIndex((r) => r.id === where[0].value);
        if (i >= 0) rows.splice(i, 1);
      },
    };
    /** The same table seen by a writer whose create waits for `release`. */
    const slow = () => {
      let release!: () => void;
      let arrived!: () => void;
      const held = new Promise<void>((r) => (release = r));
      const reached = new Promise<void>((r) => (arrived = r));
      const create = async (args: any) => {
        arrived();
        await held;
        return adapter.create(args);
      };
      return { adapter: { ...adapter, create }, release, reached };
    };
    return { rows, counts, adapter, slow };
  };

  it("one isolate makes the first key once, however many requests ask for it at the same time", async () => {
    const t = table({ unique: false });
    const store = new TenantKeyStore(0);
    await Promise.all(Array.from({ length: 5 }, () => store.ensureFirstKey(t.adapter, SECRET, ROOT_KEY_OWNER, { commonName: "saml-idp", initial })));
    expect(t.counts.creates).toBe(1);
    expect(t.rows).toHaveLength(1);
  });

  it("without the UNIQUE index, two writers that both get in end with one active key", async () => {
    const t = table({ unique: false });
    const [a, b] = [new TenantKeyStore(0), new TenantKeyStore(0)];
    const made = await Promise.all([a, b].map((s) => s.ensureFirstKey(t.adapter, SECRET, ROOT_KEY_OWNER, { commonName: "saml-idp", initial })));
    expect(t.counts.creates).toBe(2);
    expect(t.rows.filter((r) => r.state === "active")).toHaveLength(1);
    // At least one says it stored the key. A writer that re-read before the other's row landed says
    // so too, and its key may then be the one removed: acceptable for a schema missing its index.
    expect(made.filter(Boolean).length).toBeGreaterThanOrEqual(1);
  });

  it("without the UNIQUE index, a slow writer whose key is older still leaves one active key (review: a write that lands last)", async () => {
    const t = table({ unique: false });
    const slow = t.slow();
    // B's key is made first (an earlier clock) but written last; A writes in between and sees only its own.
    const b = new TenantKeyStore(0, () => 1_000).ensureFirstKey(slow.adapter, SECRET, ROOT_KEY_OWNER, { commonName: "saml-idp", initial });
    await slow.reached;
    await new TenantKeyStore(0, () => 2_000).ensureFirstKey(t.adapter, SECRET, ROOT_KEY_OWNER, { commonName: "saml-idp", initial });
    expect(t.rows.filter((r) => r.state === "active")).toHaveLength(1);
    slow.release();
    await b;
    expect(t.rows.filter((r) => r.state === "active")).toHaveLength(1);
  });

  it("a write that fails for another reason isn't retried on every request: only after a while", async () => {
    const t = table({ failCreate: true });
    let now = 1_000_000;
    const store = new TenantKeyStore(0, () => now);
    const ensure = () => store.ensureFirstKey(t.adapter, SECRET, ROOT_KEY_OWNER, { commonName: "saml-idp", initial });
    await expect(ensure()).rejects.toThrow(/no such table/);
    await expect(ensure()).rejects.toThrow(/no such table/);
    expect(t.counts.creates).toBe(1);
    now += FAILED_RETRY_MS + 1;
    await expect(ensure()).rejects.toThrow(/no such table/);
    expect(t.counts.creates).toBe(2);
  });
});

describe("managed signing key with tenants (D-080)", () => {
  it("tenants on the shared key sign with the managed key; a tenant's first own key keeps the managed certificate published as previous", async () => {
    const w = await world({ plugins: [organization()], saml: { tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, minPublishedSeconds: 0 } } });
    const rootCert = (await json(await w.keys(""))).keys[0].certificate as string;
    const org = await w.ctx.adapter.create({ model: "organization", data: { name: "Acme", slug: `acme-${Date.now().toString(36)}`, createdAt: new Date() } });
    // A tenant made before per-tenant keys: no key rows of its own, so it signs with the shared (managed) key.
    const shared = await w.host({ tenants: { enabled: true, keys: "shared", cacheSeconds: 0 } });
    const tenants = (path: string, body?: unknown) =>
      w.admin.fetch(`${AUTH_BASE}/saml-idp/tenants${path}`, { method: body === undefined ? "GET" : "POST", headers: { "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const onShared = Object.assign(Object.create(Browser.prototype), w.admin, { auth: shared }) as Browser;
    const created = await json(await onShared.fetch(`${AUTH_BASE}/saml-idp/tenants/create`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ organizationId: org.id }) }));
    const tenantMd = await (await shared.handler(new Request(created.tenant.metadataUrl))).text();
    expect(certsIn(tenantMd)).toEqual([b64(rootCert)]);
    // Back on per-tenant keys: rotate + activate its first own key.
    await json(await tenants("/keys/rotate", { organizationId: org.id }));
    const activated = (await json(await tenants("/keys/activate", { organizationId: org.id }))).tenant;
    expect(activated.keys.find((k: any) => k.state === "previous").certificate).toBe(rootCert);
  });

  it("the reserved owner can't be used as a tenant's organization id", async () => {
    const w = await world({ plugins: [organization()], saml: { tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0, minPublishedSeconds: 0 } } });
    const res = await w.admin.fetch(`${AUTH_BASE}/saml-idp/tenants/create`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ organizationId: ROOT_KEY_OWNER }) });
    expect(res.status).toBe(400);
    // The lookup by organization id would refuse it too; only the schema answers 400 here.
    for (const id of [ROOT_KEY_OWNER, "SAML-IDP:ROOT", `${ROOT_KEY_OWNER} `])
      expect((await w.admin.fetch(`${AUTH_BASE}/saml-idp/tenants/keys?organizationId=${encodeURIComponent(id)}`)).status).toBe(400);
  });
});

describe("managed signing key: options (D-080)", () => {
  it("takes no key material, and refuses a mix of both forms", () => {
    const r = resolveOptions(baseOptions({ signing: { managed: true }, registry: { enabled: true, canManage } }));
    expect(r.signing).toMatchObject({ managed: true, minPublishedMs: 86_400_000, signatureAlgorithm: "rsa-sha256", sign: "both" });
    expect(r.warnings.filter((w) => w.startsWith("signing.managed"))).toEqual([]);
    expect(() => resolveOptions(baseOptions({ signing: { managed: true, privateKey: keys.idp.privateKey } as any }))).toThrow(SamlIdpConfigError);
    expect(() => resolveOptions(baseOptions({ signing: { managed: false } as any }))).toThrow(SamlIdpConfigError);
    expect(() => resolveOptions(baseOptions({ signing: { managed: true, keyEncryptionSecret: "short" } }))).toThrow(SamlIdpConfigError);
  });

  it("warns when there's no registry API to rotate it with", () => {
    const r = resolveOptions(baseOptions({ signing: { managed: true } }));
    expect(r.warnings.some((w) => w.startsWith("signing.managed: the key is generated and used, but rotating it needs the registry API"))).toBe(true);
  });
});

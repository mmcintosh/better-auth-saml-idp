// Database adapter matrix (roadmap v1.0): every database-dependent behaviour of the plugin, against
// a real database server. Runs only when ADAPTER_DB is set (CI service containers, or local):
//
//   ADAPTER_DB=postgres ADAPTER_URL=postgres://postgres:test@localhost:55432/postgres \
//     npx vitest run --project node test/adapters
//
// Each run creates a fresh database and migrates it with Better Auth's own migrator, as a host would.
import { betterAuth } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { AssertionExchangeError, getSamlIdpExchange, samlIdp } from "../../src";
import { listParticipants } from "../../src/storage/participants";
import { recordRequestId } from "../../src/storage/seen";
import { resetSweepThrottle, sweepExpired } from "../../src/storage/sweep";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, BASE_URL } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const KIND = process.env.ADAPTER_DB;
const URL_ = process.env.ADAPTER_URL ?? "";
// CI sets ADAPTER_REQUIRED: a job whose database variables went missing must fail, not skip
// every test and go green (review 4).
if (process.env.ADAPTER_REQUIRED && (!KIND || !URL_)) throw new Error("ADAPTER_REQUIRED is set, but ADAPTER_DB or ADAPTER_URL is empty");

interface Db {
  database: unknown;
  migrate: boolean;
  close(): Promise<void>;
  /** The fresh database's URL (Postgres), for clients that connect on their own (Prisma). */
  url?: string;
}

/** One small function per database: a fresh, empty database and Better Auth's `database` option. */
const databases: Record<string, (tenants?: boolean) => Promise<Db>> = {
  async postgres() {
    const { Pool } = await import("pg");
    const name = `saml_matrix_${Date.now().toString(36)}`;
    const admin = new Pool({ connectionString: URL_ });
    await admin.query(`CREATE DATABASE ${name}`);
    const url = new URL(URL_);
    url.pathname = `/${name}`;
    const pool = new Pool({ connectionString: url.toString(), max: 10 });
    // DROP DATABASE … WITH (FORCE) at teardown ends any leftover connections; pg reports that as an
    // "error" event on idle clients, which is expected here.
    pool.on("error", () => {});
    return {
      database: pool,
      migrate: true,
      url: url.toString(),
      async close() {
        await pool.end();
        await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
        await admin.end();
      },
    };
  },

  async mysql() {
    const mysql = await import("mysql2/promise");
    const name = `saml_matrix_${Date.now().toString(36)}`;
    const admin = await mysql.createConnection(URL_);
    await admin.query(`CREATE DATABASE ${name}`);
    const url = new URL(URL_);
    url.pathname = `/${name}`;
    const pool = mysql.createPool({ uri: url.toString(), connectionLimit: 10, timezone: "Z" });
    return {
      database: pool,
      migrate: true,
      async close() {
        await pool.end();
        await admin.query(`DROP DATABASE IF EXISTS ${name}`);
        await admin.end();
      },
    };
  },

  // The same servers, through Drizzle (the most common Better Auth adapter after Kysely).
  "drizzle-postgres": async (tenants) => withDrizzle(await databases.postgres!(), "pg", tenants),
  "drizzle-mysql": async (tenants) => withDrizzle(await databases.mysql!(), "mysql", tenants),
  "prisma-postgres": async (tenants) => withPrisma(await databases.postgres!(), tenants),

  async mongodb() {
    const { MongoClient } = await import("mongodb");
    const { mongodbAdapter } = await import("better-auth/adapters/mongodb");
    const client = new MongoClient(URL_);
    await client.connect();
    const database = client.db(`saml_matrix_${Date.now().toString(36)}`);
    return {
      // No migrations: the adapter creates collections and indexes (UNIQUE ones too) on first use.
      database: mongodbAdapter(database, { client }),
      migrate: false,
      async close() {
        await database.dropDatabase();
        await client.close();
      },
    };
  },
};

let db: Db;
let auth: Awaited<ReturnType<typeof build>>;

/** The options every entry runs with; `database` is the entry's. `tenants`: the multi-tenant schema (D-052). */
const optionsFor = (database: unknown, tenants = false) => ({
    baseURL: BASE_URL,
    secret: "test-secret-that-is-at-least-32-characters-long",
    telemetry: { enabled: false },
    database: database as any,
    emailAndPassword: { enabled: true },
    rateLimit: { enabled: false },
    plugins: [
      admin(),
      organization(),
      samlIdp(
        baseOptions({
          serviceProviders: [
            { id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], singleLogoutService: { url: "https://sp.test/slo" } },
            // Assertion exchange (D-071): its record goes through the verification table.
            { id: "x-sp", entityId: "https://x.test/sp", acsUrls: ["https://x.test/acs"], allowIdpInitiated: true, tokenExchange: { clientId: "agent" } },
          ],
          registry: { enabled: true, canManage: ({ user }) => user.role === "admin", cacheSeconds: 0 },
          singleLogout: { enabled: true },
          auditLog: { enabled: true },
          // Per-tenant keys (D-058): their table and its UNIQUE state key are in the schema too.
          ...(tenants ? { tenants: { enabled: true, keys: "per-tenant" as const, cacheSeconds: 0, minPublishedSeconds: 0 } } : {}),
        }),
      ),
    ],
  });

/**
 * A Drizzle entry: the tables are created by Better Auth's own migrator on a raw connection (as a
 * host running `npx auth migrate` would), then the plugin runs through drizzleAdapter with a
 * schema built from the same table definitions (orm-schemas.ts).
 */
async function withDrizzle(raw: Db, provider: "pg" | "mysql", tenants = false): Promise<Db> {
  const { getMigrations } = await import("better-auth/db/migration");
  await (await getMigrations(optionsFor(raw.database, tenants) as any)).runMigrations();
  const { drizzleAdapter } = await import("better-auth/adapters/drizzle");
  const schemas = await import("./orm-schemas");
  const drizzleDb =
    provider === "pg"
      ? (await import("drizzle-orm/node-postgres")).drizzle(raw.database as any)
      : (await import("drizzle-orm/mysql2")).drizzle(raw.database as any);
  const schema = provider === "pg" ? await schemas.drizzlePgSchema(optionsFor(null, tenants) as any) : await schemas.drizzleMysqlSchema(optionsFor(null, tenants) as any);
  return { database: drizzleAdapter(drizzleDb as any, { provider, schema: schema as any }), migrate: false, close: raw.close };
}

/**
 * A Prisma entry: tables from Better Auth's migrator, then a Prisma client generated from a schema
 * built from the same table definitions (`prisma generate` into a temporary directory).
 */
async function withPrisma(raw: Db, tenants = false): Promise<Db> {
  const { getMigrations } = await import("better-auth/db/migration");
  await (await getMigrations(optionsFor(raw.database, tenants) as any)).runMigrations();
  const { mkdirSync, mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { execFileSync } = await import("node:child_process");
  const { pathToFileURL } = await import("node:url");
  // Inside the project, so the generated client resolves the installed @prisma/client.
  const cache = join(process.cwd(), "node_modules/.cache");
  mkdirSync(cache, { recursive: true });
  const dir = mkdtempSync(join(cache, "saml-prisma-"));
  const { prismaSchema } = await import("./orm-schemas");
  writeFileSync(join(dir, "schema.prisma"), prismaSchema(optionsFor(null, tenants) as any, join(dir, "client")));
  execFileSync(join(process.cwd(), "node_modules/.bin/prisma"), ["generate", "--schema", join(dir, "schema.prisma")], { stdio: "pipe" });
  // The prisma-client generator writes TypeScript (client.ts), which Vitest loads directly.
  const { PrismaClient } = (await import(pathToFileURL(join(dir, "client/client.ts")).href)) as any;
  // Prisma 7 connects through a driver adapter, not a URL in the schema.
  const { PrismaPg } = await import("@prisma/adapter-pg");
  const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: raw.url }) });
  const { prismaAdapter } = await import("better-auth/adapters/prisma");
  return {
    database: prismaAdapter(prisma, { provider: "postgresql" }),
    migrate: false,
    async close() {
      await prisma.$disconnect();
      await raw.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function build(from: Db = db, tenants = false) {
  const a = betterAuth(optionsFor(from.database, tenants));
  if (from.migrate) {
    const { getMigrations } = await import("better-auth/db/migration");
    await (await getMigrations((await a.$context).options)).runMigrations();
  }
  return a;
}

const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const ctx = async () => (await auth.$context) as any;

describe.skipIf(!KIND)(`adapter matrix: ${KIND}`, { timeout: 60_000 }, () => {
  beforeAll(async () => {
    const make = databases[KIND as string];
    if (!make) throw new Error(`unknown ADAPTER_DB ${KIND}; known: ${Object.keys(databases).join(", ")}`);
    db = await make();
    auth = await build();
  });
  afterAll(async () => {
    await db?.close();
  });

  it("the seen-request UNIQUE key is enforced by the database itself, even on the very first inserts (MongoDB creates indexes lazily)", async () => {
    const c = await ctx();
    const expires = new Date(Date.now() + 60_000);
    const first = await Promise.all(Array.from({ length: 8 }, () => recordRequestId(c.adapter, "sp-x", "_same", expires)));
    expect(first.filter(Boolean)).toHaveLength(1);
  });

  it("a full sign-in: request parked, resumed once, Response issued", async () => {
    const browser = new Browser(auth);
    const toLogin = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(toLogin.status).toBe(302);
    const resume = new URL(toLogin.headers.get("location")!).searchParams.get("callbackURL")!;
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(resume));
    expect(form.xml).toContain("status:Success");
    expect(await code(await browser.fetch(resume))).toBe("PENDING_REQUEST_NOT_FOUND"); // single use
  });

  it("assertion exchange (D-071): recorded at sign-in, and of 10 concurrent exchanges exactly one is accepted", async () => {
    const browser = new Browser(auth);
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=x-sp`));
    const assertion = /<saml:Assertion [\s\S]*<\/saml:Assertion>/.exec(form.xml)![0].replace("<saml:Assertion ", '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ');
    const c = await ctx();
    const exchange = getSamlIdpExchange({ context: c })!;
    const codes = await Promise.all(
      Array.from({ length: 10 }, () =>
        exchange.verifyIssuedAssertion({ context: c } as any, assertion, { clientId: "agent" }).then(
          () => "OK",
          (e) => (e instanceof AssertionExchangeError ? e.code : String(e)),
        ),
      ),
    );
    expect(codes.filter((x) => x === "OK")).toHaveLength(1);
    expect(codes.filter((x) => x === "ALREADY_EXCHANGED")).toHaveLength(9);
  });

  it("replay protection holds under concurrency: 10 identical requests, exactly one accepted", async () => {
    const browser = new Browser(auth);
    const url = await redirectUrl(authnRequestXml().xml);
    const results = await Promise.all(Array.from({ length: 10 }, () => browser.fetch(url)));
    expect(results.filter((r) => r.status === 302)).toHaveLength(1);
    expect((await Promise.all(results.filter((r) => r.status !== 302).map(code))).every((c) => c === "DUPLICATE_REQUEST_ID")).toBe(true);
  });

  it("a resume link is consumed once, even when used concurrently", async () => {
    const browser = new Browser(auth);
    const toLogin = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    const resume = new URL(toLogin.headers.get("location")!).searchParams.get("callbackURL")!;
    await browser.signUp();
    const results = await Promise.all(Array.from({ length: 6 }, () => browser.fetch(resume)));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
  });

  it("registry: concurrent creates of one SP, exactly one wins; booleans and dates round-trip; lookups are exact", async () => {
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const c = await ctx();
    await c.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin" } });
    const sp = { id: "stored", entityId: "https://Stored.test/sp", acsUrls: ["https://stored.test/acs"] };
    const post = (path: string, body: unknown) =>
      browser.fetch(`${AUTH_BASE}/saml-idp/service-providers${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const results = await Promise.all(Array.from({ length: 5 }, () => post("/create", { serviceProvider: sp, enabled: false })));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 409)).toHaveLength(4);
    const got = (await (await browser.fetch(`${AUTH_BASE}/saml-idp/service-providers/get?id=stored`)).json()) as any;
    expect(got.serviceProvider).toMatchObject({ enabled: false, valid: true });
    expect(Number.isNaN(new Date(got.serviceProvider.createdAt).getTime())).toBe(false);
    await post("/update", { id: "stored", serviceProvider: sp, enabled: true });
    const ok = await browser.fetch(await redirectUrl(authnRequestXml({ issuer: sp.entityId, acsUrl: sp.acsUrls[0] }).xml));
    expect(ok.status).toBe(200);
    // Exact match only, whatever the database's collation does with case.
    const other = await browser.fetch(await redirectUrl(authnRequestXml({ issuer: "https://stored.test/sp", acsUrl: sp.acsUrls[0] }).xml));
    expect(await code(other)).toBe("UNKNOWN_SERVICE_PROVIDER");
  });

  it("registry update/delete act only on the exact id, whatever the collation (MySQL's is case-insensitive; R4-L8)", async () => {
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const c = await ctx();
    await c.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin" } });
    const post = (path: string, body: unknown) =>
      browser.fetch(`${AUTH_BASE}/saml-idp/service-providers${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const sp = { id: "casey", entityId: "https://casey.test/sp", acsUrls: ["https://casey.test/acs"] };
    expect((await post("/create", { serviceProvider: sp })).status).toBe(200);
    expect((await post("/update", { id: "CASEY", serviceProvider: { ...sp, id: "CASEY" } })).status).toBe(404);
    expect((await post("/delete", { id: "CASEY" })).status).toBe(404);
    const got = (await (await browser.fetch(`${AUTH_BASE}/saml-idp/service-providers/get?id=casey`)).json()) as any;
    expect(got.serviceProvider).toMatchObject({ id: "casey", valid: true });
  });

  it("logout participants: recorded, refreshed on a second assertion, listed, and cleared by logout", async () => {
    const browser = new Browser(auth);
    await browser.signUp();
    await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml))); // second assertion: the upsert path
    const c = await ctx();
    const session = (await (await browser.fetch(`${AUTH_BASE}/get-session`)).json()) as any;
    const listed = await listParticipants(c.adapter, session.session.id);
    expect(listed.participants.map((p) => p.spId)).toEqual(["test-sp"]);
    const res = await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=/`);
    expect(res.status).toBe(302);
    expect((await listParticipants(c.adapter, session.session.id)).participants).toEqual([]);
  });

  it("organization memberships load through the adapter's `in` operator", async () => {
    const { loadMemberships } = await import("../../src/organizations");
    const c = await ctx();
    const user = await new Browser(auth).signUp();
    const a = await c.adapter.create({ model: "organization", data: { name: "A", slug: `a-${Date.now()}`, createdAt: new Date() } });
    const b = await c.adapter.create({ model: "organization", data: { name: "B", slug: `b-${Date.now()}`, createdAt: new Date() } });
    for (const [o, role] of [
      [a, "admin,member"],
      [b, "owner"],
    ] as const)
      await c.adapter.create({ model: "member", data: { organizationId: o.id, userId: user.id, role, createdAt: new Date() } });
    const m = await loadMemberships(c.adapter, user.id);
    expect(m.map((x) => [x.name, x.roles]).sort()).toEqual([
      ["A", ["admin", "member"]],
      ["B", ["owner"]],
    ]);
  });

  it("audit log: events are written with dates and nullable columns intact", async () => {
    const browser = new Browser(auth);
    const user = await browser.signUp();
    await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    const c = await ctx();
    const find = async () => (await c.adapter.findMany({ model: "samlIdpAuditEvent", where: [{ field: "userId", value: user.id }] })) as Record<string, any>[];
    await vi.waitFor(async () => expect((await find()).map((r) => r.type)).toContain("assertion.issued"));
    const row = (await find()).find((r) => r.type === "assertion.issued")!;
    expect(row).toMatchObject({ spId: "test-sp", code: null });
    expect(new Date(row.expiresAt).getTime()).toBeGreaterThan(new Date(row.at).getTime());
    expect(JSON.parse(row.details)).toMatchObject({ initiatedBy: "sp", attributes: expect.any(Array) });
  });

  it("the expiry sweep deletes expired rows (lt) and keeps live ones", async () => {
    const c = await ctx();
    await recordRequestId(c.adapter, "sp-sweep", "_old", new Date(Date.now() - 1000));
    await recordRequestId(c.adapter, "sp-sweep", "_new", new Date(Date.now() + 60_000));
    resetSweepThrottle();
    await sweepExpired(c.adapter, (what, e) => {
      throw new Error(`${what}: ${e}`);
    }, Date.now(), { participants: true });
    const rows = (await c.adapter.findMany({ model: "samlIdpSeenRequest", where: [{ field: "spId", value: "sp-sweep" }] })) as { requestId: string }[];
    expect(rows.map((r) => r.requestId)).toEqual(["_new"]);
  });
});

// Multi-tenant IdP (D-052), on a second fresh database with the tenant schema: entity IDs are unique
// per tenant through the lookupKey UNIQUE index (on MongoDB, the table-level `indexes` entry).
describe.skipIf(!KIND)(`adapter matrix: ${KIND}, tenants`, { timeout: 60_000 }, () => {
  let tdb: Db;
  let tauth: Awaited<ReturnType<typeof build>>;
  beforeAll(async () => {
    tdb = await (databases[KIND as string] as (tenants?: boolean) => Promise<Db>)(true);
    tauth = await build(tdb, true);
  });
  afterAll(async () => {
    await tdb?.close();
  });

  it("one entity ID in two tenants; within one tenant the database's UNIQUE lookup key lets exactly one of concurrent creates win; each tenant's URL finds its own", async () => {
    const c = (await tauth.$context) as any;
    const admin = new Browser(tauth);
    const adminUser = await admin.signUp();
    await c.adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
    const post = (path: string, body: unknown) =>
      admin.fetch(`${AUTH_BASE}/saml-idp${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const user = new Browser(tauth);
    const u = await user.signUp();
    const orgs: string[] = [];
    for (const name of ["ta", "tb"]) {
      const o = await c.adapter.create({ model: "organization", data: { name, slug: `${name}-${Date.now()}`, createdAt: new Date() } });
      await c.adapter.create({ model: "member", data: { organizationId: o.id, userId: u.id, role: "member", createdAt: new Date() } });
      expect((await post("/tenants/create", { organizationId: o.id })).status).toBe(200);
      orgs.push(String(o.id));
    }
    const shared = { entityId: "urn:amazon:webservices", acsUrls: ["https://signin.aws.amazon.com/saml"] };
    const racing = await Promise.all(Array.from({ length: 5 }, (_, i) => post("/service-providers/create", { serviceProvider: { id: `aws-a${i}`, ...shared, tenant: orgs[0] } })));
    expect(racing.filter((r) => r.status === 200)).toHaveLength(1);
    expect(racing.filter((r) => r.status === 409)).toHaveLength(4);
    expect((await post("/service-providers/create", { serviceProvider: { id: "aws-b", ...shared, tenant: orgs[1] } })).status).toBe(200);
    for (const org of orgs) {
      const sso = `${AUTH_BASE}/saml2/idp/sso/${org}`;
      const url = (await redirectUrl(authnRequestXml({ issuer: shared.entityId, acsUrl: shared.acsUrls[0], destination: sso }).xml)).replace(`${AUTH_BASE}/saml2/idp/sso`, sso);
      const { xml } = await readAutoPost(await user.fetch(url));
      expect(/<saml:Issuer>([^<]+)</.exec(xml)?.[1]).toBe(`${AUTH_BASE}/saml2/idp/metadata/${org}`);
    }
    // Tenant rows: booleans round-trip, and a disabled tenant is gone from its URLs.
    expect((await post("/tenants/update", { organizationId: orgs[1], enabled: false })).status).toBe(200);
    expect((await tauth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata/${orgs[1]}`))).status).toBe(404);
    expect((await tauth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata/${orgs[0]}`))).status).toBe(200);
    // Signing in above also checked each tenant's organization binding (its createdAt, D-053)
    // after a round trip through this database. A deleted tenant's key is retired (D-053).
    const tc = await c.adapter.create({ model: "organization", data: { name: "tc", slug: `tc-${Date.now()}`, createdAt: new Date() } });
    const td = await c.adapter.create({ model: "organization", data: { name: "td", slug: `td-${Date.now()}`, createdAt: new Date() } });
    expect((await post("/tenants/create", { organizationId: tc.id, tenantKey: "retired-key" })).status).toBe(200);
    expect((await post("/tenants/delete", { organizationId: tc.id })).status).toBe(200);
    const again = await post("/tenants/create", { organizationId: td.id, tenantKey: "retired-key" });
    expect(again.status).toBe(409);
    expect(((await again.json()) as { code?: string }).code).toBe("TENANT_KEY_RETIRED");
  });

  it("per-tenant keys (D-058): the database's UNIQUE state key lets exactly one of concurrent rotations win; the activated key signs, sealed in the row", async () => {
    const c = (await tauth.$context) as any;
    const admin = new Browser(tauth);
    const adminUser = await admin.signUp();
    await c.adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
    const post = (path: string, body: unknown) =>
      admin.fetch(`${AUTH_BASE}/saml-idp${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const user = new Browser(tauth);
    const u = await user.signUp();
    const o = await c.adapter.create({ model: "organization", data: { name: "tk", slug: `tk-${Date.now()}`, createdAt: new Date() } });
    const org = String(o.id);
    await c.adapter.create({ model: "member", data: { organizationId: org, userId: u.id, role: "member", createdAt: new Date() } });
    const created = (await (await post("/tenants/create", { organizationId: org })).json()) as any;
    expect(created.tenant.signing).toBe("own");
    const sp = { entityId: `https://keys-${Date.now()}.test/sp`, acsUrls: ["https://keys.test/acs"] };
    expect((await post("/service-providers/create", { serviceProvider: { id: `keys-sp-${Date.now()}`, ...sp, tenant: org } })).status).toBe(200);

    const racing = await Promise.all(Array.from({ length: 5 }, () => post("/tenants/keys/rotate", { organizationId: org })));
    expect(racing.filter((r) => r.status === 200)).toHaveLength(1);
    expect(racing.filter((r) => r.status === 409)).toHaveLength(4);
    const rows = (await c.adapter.findMany({ model: "samlIdpTenantKey", where: [{ field: "tenantId", value: org }] })) as any[];
    expect(rows.map((r) => r.state).sort()).toEqual(["active", "next"]);
    for (const r of rows) expect(r.encryptedPrivateKey).not.toContain("PRIVATE KEY");

    const activated = (await (await post("/tenants/keys/activate", { organizationId: org })).json()) as any;
    const active = activated.tenant.keys.find((k: any) => k.state === "active");
    const sso = `${AUTH_BASE}/saml2/idp/sso/${org}`;
    const url = (await redirectUrl(authnRequestXml({ issuer: sp.entityId, acsUrl: sp.acsUrls[0], destination: sso }).xml)).replace(`${AUTH_BASE}/saml2/idp/sso`, sso);
    const { xml } = await readAutoPost(await user.fetch(url));
    const certInXml = /<(?:ds:)?X509Certificate>([^<]+)</.exec(xml)?.[1]?.replace(/\s+/g, "");
    expect(certInXml).toBe(active.certificate.replace(/-----[^-]+-----|\s+/g, ""));
    // Review 7: rows stay bounded over rotations (sorted reads, pruning), and the tenant list reads
    // its tenants' key rows with an `in` filter, on this database.
    for (let i = 0; i < 7; i++) {
      expect((await post("/tenants/keys/rotate", { organizationId: org })).status).toBe(200);
      expect((await post("/tenants/keys/activate", { organizationId: org })).status).toBe(200);
    }
    expect((await post("/tenants/keys/retire", { organizationId: org })).status).toBe(200);
    const after = (await c.adapter.findMany({ model: "samlIdpTenantKey", where: [{ field: "tenantId", value: org }], limit: 1000 })) as any[];
    expect(after.filter((r) => r.state === "retired").length).toBeLessThanOrEqual(5);
    expect(after.filter((r) => r.state === "active")).toHaveLength(1);
    const listed = (await (await admin.fetch(`${AUTH_BASE}/saml-idp/tenants`)).json()) as any;
    expect(listed.tenants.find((t: any) => t.organizationId === org)).toMatchObject({ signing: "own" });
  });
});

// MongoDB only (review 6 R6-4, D-053): upgrading a registry that already has SPs. The adapter
// builds the UNIQUE lookupKey index before a write, which fails while two documents lack the key;
// backfillMongoServiceProviderKeys writes the keys through the driver, before tenants are on.
describe.skipIf(KIND !== "mongodb")("adapter matrix: mongodb, upgrading a populated registry to tenants", { timeout: 60_000 }, () => {
  it("two stored SPs: the MongoDB backfill keys them; with tenants on they sign in and the registry saves", async () => {
    const { MongoClient } = await import("mongodb");
    const { mongodbAdapter } = await import("better-auth/adapters/mongodb");
    const { backfillMongoServiceProviderKeys } = await import("../../src");
    const client = new MongoClient(URL_);
    await client.connect();
    const database = client.db(`saml_matrix_${Date.now().toString(36)}_up`);
    try {
      const before = betterAuth(optionsFor(mongodbAdapter(database, { client }), false));
      const admin = new Browser(before);
      const adminUser = await admin.signUp();
      await ((await before.$context) as any).adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
      for (const i of [1, 2]) {
        const res = await admin.fetch(`${AUTH_BASE}/saml-idp/service-providers/create`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ serviceProvider: { id: `old${i}`, entityId: `https://old${i}.test/sp`, acsUrls: [SP_ACS] } }),
        });
        expect(res.status).toBe(200);
      }
      expect(await backfillMongoServiceProviderKeys(database)).toEqual({ updated: 2, skipped: [], failed: [] });
      const after = betterAuth(optionsFor(mongodbAdapter(database, { client }), true));
      expect(await (after.api as any).samlIdpBackfillServiceProviderKeys()).toEqual({ updated: 0, skipped: [], failed: [] });
      const user = new Browser(after);
      await user.signUp();
      const { xml } = await readAutoPost(await user.fetch(await redirectUrl(authnRequestXml({ issuer: "https://old2.test/sp", acsUrl: SP_ACS }).xml)));
      expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:status:Success");
      const adminAfter = new Browser(after);
      const adminAfterUser = await adminAfter.signUp();
      await ((await after.$context) as any).adapter.update({ model: "user", where: [{ field: "id", value: adminAfterUser.id }], update: { role: "admin" } });
      const res = await adminAfter.fetch(`${AUTH_BASE}/saml-idp/service-providers/create`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ serviceProvider: { id: "new1", entityId: "https://new1.test/sp", acsUrls: [SP_ACS] } }),
      });
      expect(res.status).toBe(200);
    } finally {
      await database.dropDatabase().catch(() => {});
      await client.close();
    }
  });
});

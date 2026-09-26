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
import { samlIdp } from "../../src";
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
}

/** One small function per database: a fresh, empty database and Better Auth's `database` option. */
const databases: Record<string, () => Promise<Db>> = {
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

async function build() {
  const a = betterAuth({
    baseURL: BASE_URL,
    secret: "test-secret-that-is-at-least-32-characters-long",
    telemetry: { enabled: false },
    database: db.database as any,
    emailAndPassword: { enabled: true },
    rateLimit: { enabled: false },
    plugins: [
      admin(),
      organization(),
      samlIdp(
        baseOptions({
          serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], singleLogoutService: { url: "https://sp.test/slo" } }],
          registry: { enabled: true, canManage: ({ user }) => user.role === "admin", cacheSeconds: 0 },
          singleLogout: { enabled: true },
          auditLog: { enabled: true },
        }),
      ),
    ],
  });
  if (db.migrate) {
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

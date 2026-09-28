// Passed at review time (not a finding); kept as a check of the guide's SQL upgrade steps, and
// still passing after D-053 (whose tenant table changes are part of what step 2 creates; the
// backfill result gained `failed`, review 6 I-1).
// Review 6 (D-052): the multi-tenant guide's upgrade of a populated registry, step by step, on
// Postgres and MySQL, followed by its "drop the old UNIQUE(entityId)" SQL. Kept as a check of the
// documented steps (it passes: see the report's "tried and rejected").
//   ADAPTER_DB=postgres ADAPTER_URL=postgres://postgres:test@localhost:55432/postgres npx vitest run --project node test/review6/r6-sql-upgrade.test.ts
//   ADAPTER_DB=mysql ADAPTER_URL=mysql://root:test@127.0.0.1:53306/mysql npx vitest run --project node test/review6/r6-sql-upgrade.test.ts
import { betterAuth } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { afterAll, describe, expect, it } from "vitest";
import { samlIdp } from "../../src";
import { baseOptions, SP_ACS } from "../support/config";
import { AUTH_BASE, BASE_URL } from "../support/host";
import { Browser, readAutoPost } from "../support/sp";
import { authn } from "./world";

const KIND = process.env.ADAPTER_DB;
const URL_ = process.env.ADAPTER_URL ?? "";

describe.skipIf(KIND !== "postgres" && KIND !== "mysql")("the guide's SQL upgrade path (Postgres, MySQL)", { timeout: 120_000 }, () => {
  const closers: (() => Promise<void>)[] = [];
  afterAll(async () => {
    for (const c of closers.reverse()) await c();
  });

  async function database() {
    const name = `saml_review6_${Date.now().toString(36)}`;
    if (KIND === "postgres") {
      const { Pool } = await import("pg");
      const root = new Pool({ connectionString: URL_ });
      await root.query(`CREATE DATABASE ${name}`);
      const url = new URL(URL_);
      url.pathname = `/${name}`;
      const pool = new Pool({ connectionString: url.toString() });
      pool.on("error", () => {});
      closers.push(async () => {
        await pool.end();
        await root.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
        await root.end();
      });
      return { db: pool as unknown, sql: async (q: string) => void (await pool.query(q)) };
    }
    const mysql = await import("mysql2/promise");
    const root = await mysql.createConnection(URL_);
    await root.query(`CREATE DATABASE ${name}`);
    const url = new URL(URL_);
    url.pathname = `/${name}`;
    const pool = mysql.createPool({ uri: url.toString(), timezone: "Z" });
    closers.push(async () => {
      await pool.end();
      await root.query(`DROP DATABASE IF EXISTS ${name}`);
      await root.end();
    });
    return { db: pool as unknown, sql: async (q: string) => void (await pool.query(q)) };
  }

  const options = (db: unknown, tenants: boolean, sps: any[] = []) => ({
    baseURL: BASE_URL,
    secret: "test-secret-that-is-at-least-32-characters-long",
    telemetry: { enabled: false },
    database: db as any,
    emailAndPassword: { enabled: true },
    rateLimit: { enabled: false },
    plugins: [
      admin(),
      organization(),
      samlIdp(
        baseOptions({
          serviceProviders: sps,
          registry: { enabled: true, canManage: ({ user }) => user.role === "admin", cacheSeconds: 0 },
          auditLog: { enabled: true },
          ...(tenants ? { tenants: { enabled: true, cacheSeconds: 0 } } : {}),
        }),
      ),
    ],
  });
  const migrate = async (o: any) => {
    const { getMigrations } = await import("better-auth/db/migration");
    await (await getMigrations(o)).runMigrations();
  };
  const post = (b: Browser, path: string, body: unknown) => b.fetch(`${AUTH_BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

  it("steps 1-4, then the SQL that drops UNIQUE(entityId): old SPs work, one entity ID fits in two tenants", async () => {
    const { db, sql } = await database();
    // Before tenants: two stored SPs.
    await migrate(options(db, false));
    const before = betterAuth(options(db, false));
    const adminB = new Browser(before);
    const adminUser = await adminB.signUp();
    await ((await before.$context) as any).adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
    for (const n of [1, 2]) expect((await post(adminB, "/saml-idp/service-providers/create", { serviceProvider: { id: `sp${n}`, entityId: `https://sp${n}.test/sp`, acsUrls: [SP_ACS] } })).status).toBe(200);

    // Step 1: the column, nullable, by hand.
    await sql(KIND === "postgres" ? `ALTER TABLE "samlIdpServiceProvider" ADD COLUMN "lookupKey" text` : "ALTER TABLE samlIdpServiceProvider ADD COLUMN lookupKey varchar(255) NULL");
    // Step 2: the migrator, with tenants on.
    await migrate(options(db, true));
    const after = betterAuth(options(db, true));
    // Step 3: the backfill.
    expect(await (after.api as any).samlIdpBackfillServiceProviderKeys()).toEqual({ updated: 2, skipped: [], failed: [] });
    // Step 4: NOT NULL.
    await sql(KIND === "postgres" ? `ALTER TABLE "samlIdpServiceProvider" ALTER COLUMN "lookupKey" SET NOT NULL` : "ALTER TABLE samlIdpServiceProvider MODIFY lookupKey varchar(255) NOT NULL");

    // Old SPs sign in as before.
    const user = new Browser(after);
    await user.signUp();
    const res = await user.fetch(await authn(`${AUTH_BASE}/saml2/idp/sso`, { issuer: "https://sp1.test/sp", acsUrl: SP_ACS }));
    expect(res.status).toBe(200);
    await readAutoPost(res);

    // Two tenants; the same entity ID in both is refused until the old constraint goes.
    const ctx = (await after.$context) as any;
    const orgA = await ctx.adapter.create({ model: "organization", data: { name: "A", slug: `a-${Date.now()}`, createdAt: new Date() } });
    const orgB = await ctx.adapter.create({ model: "organization", data: { name: "B", slug: `b-${Date.now()}`, createdAt: new Date() } });
    const adminA = new Browser(after);
    await adminA.signIn(adminUser.email);
    for (const o of [orgA, orgB]) expect((await post(adminA, "/saml-idp/tenants/create", { organizationId: o.id })).status).toBe(200);
    const shared = (id: string, tenant: string) => post(adminA, "/saml-idp/service-providers/create", { serviceProvider: { id, entityId: "urn:shared:sp", acsUrls: [SP_ACS], tenant } });
    expect((await shared("in-a", orgA.id)).status).toBe(200);
    expect((await shared("in-b", orgB.id)).status).toBe(409);
    if (KIND === "postgres") {
      await sql(`ALTER TABLE "samlIdpServiceProvider" DROP CONSTRAINT "samlIdpServiceProvider_entityId_key"`);
      await sql("DROP INDEX saml_idp_service_provider_entity_id_unique");
    } else {
      await sql("ALTER TABLE samlIdpServiceProvider DROP INDEX entityId, DROP INDEX saml_idp_service_provider_entity_id_unique");
    }
    expect((await shared("in-b", orgB.id)).status).toBe(200);
  });
});

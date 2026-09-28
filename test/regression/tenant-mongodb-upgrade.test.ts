// Fixed in D-053 (backfillMongoServiceProviderKeys; the endpoint reports rows it can't write);
// kept as a regression test, and the adapter matrix has the main suite's (MongoDB only).
// Comments saying "today" describe dac64f3.
// Review 6 (D-052): the documented upgrade of an existing registry, on MongoDB. The guide says
// "run step 3 [the backfill] before the UNIQUE index on lookupKey is created". But Better Auth's
// MongoDB adapter creates a model's declared indexes itself, on the first create/update of that
// model, before the write. The backfill's first update therefore builds the UNIQUE lookupKey index
// while two or more documents still lack the field (MongoDB indexes a missing field as null, so
// that is a duplicate key), the index build fails, and the update with it. Every later write of
// the model retries and fails the same way: the backfill can't complete, and the registry can't
// create or update SPs either, until someone fixes the collection by hand.
//
// Runs only against a MongoDB replica set, like the adapter matrix:
//   ADAPTER_DB=mongodb ADAPTER_URL='mongodb://127.0.0.1:27017/?replicaSet=rs0&directConnection=true' \
//     npx vitest run --project node test/regression/tenant-mongodb-upgrade.test.ts
import { betterAuth } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { afterAll, describe, expect, it } from "vitest";
import { backfillMongoServiceProviderKeys, samlIdp } from "../../src";
import { lookupKeyOf } from "../../src/saml/sp-directory";
import { baseOptions, SP_ACS } from "../support/config";
import { AUTH_BASE, BASE_URL } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const KIND = process.env.ADAPTER_DB;
const URL_ = process.env.ADAPTER_URL ?? "";

describe.skipIf(KIND !== "mongodb")("R6-4: the upgrade of a populated registry on MongoDB", () => {
  const closers: (() => Promise<void>)[] = [];
  afterAll(async () => {
    for (const c of closers.reverse()) await c();
  });

  async function host(tenants: boolean, dbName: string) {
    const { MongoClient } = await import("mongodb");
    const { mongodbAdapter } = await import("better-auth/adapters/mongodb");
    const client = new MongoClient(URL_);
    await client.connect();
    const database = client.db(dbName);
    closers.push(async () => {
      if (!tenants) await database.dropDatabase().catch(() => {});
      await client.close();
    });
    return {
      database,
      auth: betterAuth({
        baseURL: BASE_URL,
        secret: "test-secret-that-is-at-least-32-characters-long",
        telemetry: { enabled: false },
        database: mongodbAdapter(database, { client }),
        emailAndPassword: { enabled: true },
        rateLimit: { enabled: false },
        plugins: [
          admin(),
          organization(),
          samlIdp(
            baseOptions({
              serviceProviders: [],
              registry: { enabled: true, canManage: ({ user }) => user.role === "admin", cacheSeconds: 0 },
              ...(tenants ? { tenants: { enabled: true, cacheSeconds: 0 } } : {}),
            }),
          ),
        ],
      }),
    };
  }

  /** The registry without tenants, with two SPs saved through the API. */
  async function populated(dbName: string) {
    const before = await host(false, dbName);
    const adminBrowser = new Browser(before.auth);
    const adminUser = await adminBrowser.signUp();
    await ((await before.auth.$context) as any).adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
    for (const n of [1, 2]) {
      const res = await adminBrowser.fetch(`${AUTH_BASE}/saml-idp/service-providers/create`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ serviceProvider: { id: `sp${n}`, entityId: `https://sp${n}.test/sp`, acsUrls: [SP_ACS] } }),
      });
      expect(res.status).toBe(200);
    }
    return before;
  }

  /** After the upgrade: every document has the key lookups use, the index is built, SPs sign in and the registry saves. */
  async function upgraded(after: Awaited<ReturnType<typeof host>>) {
    const docs = await after.database.collection("samlIdpServiceProvider").find({}).toArray();
    for (const d of docs) expect(d.lookupKey).toBe(await lookupKeyOf("", d.entityId));
    const browser = new Browser(after.auth);
    await browser.signUp();
    const url = (await redirectUrl(authnRequestXml({ issuer: "https://sp1.test/sp", acsUrl: SP_ACS }).xml));
    expect((await readAutoPost(await browser.fetch(url))).xml).toContain("urn:oasis:names:tc:SAML:2.0:status:Success");
    const admin = new Browser(after.auth);
    const adminUser = await admin.signUp();
    await ((await after.auth.$context) as any).adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
    const res = await admin.fetch(`${AUTH_BASE}/saml-idp/service-providers/create`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ serviceProvider: { id: "sp3", entityId: "https://sp3.test/sp", acsUrls: [SP_ACS] } }),
    });
    expect(res.status, await res.clone().text()).toBe(200);
    const indexes = await after.database.collection("samlIdpServiceProvider").indexes();
    expect(indexes.find((i) => i.name === "saml_idp_service_provider_lookup_key_unique")?.unique).toBe(true);
  }

  it("the guide's order: backfillMongoServiceProviderKeys before tenants are turned on; then everything works", async () => {
    const dbName = `saml_upgrade_${Date.now().toString(36)}a`;
    const before = await populated(dbName);
    expect(await backfillMongoServiceProviderKeys(before.database)).toEqual({ updated: 2, skipped: [], failed: [] });
    expect(await backfillMongoServiceProviderKeys(before.database)).toEqual({ updated: 0, skipped: [], failed: [] }); // idempotent
    const after = await host(true, dbName);
    expect(await (after.auth.api as any).samlIdpBackfillServiceProviderKeys()).toEqual({ updated: 0, skipped: [], failed: [] });
    await upgraded(after);
  });

  it("tenants turned on first (the old order): the endpoint reports the rows it can't write instead of throwing; the MongoDB backfill then recovers", async () => {
    const dbName = `saml_upgrade_${Date.now().toString(36)}b`;
    await populated(dbName);
    const after = await host(true, dbName);
    // Today (dac64f3) this threw E11000 at the first row. It now names every row it couldn't key.
    const result = (await (after.auth.api as any).samlIdpBackfillServiceProviderKeys()) as { updated: number; failed: string[] };
    expect(result.updated).toBe(0);
    expect(result.failed.sort()).toEqual(["sp1", "sp2"]);
    expect(await backfillMongoServiceProviderKeys(after.database)).toEqual({ updated: 2, skipped: [], failed: [] });
    await upgraded(after);
  });
});

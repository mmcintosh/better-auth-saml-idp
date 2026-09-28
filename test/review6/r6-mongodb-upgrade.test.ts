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
//     npx vitest run --project node test/review6/r6-mongodb-upgrade.test.ts
import { betterAuth } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { afterAll, describe, expect, it } from "vitest";
import { samlIdp } from "../../src";
import { baseOptions, SP_ACS } from "../support/config";
import { AUTH_BASE, BASE_URL } from "../support/host";
import { Browser } from "../support/sp";

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

  it("two stored SPs from before tenants: the backfill should fill in both keys; today its first write fails on the UNIQUE index build", async () => {
    const dbName = `saml_review6_${Date.now().toString(36)}`;
    // Before: the registry without tenants, with two SPs saved through the API.
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

    // After: tenants on (MongoDB has no column to add, so the guide's step 3 is next).
    const after = await host(true, dbName);
    let result: { updated: number; skipped: string[] } | undefined;
    let error: unknown;
    try {
      result = (await (after.auth.api as any).samlIdpBackfillServiceProviderKeys()) as typeof result;
    } catch (e) {
      error = e;
    }
    expect(error, `the backfill threw: ${String((error as Error | undefined)?.message ?? "")}`).toBeUndefined();
    expect(result).toEqual({ updated: 2, skipped: [] });
    const docs = await after.database.collection("samlIdpServiceProvider").find({}).toArray();
    expect(docs.every((d) => typeof d.lookupKey === "string")).toBe(true);
  });
});

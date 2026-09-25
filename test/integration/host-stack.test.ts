// ADDENDUM-01: Phase 0 gate on the real host stack, R5 host config, R5 negative test.
import { betterAuth } from "better-auth";
import { withCloudflare } from "better-auth-cloudflare";
import { describe, expect, it } from "vitest";
import { samlIdp } from "../../src/index";
import { libxml2Validator } from "../../src/saml/validator";
import { baseOptions } from "../support/config";
import { AUTH_BASE, BASE_URL, createHost, createHostDatabase, isWorkerd, signUp } from "../support/host";

const pkgVersion = async (name: string) => {
  if (isWorkerd) return "(see node run)";
  const { createRequire } = await import("node:module");
  const { readFileSync } = await import("node:fs");
  const req = createRequire(import.meta.url);
  let dir = req.resolve(name);
  const { dirname, join } = await import("node:path");
  for (;;) {
    try {
      const p = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      if (p.name === name) return p.version as string;
    } catch {}
    const up = dirname(dir);
    if (up === dir) return "?";
    dir = up;
  }
};

describe(`host stack (${isWorkerd ? "workerd: withCloudflare + Drizzle/D1" : "node: withCloudflare + node:sqlite"})`, () => {
  it("reports the versions under test", async () => {
    const versions = {
      "better-auth": await pkgVersion("better-auth"),
      "@better-auth/core": await pkgVersion("@better-auth/core"),
      "better-auth-cloudflare": `${await pkgVersion("better-auth-cloudflare")} (main dbe08c51b)`,
      "drizzle-orm": await pkgVersion("drizzle-orm"),
    };
    console.log("VERSIONS", JSON.stringify(versions));
    if (!isWorkerd) expect(versions["better-auth"]).toMatch(/^1\.7\.\d+$/);
  });

  it("passes validateSchema with the plugin's table", async () => {
    const { auth } = await createHost();
    const ctx = await auth.$context;
    expect(ctx.options.advanced?.database?.validateSchema).toBe(true);
    if (ctx.checkSchema) await expect(ctx.checkSchema()).resolves.not.toThrow();
    else expect(isWorkerd).toBe(false); // Kysely/node:sqlite introspects; Drizzle must expose a check
  });

  it.runIf(isWorkerd)("validateSchema really catches a missing plugin table (the check is not vacuous)", async () => {
    const { env } = await import("cloudflare:test");
    const { drizzle } = await import("drizzle-orm/d1");
    const { schema } = await import("../support/d1/schema");
    const { samlIdpSeenRequests: _omitted, ...withoutPluginTable } = schema;
    const { auth } = await createHost({ database: { kind: "d1", db: drizzle(env.DB, { schema: withoutPluginTable }) } });
    const ctx = await auth.$context;
    await expect(ctx.checkSchema!()).rejects.toThrow(/samlIdpSeenRequest/);
  });

  it("uses the atomic storage configuration (verification + rate limit in the database)", async () => {
    const { auth } = await createHost();
    const ctx = await auth.$context;
    expect(ctx.options.verification?.storeInDatabase).toBe(true);
    expect(ctx.options.rateLimit).toMatchObject({ enabled: true, storage: "database" });
    expect((ctx.options as { secondaryStorage?: unknown }).secondaryStorage).toBeUndefined();
    expect(ctx.options.plugins?.map((p) => p.id)).toEqual(["cloudflare", "admin", "saml-idp"]);
  });

  it("signs up a user and records rate-limit state in the database", async () => {
    const { auth } = await createHost();
    const { cookie } = await signUp(auth);
    expect(cookie).toMatch(/better-auth\.session_token=/);
    const ctx = await auth.$context;
    const rows = await ctx.adapter.findMany({ model: "rateLimit" });
    expect(rows.length).toBeGreaterThan(0);
  });

  it("serves schema-valid metadata", async () => {
    const { auth } = await createHost();
    const res = await auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`));
    expect(res.status).toBe(200);
    expect(await libxml2Validator().validate(await res.text(), "metadata")).toEqual({ valid: true });
  });
});

describe("R5 negative host config: KV secondary storage without storeInDatabase", () => {
  it("fails loudly instead of silently taking the non-atomic path", async () => {
    const kv = {
      get: async () => null,
      put: async () => {},
      delete: async () => {},
    } as any;
    // A real database, so the only thing wrong is the storage routing.
    const database = await createHostDatabase();
    const run = async () => {
      const auth = betterAuth({
        baseURL: BASE_URL,
        secret: "test-secret-that-is-at-least-32-characters-long",
        telemetry: { enabled: false },
        ...withCloudflare(
          {
            autoDetectIpAddress: true,
            geolocationTracking: false,
            cf: {},
            kv,
            ...(database.kind === "d1" ? { d1: { db: database.db as any, options: { usePlural: true } } } : {}),
          },
          {
            ...(database.kind === "sqlite" ? { database: database.db as any } : {}),
            // no verification.storeInDatabase: consumes would go to KV
            rateLimit: { enabled: true, storage: "database" },
            plugins: [samlIdp(baseOptions())],
          },
        ),
      });
      await auth.$context;
      return auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`));
    };
    await expect(run()).rejects.toThrow(/storage is not atomic: verification requires a database or secondaryStorage\.getAndDelete/);
  });
});

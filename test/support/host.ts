// The test host required by ADDENDUM-01 R5:
//  - workerd: better-auth-cloudflare `withCloudflare` + Drizzle on D1, validateSchema on.
//  - node:    the same withCloudflare shape over node:sqlite (a real database, so unique
//             constraints and DELETE ... RETURNING behave as in production), schema created
//             by Better Auth's own migrator.
// In both: verification.storeInDatabase, rateLimit on with database storage, and the
// plugins passed INSIDE withCloudflare's second argument (R6).
import { betterAuth } from "better-auth";
import { admin } from "better-auth/plugins";
import { withCloudflare } from "better-auth-cloudflare";
import { samlIdp } from "../../src/index";
import type { SamlIdpOptions } from "../../src/types";
import { baseOptions } from "./config";

export const BASE_URL = "https://auth.test";
export const AUTH_BASE = `${BASE_URL}/api/auth`;

export const isWorkerd = typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";

export interface HostOptions {
  saml?: Partial<SamlIdpOptions>;
  /** Extra Better Auth options merged into withCloudflare's second argument. */
  auth?: Record<string, unknown>;
  /** Share one database between several auth instances (separate isolates in miniature). */
  database?: HostDatabase;
}

export type HostDatabase = { kind: "d1"; db: unknown } | { kind: "sqlite"; db: unknown };

/** One database per test file on workerd (isolated D1); a fresh node:sqlite on Node. */
export async function createHostDatabase(): Promise<HostDatabase> {
  if (isWorkerd) {
    const { env } = await import("cloudflare:test");
    const { drizzle } = await import("drizzle-orm/d1");
    const { schema } = await import("./d1/schema");
    return { kind: "d1", db: drizzle(env.DB, { schema }) };
  }
  const { DatabaseSync } = await import("node:sqlite");
  return { kind: "sqlite", db: new DatabaseSync(":memory:") };
}

export async function createHost(options: HostOptions = {}) {
  const database = options.database ?? (await createHostDatabase());
  const auth = betterAuth(hostOptions(database, options));
  if (database.kind === "sqlite") {
    // Node: Better Auth's own migrator creates the default (camelCase) schema, plugins
    // included, once per database even when several hosts share it.
    let done = migrated.get(database.db as object);
    if (!done) {
      done = (async () => {
        const { getMigrations } = await import("better-auth/db/migration");
        await (await getMigrations((await auth.$context).options)).runMigrations();
      })();
      migrated.set(database.db as object, done);
    }
    await done;
  }
  return { auth, database };
}

const migrated = new WeakMap<object, Promise<void>>();

export function hostOptions(database: HostDatabase, options: HostOptions = {}) {
  return {
    baseURL: BASE_URL,
    secret: "test-secret-that-is-at-least-32-characters-long",
    telemetry: { enabled: false },
    ...withCloudflare(
      {
        autoDetectIpAddress: true,
        geolocationTracking: true,
        cf: {},
        ...(database.kind === "d1" ? { d1: { db: database.db as any, options: { usePlural: true } } } : {}),
      },
      {
        ...(database.kind === "sqlite" ? { database: database.db as any } : {}),
        emailAndPassword: { enabled: true },
        verification: { storeInDatabase: true },
        rateLimit: { enabled: true, storage: "database" },
        advanced: { database: { validateSchema: true } },
        ...options.auth,
        plugins: [admin(), samlIdp(baseOptions(options.saml))],
      },
    ),
  };
}


/** Sign up a user and return the session cookie header for follow-up requests. */
export async function signUp(auth: { handler(r: Request): Promise<Response> }, email = "alice@example.com") {
  const res = await auth.handler(
    new Request(`${AUTH_BASE}/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE_URL },
      body: JSON.stringify({ email, password: "correct-horse-battery", name: "Alice Example" }),
    }),
  );
  if (res.status !== 200) throw new Error(`sign-up failed: ${res.status} ${await res.text()}`);
  const cookie = res.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const body = (await res.json()) as { user: { id: string } };
  return { cookie, userId: body.user.id };
}

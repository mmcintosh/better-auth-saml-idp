// Second review 4 report, R4-5: issuance reads the session with `getSessionFromCtx`, which serves Better Auth's cookie cache,
// and re-reads the session row only when sessions live in the database (issue.ts eligiblePrincipal).
// With `secondaryStorage` holding sessions (the KV setup on Workers) and the cookie cache on, a
// session revoked everywhere on the server keeps getting assertions until the cookie cache expires
// (`cookieCache.maxAge`, 5 minutes by default). The docs tell hosts not to configure this; the
// plugin has a cheaper answer since Better Auth 1.7.5 exports `getAuthoritativeSessionFromCtx`
// (what `sensitiveSessionMiddleware` uses), which bypasses the cookie cache on stateful hosts.
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { describe, expect, it } from "vitest";
import { samlIdp } from "../../src/index";
import { baseOptions } from "../support/config";
import { isWorkerd } from "../support/host";
import { authnRequestXml, Browser, redirectUrl } from "../support/sp";

describe.skipIf(isWorkerd)("R4-5: a revoked session served from the cookie cache", () => {
  it("gets no assertion once every session of the user has been revoked", async () => {
    const kv = new Map<string, string>();
    const auth = betterAuth({
      baseURL: "https://auth.test",
      secret: "test-secret-that-is-at-least-32-characters-long",
      database: memoryAdapter({ user: [], session: [], account: [], verification: [], samlIdpSeenRequest: [] }),
      emailAndPassword: { enabled: true },
      telemetry: { enabled: false },
      secondaryStorage: {
        get: async (k) => kv.get(k) ?? null,
        set: async (k, v) => void kv.set(k, v),
        delete: async (k) => void kv.delete(k),
        increment: async (k) => {
          const n = Number(kv.get(k) ?? 0) + 1;
          kv.set(k, String(n));
          return n;
        },
        getAndDelete: async (k) => {
          const v = kv.get(k) ?? null;
          kv.delete(k);
          return v;
        },
      },
      session: { cookieCache: { enabled: true, maxAge: 300 } },
      plugins: [samlIdp(baseOptions())],
    });
    const browser = new Browser(auth as any);
    const user = await browser.signUp();
    expect((await browser.fetch(await redirectUrl(authnRequestXml().xml))).status).toBe(200); // sanity: an assertion

    // The admin revokes every session of the user (compromised account).
    const ctx = await auth.$context;
    await ctx.internalAdapter.deleteUserSessions(user.id);
    expect([...kv.keys()].filter((k) => !k.startsWith("active-sessions-"))).toEqual([]); // nothing left server-side

    // The browser still holds the session token and the signed cookie cache.
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).not.toBe(200); // today: 200, a signed assertion for a revoked session
  });
});

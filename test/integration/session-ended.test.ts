// D-043: a session that ends without Single Logout (admin revoke, disable, /sign-out, expiry)
// reports the SPs that weren't told, keeps them findable, and never blocks the delete.
import { describe, expect, it, vi } from "vitest";
import type { SamlIdpEvent, SessionEndedEvent } from "../../src/events";
import { AUDIT_MODEL } from "../../src/events";
import { libxml2Validator } from "../../src/saml/validator";
import { PARTICIPANT_MODEL } from "../../src/storage/participants";
import { resolveOptions, resolveStoredServiceProvider } from "../../src/options";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, BASE_URL, createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const SP = { id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] as [string], singleLogoutService: { url: "https://sp.test/slo" } };
const SP2 = { id: "other-sp", entityId: "https://other.test/sp", acsUrls: ["https://other.test/acs"] as [string] };

async function host(saml: Record<string, unknown> = {}, auth: Record<string, unknown> = {}) {
  const events: SamlIdpEvent[] = [];
  const logs: string[] = [];
  const record = (e: SamlIdpEvent) => void events.push(e);
  const { auth: a } = await createHost({
    saml: {
      singleLogout: { enabled: true },
      serviceProviders: [SP, SP2],
      auditLog: { enabled: true },
      events: { onAssertionIssued: record, onLogout: record, onSessionEnded: record },
      ...saml,
    },
    auth: { logger: { level: "warn", log: (_l: string, m: string) => logs.push(m) }, ...auth },
  });
  const ctx = await a.$context;
  return { auth: a, ctx, events, logs };
}
const ended = (events: SamlIdpEvent[]) => events.filter((e): e is SessionEndedEvent => e.type === "session.ended");
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

/** Sign up and get assertions for both SPs; returns the browser, user and session id. */
async function signedInToBoth(auth: any) {
  const browser = new Browser(auth);
  const user = await browser.signUp();
  await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
  await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ issuer: SP2.entityId, acsUrl: SP2.acsUrls[0] }).xml)));
  const session = (await (await browser.fetch(`${AUTH_BASE}/get-session`)).json()) as { session: { id: string; token: string } };
  return { browser, user, session: session.session };
}

describe("session.ended (D-043)", () => {
  it("an out-of-band delete (outside any endpoint, as an admin page does) reports both SPs, and no new assertion is issued", async () => {
    const { auth, ctx, events } = await host();
    const { browser, user, session } = await signedInToBoth(auth);
    await vi.waitFor(() => expect(events.filter((e) => e.type === "assertion.issued")).toHaveLength(2));
    const issued = new Map(events.flatMap((e) => (e.type === "assertion.issued" ? [[e.spId, e]] : [])));

    await ctx.internalAdapter.deleteUserSessions(user.id); // no request, no endpoint context
    await vi.waitFor(() => expect(ended(events)).toHaveLength(1));
    const e = ended(events)[0]!;
    expect(e).toMatchObject({ userId: user.id, sessionId: session.id, reason: "revoked" });
    expect(e.ipAddress).toBeUndefined(); // there was no request
    expect(e.participants.map((p) => p.spId).sort()).toEqual(["other-sp", "test-sp"]);
    for (const p of e.participants) {
      expect(p.nameId).toBe(issued.get(p.spId)!.nameId);
      expect(p.entityId).toBe(p.spId === "test-sp" ? SP_ENTITY_ID : SP2.entityId);
      expect(p.sessionIndex).toMatch(/^_/);
    }
    // The old cookie gets no assertion (sign-in is required again).
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toMatch(/sign-in/);
  });

  it("the ended rows are kept, ignored by Single Logout, and listed per user (and only for that user)", async () => {
    const { auth, ctx } = await host();
    const a = await signedInToBoth(auth);
    const b = await signedInToBoth(auth);
    await ctx.internalAdapter.deleteUserSessions(a.user.id);
    await vi.waitFor(async () => {
      const rows = (await ctx.adapter.findMany({ model: PARTICIPANT_MODEL, where: [{ field: "userId", value: a.user.id }] })) as any[];
      expect(rows).toHaveLength(2);
      for (const r of rows) expect(r.endedAt).toBeTruthy();
    });
    const listA = await (auth.api as any).samlIdpListSessionParticipants({ body: { userId: a.user.id } });
    expect(listA.truncated).toBe(false);
    expect(listA.participants.map((p: any) => [p.spId, p.endedAt !== null]).sort()).toEqual([
      ["other-sp", true],
      ["test-sp", true],
    ]);
    const listB = await (auth.api as any).samlIdpListSessionParticipants({ body: { userId: b.user.id } });
    expect(listB.participants.every((p: any) => p.endedAt === null && p.nameId === b.user.email)).toBe(true);
    expect(listB.participants.map((p: any) => p.nameId)).not.toContain(a.user.email);
  });

  it("Single Logout skips rows marked ended", async () => {
    const { auth, ctx } = await host();
    const { user, session } = await signedInToBoth(auth);
    const { listParticipants } = await import("../../src/storage/participants");
    expect((await listParticipants(ctx.adapter as any, session.id)).participants).toHaveLength(2);
    await ctx.adapter.updateMany({ model: PARTICIPANT_MODEL, where: [{ field: "userId", value: user.id }], update: { endedAt: new Date() } });
    expect((await listParticipants(ctx.adapter as any, session.id)).participants).toEqual([]);
  });

  it("the listing is server-only: no URL reaches it", async () => {
    const { auth } = await host();
    const { browser } = await signedInToBoth(auth);
    for (const path of ["/list-session-participants", "/saml-idp/list-session-participants", "/samlIdpListSessionParticipants"]) {
      const res = await browser.fetch(`${AUTH_BASE}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: BASE_URL }, body: "{}" });
      expect(res.status).toBe(404);
    }
    expect((auth.api as any).samlIdpListSessionParticipants.path).toBeUndefined();
  });

  it("our own Single Logout doesn't also report session.ended (it tells the SPs itself)", async () => {
    const { auth, events } = await host();
    const { browser } = await signedInToBoth(auth);
    await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=/`);
    await vi.waitFor(() => expect(events.filter((e) => e.type === "logout")).toHaveLength(1));
    await new Promise((r) => setTimeout(r, 50));
    expect(ended(events)).toEqual([]);
  });

  it("a logout whose session delete fails doesn't hide a later revoke of that session (pre-release review L-1)", async () => {
    const { auth, ctx, events } = await host();
    const { browser, user } = await signedInToBoth(auth);
    const deleteSession = ctx.internalAdapter.deleteSession.bind(ctx.internalAdapter);
    ctx.internalAdapter.deleteSession = (async () => {
      throw new Error("database unavailable");
    }) as any;
    try {
      const res = await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=/`);
      expect(res.status).toBeGreaterThanOrEqual(500);
    } finally {
      ctx.internalAdapter.deleteSession = deleteSession;
    }
    await ctx.internalAdapter.deleteUserSessions(user.id);
    await vi.waitFor(() => expect(ended(events)).toHaveLength(1));
    expect(ended(events)[0]).toMatchObject({ reason: "revoked", truncated: false });
    expect(ended(events)[0]!.participants).toHaveLength(2);
  });

  it("a stale SLO marker (over a minute old) is ignored", async () => {
    const { markEndingBySlo, consumeEndingBySlo } = await import("../../src/storage/participants");
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      markEndingBySlo("s-fresh");
      expect(consumeEndingBySlo("s-fresh")).toBe(true);
      expect(consumeEndingBySlo("s-fresh")).toBe(false); // consumed
      markEndingBySlo("s-stale");
      vi.setSystemTime(Date.now() + 61_000);
      expect(consumeEndingBySlo("s-stale")).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("lists say when they were cut at 200 (pre-release review S-2)", async () => {
    const { endParticipants, listUserParticipants, sessionKeyOf } = await import("../../src/storage/participants");
    const sessionKey = await sessionKeyOf("s-big");
    const rows = Array.from({ length: 201 }, (_, i) => ({ spId: `sp${i}`, nameId: "n", nameIdFormat: "f", sessionIndex: "_s", sessionKey, userId: "u-big", expiresAt: new Date(Date.now() + 60_000) }));
    const fake = { findMany: async (a: any) => rows.slice(0, a.limit), updateMany: async () => rows.length } as any;
    const ended = await endParticipants(fake, "s-big", new Date());
    expect([ended.participants.length, ended.truncated]).toEqual([200, true]);
    const listed = await listUserParticipants(fake, "u-big");
    expect([listed.participants.length, listed.truncated]).toEqual([200, true]);
  });

  it("Better Auth's own /sign-out reports reason signed-out, and it is audited", async () => {
    const { auth, ctx, events } = await host();
    const { browser, user } = await signedInToBoth(auth);
    await browser.fetch(`${AUTH_BASE}/sign-out`, { method: "POST", headers: { origin: BASE_URL, "content-type": "application/json" }, body: "{}" });
    await vi.waitFor(() => expect(ended(events)).toHaveLength(1));
    expect(ended(events)[0]).toMatchObject({ reason: "signed-out", userId: user.id });
    await vi.waitFor(async () => {
      const rows = (await ctx.adapter.findMany({ model: AUDIT_MODEL, where: [{ field: "type", value: "session.ended" }] })) as any[];
      expect(rows.some((r) => r.userId === user.id)).toBe(true);
    });
  });

  it("an expired session, lazily deleted, reports reason expired and writes no audit row", async () => {
    const { auth, ctx, events } = await host();
    const { browser, user, session } = await signedInToBoth(auth);
    await ctx.adapter.update({ model: "session", where: [{ field: "id", value: session.id }], update: { expiresAt: new Date(Date.now() - 1000) } });
    await browser.fetch(`${AUTH_BASE}/get-session`, { headers: { "cache-control": "no-cache" } });
    await vi.waitFor(() => expect(ended(events)).toHaveLength(1));
    expect(ended(events)[0]).toMatchObject({ reason: "expired", userId: user.id });
    await new Promise((r) => setTimeout(r, 50));
    const rows = (await ctx.adapter.findMany({ model: AUDIT_MODEL, where: [{ field: "type", value: "session.ended" }] })) as any[];
    expect(rows.filter((r) => r.userId === user.id)).toEqual([]);
  });

  it("a failing participant read never blocks the delete (observer rule); the error is logged", async () => {
    const { auth, ctx, events, logs } = await host();
    const { user } = await signedInToBoth(auth);
    const findMany = ctx.adapter.findMany.bind(ctx.adapter);
    ctx.adapter.findMany = (async (args: any) => {
      if (args.model === PARTICIPANT_MODEL) throw new Error("participants unavailable");
      return findMany(args);
    }) as any;
    try {
      await ctx.internalAdapter.deleteUserSessions(user.id);
    } finally {
      ctx.adapter.findMany = findMany;
    }
    expect(await ctx.adapter.findMany({ model: "session", where: [{ field: "userId", value: user.id }] })).toEqual([]);
    await vi.waitFor(() => expect(logs.some((m) => /could not record the end of a session/.test(m))).toBe(true));
    expect(ended(events)).toEqual([]);
  });

  it("works without Single Logout: onSessionEnded alone turns tracking on (no /slo route)", async () => {
    const { auth, ctx, events } = await host({ singleLogout: undefined });
    const { browser, user } = await signedInToBoth(auth);
    expect((await browser.fetch(`${AUTH_BASE}/saml2/idp/slo`)).status).toBe(404);
    await ctx.internalAdapter.deleteUserSessions(user.id);
    await vi.waitFor(() => expect(ended(events)).toHaveLength(1));
    expect(ended(events)[0]!.participants).toHaveLength(2);
  });

  it("warns at startup when sessions live only in secondary storage (no hook can fire)", async () => {
    const store = new Map<string, string>();
    const secondaryStorage = { get: async (k: string) => store.get(k) ?? null, set: async (k: string, v: string) => void store.set(k, v), delete: async (k: string) => void store.delete(k) };
    const run = async (geolocationTracking: boolean) => {
      const logs: string[] = [];
      const { auth } = await createHost({
        cloudflare: { geolocationTracking },
        saml: { events: { onSessionEnded: () => {} } },
        auth: { secondaryStorage, logger: { level: "warn", log: (_l: string, m: string) => logs.push(m) } },
      });
      await auth.$context;
      return logs.some((m) => /events.onSessionEnded won't fire/.test(m));
    };
    expect(await run(false)).toBe(true);
    // better-auth-cloudflare's geolocation tracking forces sessions into the database too: no warning.
    expect(await run(true)).toBe(false);
  });

  it("a session with no SAML participants emits nothing", async () => {
    const { auth, ctx, events } = await host();
    const browser = new Browser(auth);
    const user = await browser.signUp();
    await ctx.internalAdapter.deleteUserSessions(user.id);
    await new Promise((r) => setTimeout(r, 50));
    expect(ended(events)).toEqual([]);
    expect(code).toBeTypeOf("function");
  });
});

describe("sessionNotOnOrAfter (D-043)", () => {
  const authnStatement = (xml: string) => /<saml:AuthnStatement [^>]*>/.exec(xml)![0];
  async function issued(saml: Record<string, unknown>) {
    const { auth } = await createHost({ saml });
    const browser = new Browser(auth);
    await browser.signUp();
    const before = Date.now();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    const session = (await (await browser.fetch(`${AUTH_BASE}/get-session`)).json()) as { session: { expiresAt: string } };
    return { xml, before, expiresAt: new Date(session.session.expiresAt).getTime() };
  }
  const sessionEnd = (stmt: string) => {
    const m = /SessionNotOnOrAfter="([^"]+)"/.exec(stmt);
    return m ? new Date(m[1]!).getTime() : undefined;
  };

  it("absent by default", async () => {
    expect(authnStatement((await issued({})).xml)).not.toContain("SessionNotOnOrAfter");
  });

  it('"idp-session": the IdP session\'s expiry', async () => {
    const { xml, expiresAt } = await issued({ sessionNotOnOrAfter: "idp-session" });
    expect(Math.abs(sessionEnd(authnStatement(xml))! - expiresAt)).toBeLessThan(1000);
  });

  it("{ maxSeconds }: that long after issuance, never past the IdP session; schema-valid", async () => {
    const { xml, before, expiresAt } = await issued({ sessionNotOnOrAfter: { maxSeconds: 600 } });
    const end = sessionEnd(authnStatement(xml))!;
    expect(end).toBeGreaterThanOrEqual(Math.floor(before / 1000) * 1000 + 600_000 - 1000);
    expect(end).toBeLessThanOrEqual(Date.now() + 600_000);
    expect(end).toBeLessThan(expiresAt);
    expect(await libxml2Validator().validate(xml, "protocol")).toEqual({ valid: true });
    // A cap longer than the session is cut to the session's end.
    const long = await issued({ sessionNotOnOrAfter: { maxSeconds: 30 * 86400 } });
    expect(Math.abs(sessionEnd(authnStatement(long.xml))! - long.expiresAt)).toBeLessThan(1000);
  });

  it("each SP can override the global setting", async () => {
    const { xml } = await issued({ sessionNotOnOrAfter: "idp-session", serviceProviders: [{ ...SP, sessionNotOnOrAfter: false }] });
    expect(authnStatement(xml)).not.toContain("SessionNotOnOrAfter");
  });

  it("stored SPs take it, and bad values are refused", () => {
    const options = resolveOptions(baseOptions());
    const sp = (v: unknown) => ({ id: "s", entityId: "https://s.test/sp", acsUrls: ["https://s.test/acs"], sessionNotOnOrAfter: v });
    expect(resolveStoredServiceProvider(sp({ maxSeconds: 3600 }), options).serviceProvider?.sessionNotOnOrAfter).toEqual({ maxSeconds: 3600 });
    for (const bad of [true, "forever", { maxSeconds: 10 }, { maxSeconds: 3600, extra: 1 }])
      expect(resolveStoredServiceProvider(sp(bad), options).issues.join()).toMatch(/sessionNotOnOrAfter/);
  });
});

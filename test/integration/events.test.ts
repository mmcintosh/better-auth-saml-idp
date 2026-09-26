// Observability (D-038): events.onAssertionIssued / onDenied / onLogout, and the audit-log table.
import { describe, expect, it, vi } from "vitest";
import type { SamlIdpEvent } from "../../src/events";
import { AUDIT_MODEL } from "../../src/events";
import { resetSweepThrottle, sweepExpired } from "../../src/storage/sweep";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const SP = { id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] as [string], singleLogoutService: { url: "https://sp.test/slo" }, attributes: { mail: "email" } };

async function host(opts: { saml?: Record<string, unknown>; handlers?: "record" | "throw" | "hang" } = {}) {
  const events: SamlIdpEvent[] = [];
  const logs: string[] = [];
  const record = (e: SamlIdpEvent) => {
    events.push(e);
    if (opts.handlers === "throw") throw new Error("handler exploded");
    if (opts.handlers === "hang") return new Promise<void>(() => {});
  };
  const { auth } = await createHost({
    saml: {
      singleLogout: { enabled: true },
      serviceProviders: [SP],
      events: { onAssertionIssued: record, onDenied: record, onLogout: record },
      ...opts.saml,
    },
    auth: { logger: { level: "error", log: (_l: string, m: string) => logs.push(m) } },
  });
  const rows = async () => ((await (await auth.$context).adapter.findMany({ model: AUDIT_MODEL })) as Record<string, any>[]).sort((a, b) => +new Date(a.at) - +new Date(b.at));
  return { auth, events, logs, rows };
}

const of = <T extends SamlIdpEvent["type"]>(events: SamlIdpEvent[], type: T) => events.filter((e): e is Extract<SamlIdpEvent, { type: T }> => e.type === type);

describe("events", () => {
  it("onAssertionIssued: who got what, where, without attribute values", async () => {
    const { auth, events } = await host();
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const { id, xml } = authnRequestXml();
    await readAutoPost(await browser.fetch(await redirectUrl(xml)));
    await vi.waitFor(() => expect(of(events, "assertion.issued")).toHaveLength(1));
    const e = of(events, "assertion.issued")[0]!;
    expect(e).toMatchObject({
      spId: "test-sp",
      entityId: SP_ENTITY_ID,
      userId: user.id,
      initiatedBy: "sp",
      inResponseTo: id,
      acsUrl: SP_ACS,
      nameId: user.email,
      attributes: ["mail"],
      encrypted: false,
    });
    expect(e.assertionId).toMatch(/^_/);
    expect(e.at).toBeInstanceOf(Date);
    expect(e.ipAddress).toMatch(/^10\./);
    expect(JSON.stringify(e)).not.toContain(`"mail":`); // names only, never values
  });

  it("onDenied: protocol errors (no SP known), access denials (SP and user), and SAML status Responses", async () => {
    const { auth, events } = await host({ saml: { serviceProviders: [{ ...SP, authorize: () => false }] } });
    const browser = new Browser(auth);
    // Unknown SP, nobody signed in.
    await browser.fetch(await redirectUrl(authnRequestXml({ issuer: "https://nobody.test/sp" }).xml));
    // IsPassive without a session: a SAML NoPassive Response to the SP.
    await browser.fetch(await redirectUrl(authnRequestXml({ isPassive: true }).xml));
    // Signed in, but authorize() says no.
    const user = await browser.signUp();
    await browser.fetch(await redirectUrl(authnRequestXml().xml));
    await vi.waitFor(() => expect(of(events, "denied")).toHaveLength(3));
    const [unknown, passive, denied] = of(events, "denied");
    expect(unknown).toMatchObject({ code: "UNKNOWN_SERVICE_PROVIDER" });
    expect(unknown!.spId).toBeUndefined();
    expect(passive).toMatchObject({ code: "SAML_STATUS", status: { code: "Responder", subCode: "NoPassive" }, spId: "test-sp" });
    expect(denied).toMatchObject({ code: "ACCESS_DENIED", spId: "test-sp", userId: user.id });
    expect(denied!.detail).toContain("authorize() denied");
  });

  it("onLogout: IdP-initiated sign-out everywhere, with the SPs to notify", async () => {
    const { auth, events } = await host();
    const browser = new Browser(auth);
    const user = await browser.signUp();
    await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    const session = (await (await browser.fetch(`${AUTH_BASE}/get-session`)).json()) as { session: { id: string } };
    await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=/`);
    await vi.waitFor(() => expect(of(events, "logout")).toHaveLength(1));
    expect(of(events, "logout")[0]).toMatchObject({ initiatedBy: "idp", userId: user.id, sessionId: session.session.id, notifying: ["test-sp"] });
  });

  it("a handler that throws is logged, and sign-in still works", async () => {
    const { auth, events, logs } = await host({ handlers: "throw" });
    const browser = new Browser(auth);
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(form.xml).toContain("status:Success");
    await vi.waitFor(() => expect(logs.some((m) => /events\.onAssertionIssued threw/.test(m))).toBe(true));
    expect(events).toHaveLength(1);
  });

  it("handlers run through Better Auth's background tasks (waitUntil on Workers), so they outlive the response", async () => {
    const tasks: Promise<unknown>[] = [];
    const events: SamlIdpEvent[] = [];
    const { auth } = await createHost({
      saml: { serviceProviders: [SP], events: { onAssertionIssued: async (e) => { await new Promise((r) => setTimeout(r, 50)); events.push(e); } } },
      auth: { advanced: { backgroundTasks: { handler: (p: Promise<unknown>) => void tasks.push(p) } } },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    await Promise.all(tasks);
    expect(events).toHaveLength(1); // delivered by a task the host was given to keep alive
  });

  it("a handler that never settles doesn't delay the response", async () => {
    const { auth } = await host({ handlers: "hang" });
    const browser = new Browser(auth);
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(form.xml).toContain("status:Success");
  });
});

describe("audit log", () => {
  it("records issued assertions, denials of signed-in users, and logouts; not anonymous denials", async () => {
    const { auth, rows } = await host({ saml: { auditLog: { enabled: true, retentionDays: 30 } } });
    const anonymous = new Browser(auth);
    await anonymous.fetch(await redirectUrl(authnRequestXml({ issuer: "https://nobody.test/sp" }).xml)); // no SP, no user
    for (let i = 0; i < 5; i++) await anonymous.fetch(await redirectUrl(authnRequestXml({ isPassive: true }).xml)); // names the SP, no user (R4-3)
    const unverified = new Browser(auth);
    const refused = await unverified.signUp(undefined, { verified: false });
    await unverified.fetch(await redirectUrl(authnRequestXml().xml)); // EMAIL_NOT_VERIFIED: a signed-in user, stored
    const browser = new Browser(auth);
    const user = await browser.signUp();
    await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=/`);
    const mine = async () => (await rows()).filter((r) => r.userId === user.id || r.userId === refused.id);
    await vi.waitFor(async () => expect((await mine()).map((r) => r.type)).toEqual(["denied", "assertion.issued", "logout"]));
    const [denied, issued, logout] = await mine();
    expect(denied).toMatchObject({ code: "EMAIL_NOT_VERIFIED", spId: "test-sp", userId: refused.id });
    expect(issued).toMatchObject({ spId: "test-sp", userId: user.id, code: null });
    expect(issued!.ipAddress).toMatch(/^10\./);
    expect(JSON.parse(issued!.details)).toMatchObject({ nameId: user.email, attributes: ["mail"], initiatedBy: "sp" });
    expect(logout).toMatchObject({ userId: user.id });
    // Denials without a user were never stored, whether or not they named an SP.
    expect((await rows()).filter((r) => r.type === "denied" && r.userId === null)).toEqual([]);
    const days = (+new Date(issued!.expiresAt) - +new Date(issued!.at)) / 86_400_000;
    expect(Math.round(days)).toBe(30);
  });

  it("expired rows are swept, live ones kept", async () => {
    const { auth, rows } = await host({ saml: { auditLog: { enabled: true } } });
    const ctx = await auth.$context;
    const base = { type: "denied", spId: "sweep-test", details: "{}", at: new Date() };
    await ctx.adapter.create({ model: AUDIT_MODEL, data: { ...base, code: "old", expiresAt: new Date(Date.now() - 1000) } });
    await ctx.adapter.create({ model: AUDIT_MODEL, data: { ...base, code: "new", expiresAt: new Date(Date.now() + 60_000) } });
    resetSweepThrottle();
    await sweepExpired(ctx.adapter as any, (w, e) => { throw new Error(`${w}: ${e}`); }, Date.now(), { auditLog: true });
    expect((await rows()).filter((r) => r.spId === "sweep-test").map((r) => r.code)).toEqual(["new"]);
  });

  it("without auditLog, no table is used", async () => {
    const { auth } = await host();
    const ctx = await auth.$context;
    expect(Object.keys(ctx.options.plugins?.find((p) => p.id === "saml-idp")?.schema ?? {})).not.toContain(AUDIT_MODEL);
  });
});

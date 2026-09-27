// authorize() may return { allow: false, reason, reauthenticate } (before 1.0; D-044): a reason for
// the denied event, and a way to send the user back to sign in again (e.g. for a fresh MFA).
import { describe, expect, it, vi } from "vitest";
import type { DeniedEvent, SamlIdpEvent } from "../../src/events";
import type { AuthorizeContext, AuthorizeResult } from "../../src/types";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, BASE_URL, createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

async function host(authorize: (ctx: AuthorizeContext) => AuthorizeResult | Promise<AuthorizeResult>) {
  const events: SamlIdpEvent[] = [];
  const logs: string[] = [];
  const { auth } = await createHost({
    saml: {
      serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], authorize }],
      events: { onDenied: (e) => void events.push(e), onAssertionIssued: (e) => void events.push(e) },
    },
    auth: { logger: { level: "info", log: (_l: string, m: string) => logs.push(m) } },
  });
  const browser = new Browser(auth);
  const user = await browser.signUp();
  return { auth, browser, user, events, logs };
}
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const signInAgain = (browser: Browser, email: string) =>
  browser.fetch(`${AUTH_BASE}/sign-in/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BASE_URL },
    body: JSON.stringify({ email, password: "correct-horse-battery" }),
  });

describe("authorize() results (D-044)", () => {
  it("{ allow: true } issues", async () => {
    const { browser } = await host(() => ({ allow: true }));
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(xml).toContain("<saml:Assertion");
  });

  it("{ allow: false, reason } denies, and the reason reaches the denied event (log-safe)", async () => {
    const { browser, events } = await host(() => ({ allow: false, reason: "no entitlement for\ntest-sp" }));
    expect(await code(await browser.fetch(await redirectUrl(authnRequestXml().xml)))).toBe("ACCESS_DENIED");
    await vi.waitFor(() => expect(events.some((e) => e.type === "denied")).toBe(true));
    const denied = events.find((e): e is DeniedEvent => e.type === "denied")!;
    expect(denied.detail).toMatch(/no entitlement for.test-sp/);
    expect(denied.detail).not.toContain("\n");
  });

  it("reauthenticate: the user is sent to sign in again (prompt=login), and the fresh session is allowed", async () => {
    let cutoff = Number.POSITIVE_INFINITY;
    const { browser, logs } = await host(({ session }) =>
      new Date(session.createdAt).getTime() >= cutoff ? true : { allow: false, reason: "mfa too old\n[saml-idp] forged line", reauthenticate: true },
    );
    cutoff = Date.now() + 5; // the current session is older than this
    await new Promise((r) => setTimeout(r, 10));
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).toBe(302);
    const login = new URL(res.headers.get("location")!);
    expect(login.pathname).toBe("/sign-in");
    expect(login.searchParams.get("prompt")).toBe("login");
    const resume = login.searchParams.get("callbackURL")!;
    expect(resume).toMatch(/\/saml2\/idp\/resume\?rid=/);
    // The reason is logged on one line: a newline can't forge a log entry.
    const line = logs.find((m) => /asking the user to sign in again/.test(m))!;
    expect(line).toMatch(/mfa too old.\[saml-idp\] forged line/);
    expect(line).not.toContain("\n");

    // Coming back without signing in again is refused.
    expect(await code(await browser.fetch(resume))).toBe("REAUTHENTICATION_REQUIRED");
  });

  it("reauthenticate, then a fresh sign-in completes the original request", async () => {
    let cutoff = Number.POSITIVE_INFINITY;
    const { browser, user } = await host(({ session }) =>
      new Date(session.createdAt).getTime() >= cutoff ? true : { allow: false, reauthenticate: true },
    );
    cutoff = Date.now() + 5;
    await new Promise((r) => setTimeout(r, 10));
    const { id, xml } = authnRequestXml();
    const res = await browser.fetch(await redirectUrl(xml));
    const resume = new URL(res.headers.get("location")!).searchParams.get("callbackURL")!;
    expect((await signInAgain(browser, user.email)).status).toBe(200);
    const form = await readAutoPost(await browser.fetch(resume));
    expect(form.xml).toContain(`InResponseTo="${id}"`);
    expect(form.xml).toContain("<saml:Assertion");
  });

  it("loop guard: still refused after signing in again for this request → a plain denial, not another round", async () => {
    const { browser, user, events } = await host(() => ({ allow: false, reason: "never enough", reauthenticate: true }));
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    const resume = new URL(res.headers.get("location")!).searchParams.get("callbackURL")!;
    await new Promise((r) => setTimeout(r, 5));
    expect((await signInAgain(browser, user.email)).status).toBe(200);
    const again = await browser.fetch(resume);
    expect(again.status).not.toBe(302);
    expect(await code(again)).toBe("ACCESS_DENIED");
    await vi.waitFor(() => expect(events.some((e) => e.type === "denied" && /still after signing in again/.test(e.detail ?? ""))).toBe(true));
  });

  it("IsPassive: the SP gets NoPassive instead of a login page", async () => {
    const { browser } = await host(() => ({ allow: false, reauthenticate: true }));
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ isPassive: true }).xml)));
    expect(form.xml).toContain("urn:oasis:names:tc:SAML:2.0:status:NoPassive");
    expect(form.xml).not.toContain("<saml:Assertion");
  });

  it("anything else (a truthy non-true value, a malformed object) denies", async () => {
    for (const verdict of [1, "yes", { allow: "true" }, {}, null] as unknown as AuthorizeResult[]) {
      const { browser } = await host(() => verdict);
      expect(await code(await browser.fetch(await redirectUrl(authnRequestXml().xml)))).toBe("ACCESS_DENIED");
    }
  });
});

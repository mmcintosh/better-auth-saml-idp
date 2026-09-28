// Fixed in D-048; kept as regression tests. Comments saying "today" describe fad67c2.
// Review 5 (step-up, D-047): the first sign-in round never carries acr_values, so a login page
// can't step up on it. For an SP that sends ForceAuthn with its RequestedAuthnContext (common:
// "re-authenticate with MFA"), the loop guard then fires after that single password round and
// the SP gets NoAuthnContext; step-up can never succeed for such an SP. The same happens when
// authorize() asked for re-authentication first (D-044) and step-up is judged on the fresh session.
import { describe, expect, it } from "vitest";
import { AUTH_BASE, BASE_URL, createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";

const PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const MFA = "https://refeds.org/profile/mfa";
const LEVELS = [PPT, MFA];
const rac = (comparison: string, ...refs: string[]) =>
  `<samlp:RequestedAuthnContext Comparison="${comparison}">${refs.map((r) => `<saml:AuthnContextClassRef>${r}</saml:AuthnContextClassRef>`).join("")}</samlp:RequestedAuthnContext>`;
const statusOf = (xml: string) => [...xml.matchAll(/StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:([A-Za-z]+)"/g)].map((m) => m[1]);
const classOf = (xml: string) => /<saml:AuthnContextClassRef>([^<]+)<\/saml:AuthnContextClassRef>/.exec(xml)?.[1];

/** MFA is "done" when the user's image field says so; the login page simulates it by setting it before signing in. */
async function host(extraSp: Record<string, unknown> = {}) {
  const { auth } = await createHost({
    saml: {
      serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], ...extraSp }],
      authnContext: { levels: LEVELS, current: ({ user }: any) => (user.image === "mfa" ? MFA : PPT) },
    },
  });
  const browser = new Browser(auth);
  const user = await browser.signUp();
  const ctx = await auth.$context;
  const completeMfa = () => ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { image: "mfa" } });
  const signIn = () =>
    browser.fetch(`${AUTH_BASE}/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE_URL },
      body: JSON.stringify({ email: user.email, password: "correct-horse-battery" }),
    });
  const signOut = () => browser.fetch(`${AUTH_BASE}/sign-out`, { method: "POST", headers: { origin: BASE_URL, "content-type": "application/json" }, body: "{}" });
  return { browser, user, completeMfa, signIn, signOut };
}

describe("R5-1: the first sign-in round carries no acr_values", () => {
  it("signed out, minimum MFA: the sign-in redirect should already say acr_values=MFA (it doesn't, so the user signs in twice)", async () => {
    const { browser, signOut } = await host();
    await signOut();
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ inner: rac("minimum", MFA) }).xml));
    expect(res.status).toBe(302);
    const login = new URL(res.headers.get("location")!);
    expect(login.searchParams.get("acr_values")).toBe(MFA);
  });

  it("signed out, minimum MFA: after one MFA sign-in the request is issued (today: a second sign-in round is demanded)", async () => {
    const { browser, signOut, signIn, completeMfa } = await host();
    await signOut();
    const { id, xml } = authnRequestXml({ inner: rac("minimum", MFA) });
    const res = await browser.fetch(await redirectUrl(xml));
    const resume = new URL(res.headers.get("location")!).searchParams.get("callbackURL")!;
    // The login page did MFA on this very round (as it would with acr_values).
    await completeMfa();
    expect((await signIn()).status).toBe(200);
    const back = await browser.fetch(resume);
    // Expected: the assertion, on the first return. (This part passes today; the cost is the
    // extra round when the page can't know MFA is wanted, shown by the previous test.)
    expect(back.status).toBe(200);
    const { xml: response } = await readAutoPost(back);
    expect(response).toContain(`InResponseTo="${id}"`);
    expect(classOf(response)).toBe(MFA);
  });

  it("SP ForceAuthn + minimum MFA, signed-in password user: the redirect must carry acr_values; today the page isn't told, and the one round it gets ends in NoAuthnContext", async () => {
    const { browser, signIn } = await host();
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ forceAuthn: true, inner: rac("minimum", MFA) }).xml));
    expect(res.status).toBe(302);
    const login = new URL(res.headers.get("location")!);
    expect(login.searchParams.get("prompt")).toBe("login");
    // FAILS today: no acr_values on a ForceAuthn park.
    expect(login.searchParams.get("acr_values")).toBe(MFA);
    // Consequence (passes today, documenting the dead end): the page, not told, does a password
    // sign-in; the loop guard sees forceAuthn + a fresh session and answers NoAuthnContext, so
    // this SP can never be stepped up.
    const resume = login.searchParams.get("callbackURL")!;
    await new Promise((r) => setTimeout(r, 5));
    expect((await signIn()).status).toBe(200);
    const { xml } = await readAutoPost(await browser.fetch(resume));
    expect(statusOf(xml)).toEqual(["Responder", "NoAuthnContext"]);
  });
});

describe("R5-2: authorize() reauthenticate, then step-up", () => {
  // Fixed by sending acr_values on every park (the reviewer's second option, D-048): the
  // reauthenticate redirect already names the level, so one round is enough for a page that
  // honours it; a page that ignores it gets NoAuthnContext, as the loop guard intends.
  it("the reauthenticate redirect carries acr_values; a page that honours it gets the assertion in one round", async () => {
    let cutoff = Number.POSITIVE_INFINITY;
    const { browser, signIn, completeMfa } = await host({
      authorize: ({ session }: any) => (new Date(session.createdAt).getTime() >= cutoff ? true : { allow: false, reason: "stale", reauthenticate: true }),
    });
    cutoff = Date.now() + 5;
    await new Promise((r) => setTimeout(r, 10));
    const { id, xml } = authnRequestXml({ inner: rac("minimum", MFA) });
    const res = await browser.fetch(await redirectUrl(xml));
    expect(res.status).toBe(302);
    const login = new URL(res.headers.get("location")!);
    expect([login.searchParams.get("prompt"), login.searchParams.get("acr_values")]).toEqual(["login", MFA]);
    const resume = login.searchParams.get("callbackURL")!;
    await completeMfa(); // the page did what acr_values asked
    expect((await signIn()).status).toBe(200);
    const { xml: response } = await readAutoPost(await browser.fetch(resume));
    expect(response).toContain(`InResponseTo="${id}"`);
    expect(classOf(response)).toBe(MFA);
  });

  it("a page that ignores acr_values on that round gets NoAuthnContext (it was told)", async () => {
    let cutoff = Number.POSITIVE_INFINITY;
    const { browser, signIn } = await host({
      authorize: ({ session }: any) => (new Date(session.createdAt).getTime() >= cutoff ? true : { allow: false, reauthenticate: true }),
    });
    cutoff = Date.now() + 5;
    await new Promise((r) => setTimeout(r, 10));
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ inner: rac("minimum", MFA) }).xml));
    const resume = new URL(res.headers.get("location")!).searchParams.get("callbackURL")!;
    expect((await signIn()).status).toBe(200);
    const { xml } = await readAutoPost(await browser.fetch(resume));
    expect(statusOf(xml)).toEqual(["Responder", "NoAuthnContext"]);
  });
});

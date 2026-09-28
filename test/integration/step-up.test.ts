// Step-up authentication (D-047): RequestedAuthnContext judged against the host's levels and the
// class the current session achieved, sending the user back to sign in when more is needed.
import { describe, expect, it } from "vitest";
import { resolveOptions, SamlIdpConfigError } from "../../src/options";
import { satisfiesAuthnContext, stepUpTarget } from "../../src/saml/request";
import { baseOptions } from "../support/config";
import { AUTH_BASE, BASE_URL, createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const MFA = "https://refeds.org/profile/mfa";
const OTHER = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
const LEVELS = [PPT, MFA];
const rac = (comparison: string, ...refs: string[]) =>
  `<samlp:RequestedAuthnContext Comparison="${comparison}">${refs.map((r) => `<saml:AuthnContextClassRef>${r}</saml:AuthnContextClassRef>`).join("")}</samlp:RequestedAuthnContext>`;
const classOf = (xml: string) => /<saml:AuthnContextClassRef>([^<]+)<\/saml:AuthnContextClassRef>/.exec(xml)?.[1];
const statusOf = (xml: string) => [...xml.matchAll(/StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:([A-Za-z]+)"/g)].map((m) => m[1]);
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe("level comparison (SAML Core §3.3.2.2.1)", () => {
  const r = (comparison: "exact" | "minimum" | "maximum" | "better", ...classRefs: string[]) => ({ comparison, classRefs, hasDeclRefs: false });
  it.each([
    ["exact", [MFA], MFA, true],
    ["exact", [MFA], PPT, false],
    ["minimum", [PPT], MFA, true],
    ["minimum", [MFA], PPT, false],
    ["better", [PPT], MFA, true],
    ["better", [MFA], MFA, false],
    ["maximum", [MFA], PPT, true],
    ["maximum", [MFA], MFA, true], // "no stronger than": equal counts
    ["minimum", [MFA], MFA, true], // "at least as strong": equal counts
    ["maximum", [PPT], MFA, false],
    ["minimum", [OTHER], MFA, false], // unknown classes only match exactly
    ["exact", [OTHER, MFA], MFA, true],
  ] as const)("%s %j with %s → %s", (comparison, refs, achieved, want) => {
    expect(satisfiesAuthnContext(r(comparison, ...refs), achieved, LEVELS)).toBe(want);
  });

  it("the step-up target is the weakest level that would do; none for the unreachable", () => {
    expect(stepUpTarget(r("minimum", MFA), LEVELS)).toBe(MFA);
    expect(stepUpTarget(r("minimum", PPT), LEVELS)).toBe(PPT);
    expect(stepUpTarget(r("better", PPT), LEVELS)).toBe(MFA);
    expect(stepUpTarget(r("better", MFA), LEVELS)).toBeUndefined();
    expect(stepUpTarget(r("exact", OTHER), LEVELS)).toBeUndefined();
    expect(stepUpTarget({ comparison: "exact", classRefs: [MFA], hasDeclRefs: true }, LEVELS)).toBeUndefined();
  });

  it("config: levels are unique and non-empty, and exclusive with authnContextClassRef", () => {
    const current = () => PPT;
    expect(() => resolveOptions(baseOptions({ authnContext: { levels: [PPT, PPT], current } }))).toThrow(/unique/);
    expect(() => resolveOptions(baseOptions({ authnContext: { levels: [], current } }))).toThrow(SamlIdpConfigError);
    expect(() => resolveOptions(baseOptions({ authnContextClassRef: PPT, authnContext: { levels: LEVELS, current } }))).toThrow(/not both/);
  });
});

/** A host whose "second factor" is simulated by the user's `image` field: "mfa" means done. */
async function host(current?: (ctx: any) => unknown) {
  const { auth } = await createHost({
    saml: { authnContext: { levels: LEVELS, current: (current ?? (({ user }: any) => (user.image === "mfa" ? MFA : PPT))) as any } },
  });
  const browser = new Browser(auth);
  const user = await browser.signUp();
  const ctx = await auth.$context;
  const completeMfa = () => ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { image: "mfa" } });
  const signInAgain = () =>
    browser.fetch(`${AUTH_BASE}/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE_URL },
      body: JSON.stringify({ email: user.email, password: "correct-horse-battery" }),
    });
  return { browser, user, completeMfa, signInAgain };
}

describe("step-up, end to end", () => {
  it("no RequestedAuthnContext: the assertion states what the session achieved", async () => {
    const { browser } = await host();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(classOf(xml)).toBe(PPT);
  });

  it("minimum MFA on a password session: back to sign-in with prompt=login and acr_values; after MFA, issued with MFA", async () => {
    const { browser, completeMfa, signInAgain } = await host();
    const { id, xml: request } = authnRequestXml({ inner: rac("minimum", MFA) });
    const res = await browser.fetch(await redirectUrl(request));
    expect(res.status).toBe(302);
    const login = new URL(res.headers.get("location")!);
    expect([login.searchParams.get("prompt"), login.searchParams.get("acr_values")]).toEqual(["login", MFA]);
    const resume = login.searchParams.get("callbackURL")!;
    // Coming back on the old session is refused: a fresh sign-in is needed.
    expect(await code(await browser.fetch(resume))).toBe("REAUTHENTICATION_REQUIRED");
    const again = await browser.fetch(await redirectUrl(authnRequestXml({ inner: rac("minimum", MFA) }).xml));
    const resume2 = new URL(again.headers.get("location")!).searchParams.get("callbackURL")!;
    await completeMfa();
    await new Promise((r) => setTimeout(r, 5));
    expect((await signInAgain()).status).toBe(200);
    const { xml } = await readAutoPost(await browser.fetch(resume2));
    expect(classOf(xml)).toBe(MFA);
    expect(xml).toContain("<saml:Assertion");
    void id;
  });

  it("already enough: a minimum-password request on an MFA session is issued at once, stating MFA", async () => {
    const { browser, completeMfa } = await host();
    await completeMfa();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ inner: rac("minimum", PPT) }).xml)));
    expect(classOf(xml)).toBe(MFA);
  });

  it("loop guard: still not enough after signing in again → NoAuthnContext to the SP, not another round", async () => {
    const { browser, signInAgain } = await host();
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ inner: rac("exact", MFA) }).xml));
    const resume = new URL(res.headers.get("location")!).searchParams.get("callbackURL")!;
    await new Promise((r) => setTimeout(r, 5));
    expect((await signInAgain()).status).toBe(200); // no MFA this time
    const { xml } = await readAutoPost(await browser.fetch(resume));
    expect(statusOf(xml)).toEqual(["Responder", "NoAuthnContext"]);
    expect(xml).not.toContain("<saml:Assertion");
  });

  it("IsPassive: NoPassive instead of a sign-in page", async () => {
    const { browser } = await host();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ isPassive: true, inner: rac("minimum", MFA) }).xml)));
    expect(statusOf(xml)).toEqual(["Responder", "NoPassive"]);
  });

  it("a class no level can deliver is refused at once (NoAuthnContext), without a sign-in round", async () => {
    const { browser } = await host();
    // Signed out: without the early check this would go to the sign-in page first.
    await browser.fetch(`${AUTH_BASE}/sign-out`, { method: "POST", headers: { origin: BASE_URL, "content-type": "application/json" }, body: "{}" });
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ inner: rac("exact", OTHER) }).xml)));
    expect(statusOf(xml)).toEqual(["Responder", "NoAuthnContext"]);
  });

  it("current() returning a class outside levels, or throwing, issues nothing", async () => {
    for (const current of [() => OTHER, () => { throw new Error("boom"); }]) {
      const { browser } = await host(current);
      expect(await code(await browser.fetch(await redirectUrl(authnRequestXml().xml)))).toBe("INTERNAL_ERROR");
    }
  });
});

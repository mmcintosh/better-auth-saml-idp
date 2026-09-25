// IdP-initiated SSO (GET /saml2/idp/init?sp=<id>), DECISIONS.md D-021, on the R5 host
// (workerd: withCloudflare + Drizzle/D1; node: node:sqlite).
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost, createHostDatabase, type HostOptions } from "../support/host";
import { Browser, readAutoPost, strictSp } from "../support/sp";

type Sp = NonNullable<HostOptions["saml"]>["serviceProviders"];
const INIT_URL = `${AUTH_BASE}/saml2/idp/init`;
const init = (query: Record<string, string> = { sp: "test-sp" }) => `${INIT_URL}?${new URLSearchParams(query)}`;

function spConfig(over: Record<string, unknown> = {}): Sp {
  return [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS, "https://sp.test/acs2"], allowIdpInitiated: true, ...over }] as Sp;
}

async function host(sp: Record<string, unknown> = {}, options: HostOptions = {}) {
  const h = await createHost({ ...options, saml: { serviceProviders: spConfig(sp), ...options.saml } });
  return { ...h, browser: new Browser(h.auth) };
}

const pageCode = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const hasAssertion = async (res: Response) => /SAMLResponse/.test(await res.clone().text());

describe("IdP-initiated SSO: refusals", () => {
  it("is off by default: an SP without the opt-in gets no Response", async () => {
    const { browser } = await host({ allowIdpInitiated: undefined });
    await browser.signUp();
    const res = await browser.fetch(init());
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("IDP_INITIATED_NOT_ALLOWED");
    expect(await hasAssertion(res)).toBe(false);
  });

  it("the opt-in is refused without a session too (no login redirect, no pending request)", async () => {
    const { browser } = await host({ allowIdpInitiated: false });
    const res = await browser.fetch(init());
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("IDP_INITIATED_NOT_ALLOWED");
  });

  it("unknown or missing sp → 400, nothing reflected", async () => {
    const { browser } = await host();
    await browser.signUp();
    const unknown = await browser.fetch(init({ sp: "evil<script>" }));
    expect(unknown.status).toBe(400);
    expect(await pageCode(unknown)).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(await unknown.clone().text()).not.toContain("evil");
    expect(await hasAssertion(unknown)).toBe(false);
    const missing = await browser.fetch(INIT_URL);
    expect(missing.status).toBe(400);
    expect(await pageCode(missing)).toBe("UNKNOWN_SERVICE_PROVIDER");
  });

  it("is GET only: POST is not routed", async () => {
    const { browser } = await host();
    await browser.signUp();
    const res = await browser.fetch(INIT_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "sp=test-sp",
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(await hasAssertion(res)).toBe(false);
  });
});

describe("IdP-initiated SSO: with a session", () => {
  it("auto-POSTs an unsolicited Response to the SP's first ACS URL, accepted by a strict samlify SP", async () => {
    const { auth, browser } = await host();
    const user = await browser.signUp();
    const res = await browser.fetch(init());
    expect(res.status).toBe(200);
    const form = await readAutoPost(res);
    expect(form.action).toBe(SP_ACS);
    // Unsolicited: no InResponseTo on the Response or on SubjectConfirmationData.
    expect(form.xml).not.toContain("InResponseTo");
    expect(form.xml).toContain(`Destination="${SP_ACS}"`);
    expect(form.xml).toContain(`Recipient="${SP_ACS}"`);
    expect(form.xml).toContain(`<saml:Audience>${SP_ENTITY_ID}</saml:Audience>`);
    expect(form.xml).toMatch(/<saml:SubjectConfirmationData NotOnOrAfter="[^"]+" Recipient="[^"]+"\/>/);
    expect(form.relayState).toBeUndefined();

    const sp = await strictSp(auth);
    const { extract } = await sp.verify(form.samlResponse);
    expect(extract.nameID).toBe(user.email);
    expect(extract.response?.inResponseTo).toBeFalsy();
    expect(extract.audience).toBe(SP_ENTITY_ID);
  });

  it("the NameID follows the SP's format (persistent → opaque, not the email)", async () => {
    const { browser } = await host({ nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" });
    const user = await browser.signUp();
    const form = await readAutoPost(await browser.fetch(init()));
    expect(form.xml).toContain('Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"');
    expect(form.xml).not.toContain(`>${user.email}</saml:NameID>`);
  });

  it("includes the SP's attributes", async () => {
    const { browser } = await host({ attributes: (u: { email: string }) => ({ mail: u.email, role: ["a", "b"] }) });
    const user = await browser.signUp();
    const form = await readAutoPost(await browser.fetch(init()));
    expect(form.xml).toContain(`<saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>${user.email}</saml:AttributeValue>`);
    expect(form.xml).toContain("<saml:AttributeValue>a</saml:AttributeValue><saml:AttributeValue>b</saml:AttributeValue>");
  });
});

describe("IdP-initiated SSO: without a session", () => {
  it("sends the user to sign in, then resume issues the unsolicited Response once (R1)", async () => {
    const { browser } = await host({ idpInitiatedRelayState: "https://sp.test/home" });
    const toLogin = await browser.fetch(init());
    expect(toLogin.status).toBe(302);
    const login = new URL(toLogin.headers.get("location")!);
    expect(login.pathname).toBe("/sign-in");
    const resume = login.searchParams.get("callbackURL")!;
    expect(resume.startsWith(`${AUTH_BASE}/saml2/idp/resume?rid=`)).toBe(true);
    expect(browser.cookieHeader()).toMatch(/saml_idp_binding=/);

    await browser.signUp();
    const res = await browser.fetch(resume);
    expect(res.status).toBe(200);
    const form = await readAutoPost(res);
    expect(form.action).toBe(SP_ACS);
    expect(form.xml).not.toContain("InResponseTo");
    expect(form.relayState).toBe("https://sp.test/home");

    const again = await browser.fetch(resume);
    expect(again.status).toBe(400);
    expect(await pageCode(again)).toBe("PENDING_REQUEST_NOT_FOUND");
    expect(await hasAssertion(again)).toBe(false);
  });

  it("the resume link is bound to the browser that started it", async () => {
    const { auth, browser } = await host();
    const toLogin = await browser.fetch(init());
    const resume = new URL(toLogin.headers.get("location")!).searchParams.get("callbackURL")!;
    const other = new Browser(auth);
    await other.fetch(init()); // the attacker holds a valid binding cookie of their own
    expect(other.cookieHeader()).toMatch(/saml_idp_binding=/);
    await other.signUp();
    const res = await other.fetch(resume);
    expect(res.status).toBe(400);
    expect(await hasAssertion(res)).toBe(false);
  });

  it("an SP that drops the opt-in while the user signs in gets nothing on resume", async () => {
    const database = await createHostDatabase();
    const before = await createHost({ database, saml: { serviceProviders: spConfig() } });
    const after = await createHost({ database, saml: { serviceProviders: spConfig({ allowIdpInitiated: false }) } });
    const b1 = new Browser(before.auth);
    const resume = new URL((await b1.fetch(init())).headers.get("location")!).searchParams.get("callbackURL")!;
    await b1.signUp();
    const b2 = b1.clone();
    (b2 as any).auth = after.auth;
    const res = await b2.fetch(resume);
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("IDP_INITIATED_NOT_ALLOWED");
    expect(await hasAssertion(res)).toBe(false);
  });
});

describe("IdP-initiated SSO: RelayState", () => {
  const relay = { idpInitiatedRelayState: "https://sp.test/home", allowedRelayStates: ["https://sp.test/reports", "deep-link-2"] };

  it("no RelayState from the caller → the SP's default", async () => {
    const { browser } = await host(relay);
    await browser.signUp();
    expect((await readAutoPost(await browser.fetch(init()))).relayState).toBe("https://sp.test/home");
  });

  it("an allow-listed RelayState is passed through exactly", async () => {
    const { browser } = await host(relay);
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(init({ sp: "test-sp", RelayState: "https://sp.test/reports" })));
    expect(form.relayState).toBe("https://sp.test/reports");
  });

  it("any other RelayState is ignored (default used), including near-misses", async () => {
    const { browser } = await host(relay);
    await browser.signUp();
    for (const rs of ["https://evil.test/phish", "https://sp.test/reports/", "HTTPS://sp.test/reports", "https://sp.test/reports?x=1", ""]) {
      const form = await readAutoPost(await browser.fetch(init({ sp: "test-sp", RelayState: rs })));
      expect(form.relayState, rs).toBe("https://sp.test/home");
      expect(form.html).not.toContain("evil.test");
    }
  });

  it("with no default and no allow-list, a caller RelayState is dropped entirely", async () => {
    const { browser } = await host();
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(init({ sp: "test-sp", RelayState: "https://evil.test/phish" })));
    expect(form.relayState).toBeUndefined();
    expect(form.html).not.toContain("evil.test");
  });

  it("the chosen RelayState survives the login detour", async () => {
    const { browser } = await host(relay);
    const toLogin = await browser.fetch(init({ sp: "test-sp", RelayState: "deep-link-2" }));
    const resume = new URL(toLogin.headers.get("location")!).searchParams.get("callbackURL")!;
    await browser.signUp();
    expect((await readAutoPost(await browser.fetch(resume))).relayState).toBe("deep-link-2");
  });
});

describe("IdP-initiated SSO: policy still applies", () => {
  it("unverified email → EMAIL_NOT_VERIFIED, no Response", async () => {
    const { browser } = await host();
    await browser.signUp(undefined, { verified: false });
    const res = await browser.fetch(init());
    expect(res.status).toBe(403);
    expect(await pageCode(res)).toBe("EMAIL_NOT_VERIFIED");
    expect(await hasAssertion(res)).toBe(false);
  });

  it("authorize() denial → ACCESS_DENIED, no Response; it sees the SP", async () => {
    let seen: any;
    const { browser } = await host({ authorize: async (c: any) => {
        seen = c;
        return false;
      }, });
    await browser.signUp();
    const res = await browser.fetch(init());
    expect(res.status).toBe(403);
    expect(await pageCode(res)).toBe("ACCESS_DENIED");
    expect(await hasAssertion(res)).toBe(false);
    expect(seen.serviceProvider.id).toBe("test-sp");
  });

  it("a banned user is refused (R3 re-read)", async () => {
    const { browser, auth } = await host();
    const user = await browser.signUp();
    const ctx = await auth.$context;
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { banned: true } });
    const res = await browser.fetch(init());
    expect(res.status).toBe(403);
    expect(await pageCode(res)).toBe("ACCOUNT_INACTIVE");
  });
});

describe("IdP-initiated SSO: login-CSRF mitigation (Fetch Metadata)", () => {
  const nav = (site: string, user?: boolean) => ({
    headers: { "sec-fetch-site": site, "sec-fetch-mode": "navigate", ...(user ? { "sec-fetch-user": "?1" } : {}) },
  });

  it("a cross-site navigation without user activation gets a confirmation page, not a Response", async () => {
    const { browser } = await host({ allowedRelayStates: ["https://sp.test/reports"] });
    await browser.signUp();
    const res = await browser.fetch(init({ sp: "test-sp", RelayState: "https://sp.test/reports" }), nav("cross-site"));
    expect(res.status).toBe(200);
    expect(await hasAssertion(res)).toBe(false);
    const html = await res.text();
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    const href = /<a href="([^"]+)">Continue<\/a>/.exec(html)?.[1]?.replace(/&amp;/g, "&");
    expect(href).toBe(init({ sp: "test-sp", RelayState: "https://sp.test/reports" }));
    // Following the link is a same-origin, user-activated navigation: it signs in.
    const form = await readAutoPost(await browser.fetch(href!, nav("same-origin", true)));
    expect(form.action).toBe(SP_ACS);
    expect(form.relayState).toBe("https://sp.test/reports");
  });

  it("a user-activated cross-site click, a bookmark and a same-origin link all sign in directly", async () => {
    const { browser } = await host();
    await browser.signUp();
    for (const [site, user] of [["cross-site", true], ["none", true], ["same-origin", false], ["same-site", false]] as const)
      expect(await hasAssertion(await browser.fetch(init(), nav(site, user))), `${site}`).toBe(true);
  });
});

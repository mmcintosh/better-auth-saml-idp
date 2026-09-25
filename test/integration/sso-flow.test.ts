// Phase 2 gate: full SP-initiated round trip on the ADDENDUM-01 host (D1/Drizzle on workerd,
// node:sqlite on Node), verified by a strict samlify SP.
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { authnRequestXml, Browser, postBinding, readAutoPost, redirectUrl, strictSp, SSO_URL } from "../support/sp";

async function setup(saml = {}) {
  const { auth, database } = await createHost({
    saml: {
      serviceProviders: [
        {
          id: "test-sp",
          entityId: SP_ENTITY_ID,
          acsUrls: [SP_ACS, "https://sp.test/acs-alt"],
          attributes: (u) => ({ email: u.email, name: u.name, groups: ["staff", "a&b <c>"] }),
        },
      ],
      ...saml,
    },
  });
  return { auth, database, browser: new Browser(auth), verifier: await strictSp(auth) };
}

describe("SP-initiated SSO round trip", () => {
  it("SP → IdP → login → resume → SP validates the assertion", async () => {
    const { auth, browser, verifier } = await setup();
    const { id, xml } = authnRequestXml();

    // 1. SP redirects the browser to the IdP; no session yet.
    const r1 = await browser.fetch(await redirectUrl(xml, { relayState: "state-123" }));
    expect(r1.status).toBe(302);
    const login = new URL(r1.headers.get("location")!);
    expect(`${login.origin}${login.pathname}`).toBe("https://auth.test/sign-in");
    const callback = login.searchParams.get("callbackURL")!;
    expect(callback).toMatch(new RegExp(`^${AUTH_BASE}/saml2/idp/resume\\?rid=[A-Za-z0-9_-]{43}$`));

    // 2. User signs up / signs in on the host's login page.
    const user = await browser.signUp();

    // 3. Login page sends the browser back to the resume URL.
    const r3 = await browser.fetch(callback);
    expect(r3.status).toBe(200);
    const form = await readAutoPost(r3);
    expect(form.action).toBe(SP_ACS);
    expect(form.relayState).toBe("state-123");

    // 4. The strict SP accepts it.
    const parsed = await verifier.verify(form.samlResponse);
    expect(parsed.extract.nameID).toBe(user.email);
    expect(parsed.extract.response?.inResponseTo).toBe(id);
    expect(parsed.extract.audience).toBe(SP_ENTITY_ID);
    expect(parsed.extract.attributes).toMatchObject({ email: user.email, name: "Alice Example", groups: ["staff", "a&b <c>"] });

    // 5. Fields SPEC §6 step 7 requires, checked on the XML itself.
    const x = form.xml;
    expect(x).toContain(`Destination="${SP_ACS}"`);
    expect(x).toMatch(new RegExp(`<saml:SubjectConfirmationData NotOnOrAfter="[^"]+" Recipient="${SP_ACS}" InResponseTo="${id}"/>`));
    expect(x).toMatch(/<saml:AuthnStatement AuthnInstant="[^"]+" SessionIndex="_[A-Za-z0-9_-]{32}">/);
    void auth;
  });

  it("responds immediately when the user already has a session", async () => {
    const { browser, verifier } = await setup();
    const user = await browser.signUp();
    const { id, xml } = authnRequestXml();
    const res = await browser.fetch(await redirectUrl(xml));
    expect(res.status).toBe(200);
    const form = await readAutoPost(res);
    const parsed = await verifier.verify(form.samlResponse);
    expect(parsed.extract.nameID).toBe(user.email);
    expect(parsed.extract.response?.inResponseTo).toBe(id);
    expect(form.relayState).toBeUndefined();
  });

  it("accepts the HTTP-POST binding", async () => {
    const { browser, verifier } = await setup();
    await browser.signUp();
    const { id, xml } = authnRequestXml();
    // The SP's cross-site POST carries no session cookie: the IdP re-enters via a same-site GET
    // (303 → sso?cid=…), where the session is visible, and answers without the login page.
    const res = await postBinding(browser, xml, "rs");
    expect(res.status).toBe(200);
    const form = await readAutoPost(res);
    expect((await verifier.verify(form.samlResponse)).extract.response?.inResponseTo).toBe(id);
    expect(form.relayState).toBe("rs");
  });

  it("interoperates with a samlify-generated AuthnRequest (Redirect binding)", async () => {
    const { browser, verifier } = await setup();
    await browser.signUp();
    const { context } = verifier.sp.createLoginRequest(verifier.idp, "redirect") as { context: string };
    expect(context.startsWith(SSO_URL)).toBe(true);
    const res = await browser.fetch(context);
    expect(res.status).toBe(200);
    const form = await readAutoPost(res);
    const parsed = await verifier.verify(form.samlResponse);
    expect(parsed.extract.audience).toBe(SP_ENTITY_ID);
  });

  it("uses a requested ACS URL that is on the allow-list", async () => {
    const { browser, verifier } = await setup();
    await browser.signUp();
    const { xml } = authnRequestXml({ acsUrl: "https://sp.test/acs-alt" });
    const form = await readAutoPost(await browser.fetch(await redirectUrl(xml)));
    expect(form.action).toBe("https://sp.test/acs-alt");
    expect(form.xml).toContain(`Destination="https://sp.test/acs-alt"`);
    void verifier;
  });

  it("falls back to the first registered ACS URL when none is requested", async () => {
    const { browser } = await setup();
    await browser.signUp();
    const { xml } = authnRequestXml({ acsUrl: null });
    const form = await readAutoPost(await browser.fetch(await redirectUrl(xml)));
    expect(form.action).toBe(SP_ACS);
  });
});

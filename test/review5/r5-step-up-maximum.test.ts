// Fixed in D-048; kept as regression tests. Comments saying "today" describe fad67c2.
// Review 5 (D-047): Comparison="maximum" with a session already stronger than every listed class.
// Re-authentication can't lower the level a host's `current` reports (it reads user state, such as
// "2FA enabled"), so the sign-in round the IdP asks for is a dead end that ends in NoAuthnContext.
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const MFA = "https://refeds.org/profile/mfa";
const statusOf = (xml: string) => [...xml.matchAll(/StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:([A-Za-z]+)"/g)].map((m) => m[1]);

describe("R5-4: maximum below the achieved level", () => {
  it("an MFA session and Comparison=maximum PPT: no sign-in round should be demanded (it can't help); today the user is sent to sign in with acr_values=PPT", async () => {
    const { auth } = await createHost({
      saml: {
        serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }],
        authnContext: { levels: [PPT, MFA], current: () => MFA }, // every session of this host is MFA
      },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    const inner = `<samlp:RequestedAuthnContext Comparison="maximum"><saml:AuthnContextClassRef>${PPT}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`;
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ inner }).xml));
    expect(res.status).not.toBe(302);
    const { xml } = await readAutoPost(res);
    // Either answer in-protocol at once, or (arguably) issue with the achieved class; not a round trip.
    expect(statusOf(xml)[0]).toBeDefined();
  });
});

describe("R5-5: RequestedAuthnContext is bounded before it is stored", () => {
  const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
  const refs = (n: number, len = 20) => Array.from({ length: n }, (_, i) => `<saml:AuthnContextClassRef>urn:x:${String(i).padStart(len, "0")}</saml:AuthnContextClassRef>`).join("");
  it("at most 16 class refs of at most 1024 characters; more is INVALID_SAML_REQUEST", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }] } });
    const browser = new Browser(auth);
    await browser.signUp();
    const rac = (inner: string) => `<samlp:RequestedAuthnContext Comparison="exact">${inner}</samlp:RequestedAuthnContext>`;
    // 16 is fine (unsatisfiable here, so a SAML status, not a refusal of the request).
    const ok = await browser.fetch(await redirectUrl(authnRequestXml({ inner: rac(refs(16)) }).xml));
    expect(await code(ok)).toBeUndefined();
    expect(await code(await browser.fetch(await redirectUrl(authnRequestXml({ inner: rac(refs(17)) }).xml)))).toBe("INVALID_SAML_REQUEST");
    expect(await code(await browser.fetch(await redirectUrl(authnRequestXml({ inner: rac(refs(1, 1030)) }).xml)))).toBe("INVALID_SAML_REQUEST");
  });
});

// Second review 4 report, R4-6: SAML Bindings §3.4.5.2 and §3.5.5.2 require a signed message to carry `Destination`, and the
// receiver to check it; review 2 added that check for LogoutRequests and LogoutResponses
// (slo.ts "a signed LogoutRequest needs a Destination") but AuthnRequests still accept a signed
// request without one. A signed AuthnRequest captured on the way to another IdP that trusts the
// same SP key can then be replayed here (the request ID is fresh to this IdP) without the Destination
// check ever applying; nothing in the request ties it to this IdP.
import { describe, expect, inject, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, redirectUrl } from "../support/sp";

const keys = inject("keys");
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe("R4-6: signed AuthnRequests must state their Destination", () => {
  it("refuses a signed HTTP-Redirect AuthnRequest without Destination, as SLO already does", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], requireSignedAuthnRequests: true, spCertificate: keys.sp.certificate }] } });
    const browser = new Browser(auth);
    await browser.signUp();
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ destination: null }).xml, { sign: true }));
    expect(res.status).toBe(400); // today: 200 with an assertion
    expect(await code(res)).toBe("INVALID_SAML_REQUEST");
  });
});

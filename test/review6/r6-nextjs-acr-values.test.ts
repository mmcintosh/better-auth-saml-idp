// Review 6 (examples/nextjs): the example's README says its sign-in page, "when `acr_values` asks
// for a class other than password sign-in (for example MFA), says that this example can't deliver
// it. The IdP then answers the SP with NoAuthnContext." With the example's configuration
// (`authnContextClassRef: PASSWORD_CLASS`, no `authnContext.levels`), the IdP never sends a user
// to the login page with `acr_values`: an unsatisfiable RequestedAuthnContext is answered at the
// SSO endpoint, before any redirect. The page's acr_values branch can't be reached.
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, redirectUrl } from "../support/sp";

const PASSWORD_CLASS = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const MFA = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";

describe("R6-7: the Next.js example's acr_values handling is unreachable", () => {
  it("signed out, an SP asks for MFA: the README says the login page gets acr_values; it never does", async () => {
    const { auth } = await createHost({ saml: { authnContextClassRef: PASSWORD_CLASS, serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }] } });
    const inner = `<samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>${MFA}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`;
    const res = await new Browser(auth).fetch(await redirectUrl(authnRequestXml({ inner }).xml));
    // Today: a 200 auto-POST with NoAuthnContext, straight from the SSO endpoint.
    expect(res.status, "answered at the SSO endpoint; the login page never sees acr_values").toBe(302);
    expect(new URL(res.headers.get("location")!).searchParams.get("acr_values")).toBe(MFA);
  });
});

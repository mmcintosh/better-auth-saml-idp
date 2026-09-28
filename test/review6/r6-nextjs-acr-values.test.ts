// Fixed in D-053 by removing the dead branch and correcting the README, as the Workers example
// does (no step-up, no acr_values handling). This test now checks what the README says: with the
// example's configuration, an SP asking for MFA gets NoAuthnContext from the IdP itself, without
// the sign-in page; and the page no longer claims to handle acr_values. Comments saying "today"
// describe dac64f3.
// Review 6 (examples/nextjs): the example's README said its sign-in page, "when `acr_values` asks
// for a class other than password sign-in (for example MFA), says that this example can't deliver
// it. The IdP then answers the SP with NoAuthnContext." With the example's configuration
// (`authnContextClassRef: PASSWORD_CLASS`, no `authnContext.levels`), the IdP never sends a user
// to the login page with `acr_values`: an unsatisfiable RequestedAuthnContext is answered at the
// SSO endpoint, before any redirect. The page's acr_values branch couldn't be reached.
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const PASSWORD_CLASS = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const MFA = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";

describe("R6-7: the Next.js example and acr_values", () => {
  it("signed out, an SP asks for MFA: the IdP answers NoAuthnContext itself, without the sign-in page (as the README now says)", async () => {
    const { auth } = await createHost({ saml: { authnContextClassRef: PASSWORD_CLASS, serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }] } });
    const inner = `<samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>${MFA}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`;
    const res = await new Browser(auth).fetch(await redirectUrl(authnRequestXml({ inner }).xml));
    expect(res.status).toBe(200);
    expect((await readAutoPost(res)).xml).toContain("urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext");
  });

  it.skipIf(isWorkerd)("the sign-in page has no acr_values branch, and the README doesn't claim one", async () => {
    const { readFileSync } = await import("node:fs");
    const page = readFileSync(new URL("../../examples/nextjs/src/app/sign-in/page.tsx", import.meta.url), "utf8");
    expect(page).not.toMatch(/params\.get\("acr_values"\)/);
    const readme = readFileSync(new URL("../../examples/nextjs/README.md", import.meta.url), "utf8");
    expect(readme).not.toMatch(/when `acr_values` asks/);
    expect(readme).toMatch(/gets `NoAuthnContext` from the IdP straight away/);
  });
});

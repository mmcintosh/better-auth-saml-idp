// R3-3: /saml2/idp/sso enforces `relayStateMaxBytes` (default 1024, hard cap 1024), but
// /saml2/idp/slo never calls checkRelayState. An unauthenticated caller's RelayState of any size
// is accepted, written into the verification table (POST continuation, and once per hop in the
// logout state JSON) and echoed back in the LogoutResponse redirect.
import { createPrivateKey } from "node:crypto";
import { describe, expect, inject, it } from "vitest";
import { redirectBindingUrl } from "../../src/saml/logout";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { Browser } from "../support/sp";

const keys = inject("keys");
const SLO = `${AUTH_BASE}/saml2/idp/slo`;
const spSigning = (pem: string) => ({ signatureAlgorithm: "rsa-sha256", digestAlgorithm: "sha256", keyObject: createPrivateKey(pem), certificate: "" }) as any;
const iso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe("Single Logout: RelayState size", () => {
  it("refuses a RelayState over relayStateMaxBytes, as the SSO endpoint does", async () => {
    const { auth } = await createHost({
      saml: {
        singleLogout: { enabled: true },
        serviceProviders: [{ id: "sp-a", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], spCertificate: keys.sp.certificate, singleLogoutService: { url: "https://sp.test/slo" } }],
      },
    });
    const browser = new Browser(auth); // no session at all: unauthenticated caller
    const xml =
      `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr1" Version="2.0" IssueInstant="${iso()}" Destination="${SLO}">` +
      `<saml:Issuer>${SP_ENTITY_ID}</saml:Issuer><saml:NameID>x@example.com</saml:NameID><samlp:SessionIndex>_x</samlp:SessionIndex></samlp:LogoutRequest>`;
    const huge = "r".repeat(100 * 1024);
    const res = await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", xml, huge, spSigning(keys.sp.privateKey)));
    expect(res.status).toBe(400);
    expect(await code(res)).toBe("RELAY_STATE_TOO_LONG");
  });
});

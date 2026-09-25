// R3-7: serviceProviderFromMetadata() takes `ResponseLocation || Location` as the SP's SLO URL.
// SAML Metadata §2.2.2: ResponseLocation is where *responses* go; requests go to Location. The
// plugin sends its LogoutRequests to singleLogoutService.url, so an SP that publishes both gets
// LogoutRequests at its response-only endpoint, which SPs typically ignore: the chain stalls and
// the user stays logged in at that SP.
import { describe, expect, it } from "vitest";
import { serviceProviderFromMetadata } from "../../src/saml/sp-metadata";
import { libxml2Validator } from "../../src/saml/validator";

describe("sp-from-metadata: SingleLogoutService", () => {
  it("uses Location (where LogoutRequests go), not ResponseLocation", async () => {
    const xml =
      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.test/metadata">` +
      `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
      `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.test/slo" ResponseLocation="https://sp.test/slo-response"/>` +
      `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.test/acs" index="0"/>` +
      `</md:SPSSODescriptor></md:EntityDescriptor>`;
    const r = await serviceProviderFromMetadata(xml, { id: "sp" }, { schemaValidator: libxml2Validator() });
    expect(r.serviceProvider.singleLogoutService?.url).toBe("https://sp.test/slo");
  });
});

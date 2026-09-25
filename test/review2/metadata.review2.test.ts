// Second adversarial review: SP metadata (D-026 refresh cache, D-028 SLO import) proofs of concept.
// Every `it` asserts the SECURE / spec behaviour; a failing test proves the finding.
import { SignedXml } from "xml-crypto";
import { afterEach, describe, expect, inject, it, vi } from "vitest";
import { resolveOptions, resolveStoredServiceProvider } from "../../src/options";
import { SpMetadataCache } from "../../src/saml/sp-metadata-refresh";
import { serviceProviderFromMetadata } from "../../src/saml/sp-metadata";
import { libxml2Validator } from "../../src/saml/validator";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";

const keys = inject("keys");
const MD_URL = "https://sp.test/saml/metadata.xml";
const body = (pem: string) => pem.replace(/-----[^-]+-----|\s+/g, "");
const kd = (pem: string, use: string) =>
  `<md:KeyDescriptor use="${use}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${body(pem)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;

function metadata(o: { signing: string[]; signWith?: string; slo?: string }) {
  const xml =
    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_md" entityID="${SP_ENTITY_ID}">` +
    `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
    o.signing.map((c) => kd(c, "signing")).join("") +
    (o.slo ?? "") +
    `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${SP_ACS}" index="0"/>` +
    `</md:SPSSODescriptor></md:EntityDescriptor>`;
  if (!o.signWith) return xml;
  const exc = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const sig = new SignedXml({ privateKey: o.signWith, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: exc });
  sig.addReference({ xpath: "/*", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", exc], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  sig.computeSignature(xml, { prefix: "ds", location: { reference: "/*", action: "prepend" } });
  return sig.getSignedXml();
}

afterEach(() => vi.unstubAllGlobals());

const log = { info: () => {}, warn: () => {} };

describe("review2 metadata", () => {
  it("R2-MD-1: changing an SP's metadata signing pin drops certificates learned under the old pin", async () => {
    const options = resolveOptions(baseOptions({ registry: { enabled: true } } as any));
    const stored = (pin: string) => {
      const r = resolveStoredServiceProvider(
        { id: "db-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], requireSignedAuthnRequests: true, metadata: { url: MD_URL, signingCertificate: pin } },
        options,
      );
      if (!r.serviceProvider) throw new Error(r.issues.join("; "));
      return r.serviceProvider;
    };
    // The metadata signing key idpNext is compromised: the attacker publishes metadata signed with
    // it that lists the attacker's own request-signing certificate (here keys.idp's).
    vi.stubGlobal("fetch", async () => new Response(metadata({ signing: [keys.idp.certificate], signWith: keys.idpNext.privateKey })));
    const cache = new SpMetadataCache(libxml2Validator());
    const before = await cache.prepare(stored(keys.idpNext.certificate), log, () => {});
    expect(before.spCertificates).toContain(keys.idp.certificate);
    // The admin reacts: re-pins the metadata signature to the SP's new key (keys.sp), same URL.
    const after = await cache.prepare(stored(keys.sp.certificate), log, () => {});
    // Secure: nothing learned under the revoked pin is trusted any more (up to refreshSeconds, default 24 h).
    expect(after.spCertificates, "attacker certificate learned under the old pin is still trusted").not.toContain(keys.idp.certificate);
  });

  it("R2-MD-2: SingleLogoutService Location (not ResponseLocation) is where LogoutRequests go", async () => {
    const slo =
      `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.test/slo/request" ResponseLocation="https://sp.test/slo/response"/>`;
    const r = await serviceProviderFromMetadata(metadata({ signing: [keys.sp.certificate], slo }), { id: "x" });
    // The IdP sends LogoutRequests to singleLogoutService.url (nextHop) AND LogoutResponses (finish);
    // Metadata §2.2.2: ResponseLocation is for responses only.
    expect(r.serviceProvider.singleLogoutService?.url).toBe("https://sp.test/slo/request");
  });
});

// R4-4 (Medium, availability): a schema-valid 64 KiB signed AuthnRequest made signature
// verification cost ~200 ms per configured SP certificate. Protocol messages are now capped at
// MAX_MESSAGE_ELEMENTS / MAX_MESSAGE_ATTRIBUTES right after parsing, before any signature work.
import { generateKeyPairSync } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { SignedXml } from "xml-crypto";
import { MAX_MESSAGE_ATTRIBUTES, MAX_MESSAGE_ELEMENTS, MAX_REQUEST_BYTES, parseAuthnRequest, SamlRequestError } from "../../src/saml/request";
import { libxml2Validator } from "../../src/saml/validator";

const validator = libxml2Validator();
const NS = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const now = new Date("2026-09-26T00:00:30Z");
const opts = { now, clockSkewSeconds: 60, ssoUrl: "https://idp.test/sso" };
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

const authn = (rootExtra: string, inner: string) =>
  `<samlp:AuthnRequest ${NS} ID="_abc" Version="2.0" IssueInstant="2026-09-26T00:00:00Z" Destination="https://idp.test/sso" AssertionConsumerServiceURL="https://sp.test/acs"${rootExtra}><saml:Issuer>https://sp.test/metadata</saml:Issuer>${inner}</samlp:AuthnRequest>`;

function signRoot(xml: string) {
  const sig = new SignedXml({ privateKey: privPem, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" });
  sig.addReference({ xpath: "/*", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  sig.computeSignature(xml, { prefix: "ds", location: { reference: "/*/*[local-name(.)='Issuer']", action: "after" } });
  return sig.getSignedXml();
}

// The reviewer's shapes: every one schema-valid and under the 64 KiB cap.
const shapes: Record<string, string> = {
  "3000 namespace declarations + 900 elements": authn(
    Array.from({ length: 3000 }, (_, i) => ` xmlns:n${i}="u"`).join(""),
    `<samlp:Extensions><x:w xmlns:x="urn:x">${Array.from({ length: 900 }, () => `<x:e xmlns:z="u"/>`).join("")}</x:w></samlp:Extensions>`,
  ),
  "7000 attributes on one element": authn("", `<samlp:Extensions><x:w xmlns:x="urn:x"${Array.from({ length: 7000 }, (_, i) => ` a${i}=""`).join("")}/></samlp:Extensions>`),
  "2000 elements carrying ID attributes": authn("", `<samlp:Extensions><x:w xmlns:x="urn:x">${Array.from({ length: 2000 }, (_, i) => `<x:e ID="_i${i}"/>`).join("")}</x:w></samlp:Extensions>`),
};

describe("R4-4: protocol messages are capped in elements and attributes before signature work", () => {
  beforeAll(() => validator.validate("<a/>", "protocol")); // compile the wasm once, outside the timings

  for (const [name, body] of Object.entries(shapes))
    it(`${name}: refused while parsing, quickly`, async () => {
      const xml = signRoot(body);
      expect(new TextEncoder().encode(xml).byteLength).toBeLessThanOrEqual(MAX_REQUEST_BYTES);
      const t = performance.now();
      const err = await parseAuthnRequest(xml, validator, opts).catch((e) => e);
      expect(err).toBeInstanceOf(SamlRequestError);
      expect((err as Error).message).toMatch(/more than \d+ (elements|attributes)/);
      expect(performance.now() - t).toBeLessThan(500);
    });

  it("a real signed AuthnRequest, with Extensions, is far inside the caps", async () => {
    const xml = signRoot(authn("", `<samlp:Extensions><x:w xmlns:x="urn:x"><x:e a="1"/><x:e a="2"/></x:w></samlp:Extensions><samlp:NameIDPolicy AllowCreate="true"/>`));
    const info = await parseAuthnRequest(xml, validator, opts);
    expect(info.id).toBe("_abc");
  });

  it("the caps are generous next to real messages (about 15 elements)", () => {
    expect(MAX_MESSAGE_ELEMENTS).toBeGreaterThanOrEqual(100);
    expect(MAX_MESSAGE_ATTRIBUTES).toBeGreaterThanOrEqual(500);
  });
});

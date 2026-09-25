// The XSW rules in verifyEnvelopedSignature, each on its own (no XSD check in front of it).
import { SignedXml } from "xml-crypto";
import { describe, expect, inject, it } from "vitest";
import { parseXmlStrict } from "../../src/saml/xml";
import { verifyEnvelopedSignature } from "../../src/saml/xmldsig";

const keys = inject("keys");
const EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";

function signed(id = "_a", o: { c14n?: string } = {}) {
  const xml = `<r:Root xmlns:r="urn:r" ID="${id}"><r:Issuer>sp</r:Issuer><r:Body>hello</r:Body></r:Root>`;
  const sig = new SignedXml({ privateKey: keys.sp.privateKey, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: o.c14n ?? EXC });
  sig.addReference({ xpath: "/*", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", o.c14n ?? EXC], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  sig.computeSignature(xml, { location: { reference: "/*/*[local-name(.)='Issuer']", action: "after" } });
  return sig.getSignedXml();
}
const sigOf = (xml: string) => /<Signature[\s\S]*<\/Signature>/.exec(xml)![0];
const check = (xml: string, certs = [keys.sp.certificate], allowSha1 = false) => {
  const doc = parseXmlStrict(xml);
  return verifyEnvelopedSignature(xml, doc, doc.documentElement, certs, { allowSha1 });
};

describe("verifyEnvelopedSignature", () => {
  it("verifies a well-formed enveloped signature, and reports which certificate", () => {
    expect(check(signed(), [keys.idpNext.certificate, keys.sp.certificate])).toMatchObject({ present: true, valid: true, certIndex: 1, algorithm: "rsa-sha256", digest: "sha256" });
  });

  it("no certificate: structurally fine but unverified", () => {
    expect(check(signed(), [])).toMatchObject({ present: true, valid: undefined });
  });

  it("unsigned: present false", () => {
    expect(check(`<r:Root xmlns:r="urn:r" ID="_a"/>`)).toEqual({ present: false, valid: undefined });
  });

  it("duplicated ID on another element (ID, Id or id): refused", () => {
    for (const attr of ["ID", "Id", "id"]) {
      const xml = signed().replace("<r:Body>", `<r:Body><r:Copy ${attr}="_a"/>`);
      const r = check(xml);
      expect(r.valid, attr).toBe(false);
      expect(r.problem).toMatch(/appears on 2 elements/);
    }
  });

  it("wrapping: the Reference points at a nested copy, not the element being processed", () => {
    const inner = signed("_inner");
    const attack = `<r:Root xmlns:r="urn:r" ID="_outer"><r:Issuer>sp</r:Issuer>${sigOf(inner)}<r:Body>evil</r:Body><r:W>${inner.replace(sigOf(inner), "")}</r:W></r:Root>`;
    const r = check(attack);
    expect(r.valid).toBe(false);
    expect(r.problem).toMatch(/does not point at the signed element/);
  });

  it("two signatures on the element: refused", () => {
    const xml = signed();
    expect(check(xml.replace(sigOf(xml), sigOf(xml) + sigOf(xml))).problem).toMatch(/2 Signature elements/);
  });

  it("WithComments canonicalization: refused even though the signature is cryptographically valid", () => {
    const r = check(signed("_a", { c14n: "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" }));
    expect(r.valid).toBe(false);
    expect(r.problem).toMatch(/canonicalization .* is not allowed/);
  });

  it("an XPath transform: refused", () => {
    const xml = signed().replace(
      /(<Transforms>)/,
      '$1<Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><XPath>1</XPath></Transform>',
    );
    expect(check(xml).problem).toMatch(/transform .* is not allowed/);
  });

  it("the signature is only checked against the given certificates, never KeyInfo", () => {
    const sig = new SignedXml({ privateKey: keys.idpNext.privateKey, publicCert: keys.idpNext.certificate, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: EXC });
    sig.getKeyInfoContent = SignedXml.getKeyInfoContent;
    sig.addReference({ xpath: "/*", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", EXC], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
    sig.computeSignature(`<r:Root xmlns:r="urn:r" ID="_a"><r:Issuer>sp</r:Issuer></r:Root>`, { location: { reference: "/*/*[local-name(.)='Issuer']", action: "after" } });
    const xml = sig.getSignedXml();
    expect(xml).toMatch(/X509Certificate/);
    expect(check(xml).valid).toBe(false);
  });

  it("a Signature that isn't a direct child isn't this element's signature", () => {
    const xml = signed();
    const moved = xml.replace(sigOf(xml), "").replace("<r:Body>", `<r:Body>${sigOf(xml)}`);
    expect(check(moved)).toEqual({ present: false, valid: undefined });
  });
});

// Signed AuthnRequests over HTTP-POST (D-025): enveloped XML signatures, with the XSW rules in
// src/saml/xmldsig.ts. Each attack below is stopped by one specific rule; see the mutation notes
// in DECISIONS.md D-025.
import { SAML } from "@node-saml/node-saml";
import { SignedXml } from "xml-crypto";
import { describe, expect, inject, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost, type HostOptions } from "../support/host";
import { authnRequestXml, Browser, postBinding, readAutoPost, SSO_URL } from "../support/sp";

const keys = inject("keys");
const ALG = {
  sha256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  sha1: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  d256: "http://www.w3.org/2001/04/xmlenc#sha256",
  d1: "http://www.w3.org/2000/09/xmldsig#sha1",
  exc: "http://www.w3.org/2001/10/xml-exc-c14n#",
  excComments: "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
  enveloped: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
};

function sign(
  xml: string,
  o: { key?: string; cert?: string; sigAlg?: string; digest?: string; c14n?: string; keyInfo?: boolean } = {},
): string {
  const sig = new SignedXml({
    privateKey: o.key ?? keys.sp.privateKey,
    publicCert: o.cert ?? keys.sp.certificate,
    signatureAlgorithm: o.sigAlg ?? ALG.sha256,
    canonicalizationAlgorithm: o.c14n ?? ALG.exc,
  });
  // Embed the signer's certificate in KeyInfo, as many SPs do (the IdP must ignore it).
  if (o.keyInfo) sig.getKeyInfoContent = SignedXml.getKeyInfoContent;
  sig.addReference({ xpath: "/*[local-name(.)='AuthnRequest']", transforms: [ALG.enveloped, o.c14n ?? ALG.exc], digestAlgorithm: o.digest ?? ALG.d256 });
  sig.computeSignature(xml, { location: { reference: "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']", action: "after" } });
  return sig.getSignedXml();
}

const signatureOf = (xml: string) => /<(ds:)?Signature[\s>][\s\S]*<\/(ds:)?Signature>/.exec(xml)![0];

async function host(sp: Record<string, unknown> = {}, saml: HostOptions["saml"] = {}) {
  const { auth } = await createHost({
    saml: {
      ...saml,
      serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], requireSignedAuthnRequests: true, spCertificate: keys.sp.certificate, ...sp }],
    },
  });
  const browser = new Browser(auth);
  await browser.signUp();
  return browser;
}

const pageCode = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
async function expectRejected(res: Response) {
  expect(res.status).toBe(400);
  expect(await pageCode(res)).toBe("UNSIGNED_SAML_REQUEST");
}
/** Refused by the XSD check (INVALID_SAML_REQUEST) or the signature check; both are fine. */
async function expectRefused(res: Response) {
  expect(res.status).toBe(400);
  expect(["INVALID_SAML_REQUEST", "UNSIGNED_SAML_REQUEST"]).toContain(await pageCode(res));
}
async function expectAccepted(res: Response) {
  expect(res.status).toBe(200);
  expect((await readAutoPost(res)).xml).toMatch(/StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/);
}

describe("signed AuthnRequests over HTTP-POST", () => {
  it("accepts a correctly signed request when signatures are required", async () => {
    const browser = await host();
    await expectAccepted(await postBinding(browser, sign(authnRequestXml().xml)));
  });

  it("accepts rsa-sha512", async () => {
    const browser = await host();
    await expectAccepted(await postBinding(browser, sign(authnRequestXml().xml, { sigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", digest: "http://www.w3.org/2001/04/xmlenc#sha512" })));
  });

  it("interop: node-saml's signed POST AuthnRequest is accepted", async () => {
    const browser = await host();
    const saml = new SAML({
      issuer: SP_ENTITY_ID,
      callbackUrl: SP_ACS,
      entryPoint: SSO_URL,
      idpCert: keys.idp.certificate,
      authnRequestBinding: "HTTP-POST",
      privateKey: keys.sp.privateKey,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
      disableRequestedAuthnContext: true,
    });
    const html = await saml.getAuthorizeFormAsync("rs", undefined, {});
    const samlRequest = /name="SAMLRequest" value="([^"]+)"/.exec(html)![1]!;
    const res = await browser.follow(
      await browser.fetch(SSO_URL, {
        method: "POST",
        crossSite: true,
        headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://sp.test" },
        body: new URLSearchParams({ SAMLRequest: samlRequest, RelayState: "rs" }).toString(),
      }),
    );
    await expectAccepted(res);
  });

  it("rejects an unsigned request when signatures are required", async () => {
    await expectRejected(await postBinding(await host(), authnRequestXml().xml));
  });

  it("rejects a request altered after signing", async () => {
    const signed = sign(authnRequestXml().xml);
    await expectRejected(await postBinding(await host(), signed.replace("<samlp:AuthnRequest ", '<samlp:AuthnRequest ForceAuthn="true" ')));
  });

  it("rejects a signature by a key that isn't configured, even with its certificate in KeyInfo", async () => {
    const signed = sign(authnRequestXml().xml, { key: keys.idpNext.privateKey, cert: keys.idpNext.certificate, keyInfo: true });
    expect(signed).toContain("X509Certificate>");
    await expectRejected(await postBinding(await host(), signed));
  });

  it("rejects SHA-1 unless the IdP opts in", async () => {
    const signed = sign(authnRequestXml().xml, { sigAlg: ALG.sha1, digest: ALG.d1 });
    await expectRejected(await postBinding(await host(), signed));
    const lenient = await host({}, { signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate, allowInsecureSha1: true } });
    await expectAccepted(await postBinding(lenient, sign(authnRequestXml().xml, { sigAlg: ALG.sha1, digest: ALG.d1 })));
  });

  it("XSW: a signature over a request wrapped in Extensions doesn't cover the outer request", async () => {
    const original = sign(authnRequestXml({ id: "_original" }).xml);
    const inner = original.replace(signatureOf(original), "");
    const attack = authnRequestXml({ id: "_attacker", forceAuthn: true }).xml.replace(
      "</saml:Issuer>",
      `</saml:Issuer>${signatureOf(original)}<samlp:Extensions><x:w xmlns:x="urn:x">${inner}</x:w></samlp:Extensions>`,
    );
    await expectRejected(await postBinding(await host(), attack));
  });

  it("XSW: the signed request's ID duplicated on another element", async () => {
    const original = sign(authnRequestXml({ id: "_dup" }).xml);
    const inner = original.replace(signatureOf(original), "");
    const attack = authnRequestXml({ id: "_dup", forceAuthn: true }).xml.replace(
      "</saml:Issuer>",
      `</saml:Issuer>${signatureOf(original)}<samlp:Extensions><x:w xmlns:x="urn:x">${inner}</x:w></samlp:Extensions>`,
    );
    // The schema's xs:ID uniqueness refuses this first; test/unit/xmldsig.test.ts covers our own check.
    await expectRefused(await postBinding(await host(), attack));
  });

  it("rejects a comment inserted into signed text (invisible to exclusive c14n)", async () => {
    const signed = sign(authnRequestXml().xml);
    const commented = signed.replace(`<saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>`, `<saml:Issuer>${SP_ENTITY_ID.slice(0, 12)}<!---->${SP_ENTITY_ID.slice(12)}</saml:Issuer>`);
    expect(commented).toContain("<!---->");
    await expectRejected(await postBinding(await host(), commented));
  });

  it("rejects canonicalization algorithms off the allow-list (WithComments)", async () => {
    await expectRejected(await postBinding(await host(), sign(authnRequestXml().xml, { c14n: ALG.excComments })));
  });

  it("rejects two signatures", async () => {
    const signed = sign(authnRequestXml().xml);
    // The schema (one ds:Signature at most) refuses this first; see test/unit/xmldsig.test.ts.
    await expectRefused(await postBinding(await host(), signed.replace(signatureOf(signed), signatureOf(signed) + signatureOf(signed))));
  });

  it("not required: a valid signature is fine, an invalid one is still rejected, and without SP certificates it's ignored", async () => {
    const optional = await host({ requireSignedAuthnRequests: false });
    await expectAccepted(await postBinding(optional, sign(authnRequestXml().xml)));
    await expectRejected(await postBinding(optional, sign(authnRequestXml().xml, { key: keys.idpNext.privateKey, cert: keys.idpNext.certificate })));
    const noCerts = await host({ requireSignedAuthnRequests: false, spCertificate: undefined });
    await expectAccepted(await postBinding(noCerts, sign(authnRequestXml().xml, { key: keys.idpNext.privateKey })));
  });

  it("the SP's rotation: any configured certificate may have signed", async () => {
    const browser = await host({ spCertificate: [keys.idpNext.certificate, keys.sp.certificate] });
    await expectAccepted(await postBinding(browser, sign(authnRequestXml().xml)));
  });
});

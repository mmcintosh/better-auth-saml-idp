// Phase 0 runtime spike: samlify IdP issues a signed Response for a hard-coded
// user, samlify SP (strict) verifies it. Runs identically under Node and workerd.
import { beforeAll, describe, expect, inject, it } from "vitest";
import * as samlify from "samlify";
import * as xmllintValidator from "@authenio/samlify-node-xmllint";

const IDP_ENTITY = "https://idp.test/saml2/idp";
const SP_ENTITY = "https://sp.test/metadata";
const ACS = "https://sp.test/acs";

const keys = inject("keys");

let idp: ReturnType<typeof samlify.IdentityProvider>;
let sp: ReturnType<typeof samlify.ServiceProvider>;

beforeAll(() => {
  samlify.setSchemaValidator(xmllintValidator);
  idp = samlify.IdentityProvider({
    entityID: IDP_ENTITY,
    privateKey: keys.idp.privateKey,
    signingCert: keys.idp.certificate,
    isAssertionEncrypted: false,
    wantAuthnRequestsSigned: false,
    requestSignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    singleSignOnService: [
      { Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://idp.test/sso" },
    ],
    nameIDFormat: ["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"],
  });
  sp = samlify.ServiceProvider({
    entityID: SP_ENTITY,
    authnRequestsSigned: false,
    wantAssertionsSigned: true,
    wantMessageSigned: true,
    signingCert: keys.sp.certificate,
    assertionConsumerService: [
      { Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: ACS },
    ],
  });
});

async function issue() {
  const { context: redirectUrl } = sp.createLoginRequest(idp, "redirect") as { context: string };
  const url = new URL(redirectUrl);
  const req = await idp.parseLoginRequest(sp, "redirect", {
    query: Object.fromEntries(url.searchParams),
    octetString: url.search.slice(1),
  });
  const res = (await idp.createLoginResponse(sp, req, "post", { email: "alice@example.com" })) as {
    context: string;
  };
  return { requestId: req.extract.request.id as string, samlResponse: res.context };
}

describe(`phase 0 spike (${typeof navigator !== "undefined" ? navigator.userAgent : "node"})`, () => {
  it("round-trips a signed response through a strict SP", async () => {
    const t0 = performance.now();
    const { requestId, samlResponse } = await issue();
    const parsed = await sp.parseLoginResponse(idp, "post", { body: { SAMLResponse: samlResponse } });
    console.log(`round trip ms: ${(performance.now() - t0).toFixed(1)}`);

    expect(parsed.extract.nameID).toBe("alice@example.com");
    expect(parsed.extract.response.inResponseTo).toBe(requestId);
    expect(parsed.extract.audience).toBe(SP_ENTITY);

    const xml = atob(samlResponse);
    expect(xml).toContain('Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"');
    expect(xml).toContain('Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"');
  });

  it("SP rejects a response whose NameID was tampered with (signature really verified)", async () => {
    const { samlResponse } = await issue();
    const tampered = btoa(atob(samlResponse).replace("alice@example.com", "mallory@example.com"));
    await expect(
      sp.parseLoginResponse(idp, "post", { body: { SAMLResponse: tampered } }),
    ).rejects.toSatisfy((e: unknown) => { console.log("tamper rejection:", String(e)); return /SIGNATURE|ERR_/.test(String(e)); });
  });

  it("schema validator accepts a valid response and rejects a schema-invalid one", async () => {
    const { samlResponse } = await issue();
    const xml = atob(samlResponse);
    const t0 = performance.now();
    await expect(xmllintValidator.validate(xml)).resolves.toBe("SUCCESS_VALIDATE_XML");
    console.log(`validate ms: ${(performance.now() - t0).toFixed(1)}`);

    // Well-formed XML, but violates the protocol XSD (unknown child element in Response).
    const invalid = xml.replace("<saml:Issuer", "<samlp:Bogus/><saml:Issuer");
    await expect(xmllintValidator.validate(invalid)).rejects.toBe("ERR_EXCEPTION_VALIDATE_XML");
  });
});

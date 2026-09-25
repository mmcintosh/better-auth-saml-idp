// Encrypted assertions (D-020), end to end: independent SP libraries decrypt our
// EncryptedAssertion with the SP's private key and then validate it as usual.
//  - @node-saml/node-saml (decrypts with `xml-encryption`), strict settings
//  - samlify (decrypts with `@authenio/xml-encryption`), strict schema + signature checks
// The IdP runs on the ADDENDUM-01 host (workerd: withCloudflare + D1/Drizzle; node: node:sqlite).
import { constants, privateDecrypt, publicEncrypt } from "node:crypto";
import { SAML } from "@node-saml/node-saml";
import { describe, expect, inject, it } from "vitest";
import type { SamlIdpOptions, ServiceProviderConfig } from "../../src/types";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl, SSO_URL, strictSp } from "../support/sp";

const keys = inject("keys");

const NS_ISSUER = "https://node-saml.test/sp";
const NS_ACS = "https://node-saml.test/acs";

type Encryption = Omit<NonNullable<ServiceProviderConfig["encryption"]>, "certificate">;

/** An IdP with two SPs (node-saml and the samlify test SP), both encrypting to keys.sp. */
async function idp(encryption: Encryption = {}, saml: Partial<SamlIdpOptions> = {}) {
  const enc = { certificate: keys.sp.certificate, ...encryption };
  return createHost({
    saml: {
      // Password sign-in over TLS; node-saml requests exactly this class by default.
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      ...saml,
      serviceProviders: [
        { id: "node-saml", entityId: NS_ISSUER, acsUrls: [NS_ACS], attributes: (u) => ({ email: u.email, name: u.name }), encryption: enc },
        {
          id: "samlify",
          entityId: SP_ENTITY_ID,
          acsUrls: [SP_ACS],
          attributes: (u) => ({ email: u.email, name: u.name, groups: ["staff", "a&b <c>"] }),
          encryption: enc,
        },
      ],
    },
  });
}

const nodeSaml = (opts: { decryptionPvk?: string; wantAuthnResponseSigned?: boolean } = {}) =>
  new SAML({
    issuer: NS_ISSUER,
    callbackUrl: NS_ACS,
    entryPoint: SSO_URL,
    idpCert: keys.idp.certificate,
    audience: NS_ISSUER,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: opts.wantAuthnResponseSigned ?? true,
    validateInResponseTo: "always" as any,
    acceptedClockSkewMs: 60_000,
    signatureAlgorithm: "sha256",
    ...("decryptionPvk" in opts ? (opts.decryptionPvk ? { decryptionPvk: opts.decryptionPvk } : {}) : { decryptionPvk: keys.sp.privateKey }),
  });

async function nodeSamlForm(auth: Awaited<ReturnType<typeof idp>>["auth"], sp: SAML) {
  const browser = new Browser(auth);
  const user = await browser.signUp();
  const res = await browser.fetch(await sp.getAuthorizeUrlAsync("ns-relay", undefined, {}));
  expect(res.status).toBe(200);
  return { user, form: await readAutoPost(res) };
}

async function samlifyForm(auth: Awaited<ReturnType<typeof idp>>["auth"]) {
  const browser = new Browser(auth);
  const user = await browser.signUp();
  const { id, xml } = authnRequestXml();
  const res = await browser.fetch(await redirectUrl(xml));
  expect(res.status).toBe(200);
  return { user, id, form: await readAutoPost(res) };
}

/** Nothing from inside the assertion may be readable in the posted Response. */
function expectNoPlaintext(xml: string, user: { email: string }) {
  for (const secret of [user.email, "Alice Example", "staff", "a&amp;b", "<saml:Assertion", "<saml:NameID", "<saml:Subject", "<saml:AttributeStatement", "SessionIndex"])
    expect(xml).not.toContain(secret);
  expect(xml).toMatch(/<saml:EncryptedAssertion><xenc:EncryptedData [^>]*Type="http:\/\/www\.w3\.org\/2001\/04\/xmlenc#Element">/);
}

describe("interop: @node-saml/node-saml decrypts our encrypted assertions", () => {
  it("AES-256-GCM + RSA-OAEP (default): decrypts, verifies both signatures, and InResponseTo", async () => {
    const { auth } = await idp();
    const sp = nodeSaml();
    const { user, form } = await nodeSamlForm(auth, sp);
    expect(form.xml).toContain(`Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"`);
    expect(form.xml).toContain(`Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"`);
    expectNoPlaintext(form.xml, user);
    const { profile, loggedOut } = await sp.validatePostResponseAsync({ SAMLResponse: form.samlResponse });
    expect(loggedOut).toBe(false);
    expect(profile?.nameID).toBe(user.email);
    expect(profile?.issuer).toBe("https://auth.test/api/auth/saml2/idp");
    expect(profile?.email).toBe(user.email);
    expect(profile?.name).toBe("Alice Example");
  });

  it.each([
    ["aes128-gcm", {}],
    ["aes256-cbc", { allowInsecureCbc: true }],
  ] as const)("%s + RSA-OAEP: decrypts and validates", async (dataAlgorithm, extra) => {
    const { auth } = await idp({ dataAlgorithm, ...extra });
    const sp = nodeSaml();
    const { user, form } = await nodeSamlForm(auth, sp);
    expectNoPlaintext(form.xml, user);
    const { profile } = await sp.validatePostResponseAsync({ SAMLResponse: form.samlResponse });
    expect(profile?.nameID).toBe(user.email);
  });

  it("signResponse: false — the assertion signature is verified after decryption", async () => {
    const { auth } = await idp({}, { signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate, signResponse: false } });
    const sp = nodeSaml({ wantAuthnResponseSigned: false });
    const { user, form } = await nodeSamlForm(auth, sp);
    // No Response signature, and the assertion's signature is inside the ciphertext.
    expect(form.xml).not.toContain("<ds:Signature");
    const { profile } = await sp.validatePostResponseAsync({ SAMLResponse: form.samlResponse });
    expect(profile?.nameID).toBe(user.email);
  });

  it("rsa-oaep-sha256 (xmlenc11#rsa-oaep) is NOT supported by node-saml's xml-encryption: it refuses, as expected", async () => {
    const { auth } = await idp({ keyAlgorithm: "rsa-oaep-sha256" });
    const sp = nodeSaml();
    const { form } = await nodeSamlForm(auth, sp);
    await expect(sp.validatePostResponseAsync({ SAMLResponse: form.samlResponse })).rejects.toThrow(
      "key encryption algorithm http://www.w3.org/2009/xmlenc11#rsa-oaep not supported",
    );
  });

  it("a wrong SP private key can't decrypt; a missing one is refused", async () => {
    const { auth } = await idp();
    const wrong = nodeSaml({ decryptionPvk: keys.idpNext.privateKey });
    const { form } = await nodeSamlForm(auth, wrong);
    await expect(wrong.validatePostResponseAsync({ SAMLResponse: form.samlResponse })).rejects.toThrow();
    const none = nodeSaml({ decryptionPvk: undefined });
    const second = await nodeSamlForm(auth, none);
    await expect(none.validatePostResponseAsync({ SAMLResponse: second.form.samlResponse })).rejects.toThrow(/No decryption key/);
  });
});

const spOpts = () => ({ encPrivateKey: keys.sp.privateKey, encryptCert: keys.sp.certificate });

// samlify's decryptor (@authenio/xml-encryption 2.0.2) calls privateDecrypt with OAEP padding but
// no `oaepHash`. Node defaults that to SHA-1; workerd's nodejs_compat fails instead ("Failed to
// cipher/decipher"), so samlify can't decrypt *any* RSA-OAEP EncryptedKey on workerd. That's an
// SP-side runtime gap, not our output: node-saml (which passes oaepHash) decrypts on workerd.
describe.skipIf(isWorkerd)("interop: samlify decrypts our encrypted assertions (Node)", () => {
  it("AES-256-GCM + RSA-OAEP (default): schema-valid, decrypts, extracts NameID and attributes", async () => {
    const { auth } = await idp();
    const verifier = await strictSp(auth, spOpts());
    const { user, id, form } = await samlifyForm(auth);
    expectNoPlaintext(form.xml, user);
    const parsed = await verifier.verify(form.samlResponse);
    expect(parsed.extract.nameID).toBe(user.email);
    expect(parsed.extract.response?.inResponseTo).toBe(id);
    expect(parsed.extract.audience).toBe(SP_ENTITY_ID);
    expect(parsed.extract.attributes).toMatchObject({ email: user.email, name: "Alice Example", groups: ["staff", "a&b <c>"] });
  });

  it.each([
    ["aes128-gcm", {}],
    ["aes256-cbc", { allowInsecureCbc: true }],
  ] as const)("%s + RSA-OAEP: decrypts and validates", async (dataAlgorithm, extra) => {
    const { auth } = await idp({ dataAlgorithm, ...extra });
    const verifier = await strictSp(auth, spOpts());
    const { user, form } = await samlifyForm(auth);
    expect((await verifier.verify(form.samlResponse)).extract.nameID).toBe(user.email);
  });

  it("signResponse: false — samlify verifies the decrypted assertion's signature", async () => {
    const { auth } = await idp({}, { signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate, signResponse: false } });
    const verifier = await strictSp(auth, { ...spOpts(), wantMessageSigned: false });
    const { user, form } = await samlifyForm(auth);
    expect((await verifier.verify(form.samlResponse)).extract.nameID).toBe(user.email);
  });

  it("a wrong SP private key can't decrypt", async () => {
    const { auth } = await idp({}, { signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate, signResponse: false } });
    const verifier = await strictSp(auth, { encPrivateKey: keys.idpNext.privateKey, encryptCert: keys.idpNext.certificate, wantMessageSigned: false });
    const { form } = await samlifyForm(auth);
    await expect(verifier.verify(form.samlResponse)).rejects.toThrow(/ERR_EXCEPTION_OF_ASSERTION_DECRYPTION/);
  });
});

describe("interop: samlify, both runtimes", () => {
  it("rsa-oaep-sha256 is NOT supported by samlify: its XSD check rejects xenc11:MGF (and @authenio/xml-encryption lacks xmlenc11#rsa-oaep)", async () => {
    const { auth } = await idp({ keyAlgorithm: "rsa-oaep-sha256" });
    const verifier = await strictSp(auth, spOpts());
    const { form } = await samlifyForm(auth);
    await expect(verifier.verify(form.samlResponse)).rejects.toThrow(/ERR_SCHEMA.*xmlenc11#\}MGF/);
  });

  it.runIf(isWorkerd)("workerd: samlify can't decrypt, because privateDecrypt(OAEP) without oaepHash fails there", async () => {
    const k = crypto.getRandomValues(new Uint8Array(32));
    const wrapped = publicEncrypt({ key: keys.sp.certificate, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, k);
    expect(() => privateDecrypt({ key: keys.sp.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING }, wrapped)).toThrow(/Failed to cipher/);
    expect(privateDecrypt({ key: keys.sp.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, wrapped)).toHaveLength(32);
    // …so samlify, given the right key, still fails on workerd. If this starts passing, move the
    // Node-only samlify tests above to both runtimes.
    const { auth } = await idp();
    const verifier = await strictSp(auth, spOpts());
    const { form } = await samlifyForm(auth);
    await expect(verifier.verify(form.samlResponse)).rejects.toThrow(/ERR_EXCEPTION_OF_ASSERTION_DECRYPTION/);
  });

  it("an SP that isn't set up to decrypt fails closed", async () => {
    const { auth } = await idp();
    const verifier = await strictSp(auth);
    const { form } = await samlifyForm(auth);
    // samlify finds no plaintext Assertion to take the Issuer from.
    await expect(verifier.verify(form.samlResponse)).rejects.toThrow(/ERR_UNMATCH_ISSUER/);
  });
});

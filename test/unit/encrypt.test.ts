// Encrypted assertions (D-020): the encryptor on its own, then as used by buildSignedResponse.
// Decryption uses the test-only decryptor in test/support/xmlenc.ts (node:crypto and WebCrypto),
// never the code under test.
import { constants, createPublicKey, privateDecrypt } from "node:crypto";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";
import { describe, expect, inject, it } from "vitest";
import { resolveOptions, SamlIdpConfigError } from "../../src/options";
import {
  type AssertionEncryption,
  DATA_ALGORITHMS,
  encryptAssertionInResponse,
  encryptElement,
  type EncryptionDataAlgorithm,
  type EncryptionKeyAlgorithm,
  KEY_ALGORITHMS,
} from "../../src/saml/encrypt";
import { buildSignedResponse, type BuildResponseInput } from "../../src/saml/response";
import { libxml2Validator } from "../../src/saml/validator";
import type { SamlIdpOptions, ServiceProviderConfig } from "../../src/types";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";
import { decryptWithNode, decryptWithWebCrypto, parseEncryptedData } from "../support/xmlenc";

const keys = inject("keys");
const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";
const DS = "http://www.w3.org/2000/09/xmldsig#";

const certBody = (pem: string) => pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");

function spWith(encryption: ServiceProviderConfig["encryption"]): ServiceProviderConfig {
  return { id: "enc-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], encryption };
}

function resolvedEncryption(enc: Partial<NonNullable<ServiceProviderConfig["encryption"]>> = {}): AssertionEncryption {
  const r = resolveOptions(baseOptions({ serviceProviders: [spWith({ certificate: keys.sp.certificate, ...enc })] }));
  return r.serviceProviders[0]!.encryption!;
}

function issuesFor(options: SamlIdpOptions): string[] {
  try {
    resolveOptions(options);
  } catch (e) {
    if (e instanceof SamlIdpConfigError) return e.issues;
    throw e;
  }
  throw new Error("expected resolveOptions to throw");
}

const PLAIN = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>x</saml:Issuer><saml:Subject><saml:NameID>ünïcode@example.com</saml:NameID></saml:Subject></saml:Assertion>`;

const COMBOS: [EncryptionDataAlgorithm, EncryptionKeyAlgorithm][] = (["aes256-gcm", "aes128-gcm", "aes256-cbc"] as const).flatMap(
  (d) => (["rsa-oaep", "rsa-oaep-sha256"] as const).map((k): [EncryptionDataAlgorithm, EncryptionKeyAlgorithm] => [d, k]),
);

describe("encryptElement", () => {
  it("defaults to AES-256-GCM with RSA-OAEP (mgf1p), and round-trips with node:crypto and WebCrypto", async () => {
    const enc = resolvedEncryption();
    expect(enc.dataAlgorithm).toBe("aes256-gcm");
    expect(enc.keyAlgorithm).toBe("rsa-oaep");
    const xml = encryptElement(PLAIN, enc);
    const p = parseEncryptedData(xml);
    expect(p.type).toBe(`${XENC}Element`);
    expect(p.dataAlgorithm).toBe(`${XENC11}aes256-gcm`);
    expect(p.keyAlgorithm).toBe(`${XENC}rsa-oaep-mgf1p`);
    expect(p.keyDigest).toBe(`${DS}sha1`);
    expect(p.certificate).toBe(certBody(keys.sp.certificate));
    expect(p.recipient).toBe(SP_ENTITY_ID);
    expect(p.encryptedKey).toHaveLength(256); // RSA-2048
    // GCM layout (XML Enc 1.1 §5.2.4): 12-byte IV ‖ ciphertext ‖ 16-byte tag; GCM adds no padding.
    expect(p.cipherValue.length).toBe(12 + new TextEncoder().encode(PLAIN).length + 16);
    expect(decryptWithNode(xml, keys.sp.privateKey)).toBe(PLAIN);
    expect(await decryptWithWebCrypto(xml, keys.sp.privateKey)).toBe(PLAIN);
    expect(xml).not.toContain("ünïcode");
  });

  it.each(COMBOS)("%s + %s: advertises exactly what it does, and round-trips", async (dataAlgorithm, keyAlgorithm) => {
    const enc = resolvedEncryption({ dataAlgorithm, keyAlgorithm, allowInsecureCbc: dataAlgorithm === "aes256-cbc" });
    const xml = encryptElement(PLAIN, enc);
    const p = parseEncryptedData(xml);
    expect(p.dataAlgorithm).toBe(
      { "aes256-gcm": `${XENC11}aes256-gcm`, "aes128-gcm": `${XENC11}aes128-gcm`, "aes256-cbc": `${XENC}aes256-cbc` }[dataAlgorithm],
    );
    if (keyAlgorithm === "rsa-oaep") {
      expect(p.keyAlgorithm).toBe(`${XENC}rsa-oaep-mgf1p`);
      expect(p.keyDigest).toBe(`${DS}sha1`);
      expect(p.keyMgf).toBeUndefined();
    } else {
      expect(p.keyAlgorithm).toBe(`${XENC11}rsa-oaep`);
      expect(p.keyDigest).toBe(`${XENC}sha256`);
      expect(p.keyMgf).toBe(`${XENC11}mgf1sha256`);
    }
    if (dataAlgorithm === "aes256-cbc") {
      const len = new TextEncoder().encode(PLAIN).length;
      expect(p.cipherValue.length).toBe(16 + (Math.floor(len / 16) + 1) * 16); // IV ‖ padded blocks
    }
    expect(decryptWithNode(xml, keys.sp.privateKey)).toBe(PLAIN);
    expect(await decryptWithWebCrypto(xml, keys.sp.privateKey)).toBe(PLAIN);
  });

  it("rsa-oaep-sha256 really uses SHA-256 (a SHA-1 OAEP unwrap fails), and rsa-oaep really uses SHA-1", () => {
    const k = keys.sp.privateKey; // a PEM string: workerd's privateDecrypt rejects KeyObjects
    const unwrap = (xml: string, oaepHash: string) =>
      privateDecrypt({ key: k, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash }, parseEncryptedData(xml).encryptedKey);
    const s256 = encryptElement(PLAIN, resolvedEncryption({ keyAlgorithm: "rsa-oaep-sha256" }));
    expect(unwrap(s256, "sha256")).toHaveLength(32);
    expect(() => unwrap(s256, "sha1")).toThrow();
    const s1 = encryptElement(PLAIN, resolvedEncryption());
    expect(unwrap(s1, "sha1")).toHaveLength(32);
    expect(() => unwrap(s1, "sha256")).toThrow();
  });

  it("uses a fresh content key and IV every time", () => {
    const enc = resolvedEncryption();
    const a = parseEncryptedData(encryptElement(PLAIN, enc));
    const b = parseEncryptedData(encryptElement(PLAIN, enc));
    expect(Buffer.from(a.cipherValue.subarray(0, 12)).equals(Buffer.from(b.cipherValue.subarray(0, 12)))).toBe(false);
    expect(Buffer.from(a.cipherValue).equals(Buffer.from(b.cipherValue))).toBe(false);
    expect(Buffer.from(a.encryptedKey).equals(Buffer.from(b.encryptedKey))).toBe(false);
  });

  it("GCM: a flipped ciphertext bit or tag bit makes decryption fail (node:crypto and WebCrypto)", async () => {
    const xml = encryptElement(PLAIN, resolvedEncryption());
    const p = parseEncryptedData(xml);
    const original = Buffer.from(p.cipherValue).toString("base64");
    for (const index of [12, p.cipherValue.length - 1]) {
      const bytes = Uint8Array.from(p.cipherValue);
      bytes[index]! ^= 0x01;
      const tampered = xml.replace(original, Buffer.from(bytes).toString("base64"));
      expect(tampered).not.toBe(xml);
      expect(() => decryptWithNode(tampered, keys.sp.privateKey)).toThrow();
      await expect(decryptWithWebCrypto(tampered, keys.sp.privateKey)).rejects.toThrow();
    }
  });

  it("the wrong private key can't unwrap the content key", async () => {
    const xml = encryptElement(PLAIN, resolvedEncryption());
    expect(() => decryptWithNode(xml, keys.idp.privateKey)).toThrow();
    await expect(decryptWithWebCrypto(xml, keys.idpNext.privateKey)).rejects.toThrow();
  });

  it("RSA PKCS#1 v1.5 is impossible: no table entry, rejected by options, never emitted, unknown names throw", () => {
    expect(Object.values(KEY_ALGORITHMS).map((k) => k.uri)).toEqual([`${XENC}rsa-oaep-mgf1p`, `${XENC11}rsa-oaep`]);
    expect(Object.keys(DATA_ALGORITHMS)).toEqual(["aes256-gcm", "aes128-gcm", "aes256-cbc"]);
    const issues = issuesFor(baseOptions({ serviceProviders: [spWith({ certificate: keys.sp.certificate, keyAlgorithm: "rsa-1_5" as any })] }));
    expect(issues.join("\n")).toMatch(/serviceProviders\.0\.encryption\.keyAlgorithm/);
    for (const [d, k] of COMBOS) expect(encryptElement(PLAIN, { ...resolvedEncryption(), dataAlgorithm: d, keyAlgorithm: k })).not.toContain("rsa-1_5");
    expect(() => encryptElement(PLAIN, { ...resolvedEncryption(), keyAlgorithm: "rsa-1_5" as any })).toThrow(/unsupported/);
    expect(() => encryptElement(PLAIN, { ...resolvedEncryption(), dataAlgorithm: "tripledes-cbc" as any })).toThrow(/unsupported/);
  });
});

describe("encryptAssertionInResponse", () => {
  const response = (inner: string) =>
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r"><saml:Issuer>i</saml:Issuer>${inner}</samlp:Response>`;
  const assertion = `<saml:Assertion ID="_a" Version="2.0"><saml:Issuer>i</saml:Issuer></saml:Assertion>`;

  it("replaces the assertion and declares xmlns:saml on the encrypted element for standalone parsing", () => {
    const out = encryptAssertionInResponse(response(assertion), resolvedEncryption());
    expect(out).not.toContain("<saml:Assertion");
    expect(out).toMatch(/^<samlp:Response [^>]+><saml:Issuer>i<\/saml:Issuer><saml:EncryptedAssertion><xenc:EncryptedData [^]*<\/xenc:EncryptedData><\/saml:EncryptedAssertion><\/samlp:Response>$/);
    expect(decryptWithNode(out, keys.sp.privateKey)).toBe(
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a" Version="2.0"><saml:Issuer>i</saml:Issuer></saml:Assertion>`,
    );
  });

  it("refuses a Response with no assertion or with two", () => {
    expect(() => encryptAssertionInResponse(response(""), resolvedEncryption())).toThrow(/exactly one/);
    expect(() => encryptAssertionInResponse(response(assertion + assertion), resolvedEncryption())).toThrow(/exactly one/);
  });
});

describe("buildSignedResponse with encryption (sign-then-encrypt)", () => {
  const input = (): BuildResponseInput => ({
    requestId: "_req1",
    acsUrl: SP_ACS,
    audience: SP_ENTITY_ID,
    nameId: "secret-person@example.com",
    nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    attributes: { email: "secret-person@example.com", groups: ["top-secret-group"] },
    authnInstant: new Date(),
    sessionIndex: "_s1",
    now: new Date(),
  });

  function build(signing: Partial<SamlIdpOptions["signing"]> = {}) {
    const options = resolveOptions(
      baseOptions({
        signing: { ...baseOptions().signing, ...signing },
        serviceProviders: [spWith({ certificate: keys.sp.certificate })],
      }),
    );
    return { options, res: buildSignedResponse(options, input(), undefined, options.serviceProviders[0]!.encryption) };
  }

  function signatureOf(xml: string, rootLocalName: string) {
    const doc = new DOMParser().parseFromString(xml, "text/xml");
    const root = doc.documentElement!;
    expect(root.localName).toBe(rootLocalName);
    for (let n = root.firstChild; n; n = n.nextSibling) {
      if (n.nodeType === 1 && (n as any).localName === "Signature" && (n as any).namespaceURI === DS) return n;
    }
    return undefined;
  }

  function verify(xml: string, sigNode: any) {
    const sig = new SignedXml({ publicCert: keys.idp.certificate });
    sig.loadSignature(sigNode);
    return sig.checkSignature(xml);
  }

  it("signs the assertion, encrypts it, then signs the Response; the assertion signature verifies after decryption", () => {
    const { res } = build();
    expect(res.encrypted).toBe(true);
    // Response: signed, and the signature covers the EncryptedAssertion.
    const responseSig = signatureOf(res.xml, "Response");
    expect(responseSig).toBeDefined();
    expect(verify(res.xml, responseSig)).toBe(true);
    // Assertion: decrypt, then its own enveloped signature verifies standalone.
    const assertion = decryptWithNode(res.xml, keys.sp.privateKey);
    const assertionSig = signatureOf(assertion, "Assertion");
    expect(assertionSig).toBeDefined();
    expect(verify(assertion, assertionSig)).toBe(true);
    expect(assertion).toContain(`ID="${res.assertionId}"`);
    expect(assertion).toContain("<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">secret-person@example.com</saml:NameID>");
  });

  it("the plaintext assertion (NameID, attributes, subject) never appears in the Response", () => {
    const { res } = build();
    for (const secret of ["secret-person@example.com", "top-secret-group", "<saml:Assertion", "<saml:NameID", "<saml:Subject", "AttributeStatement", "_s1"])
      expect(res.xml).not.toContain(secret);
    expect(res.xml).toContain("<saml:EncryptedAssertion><xenc:EncryptedData");
  });

  it("the encrypted Response is valid against the SAML/XML-Enc schemas (libxml2)", async () => {
    const { res } = build();
    expect(await libxml2Validator().validate(res.xml, "protocol")).toEqual({ valid: true });
  });

  it("known limit (D-020): rsa-oaep-sha256's xenc11:MGF fails XSD validators that lack the XML Enc 1.1 schema", async () => {
    // xenc:EncryptionMethodType allows ##other elements with a *strict* wildcard, so a schema set
    // without xenc11 (like the SAML 2.0 set this repo vendors) rejects the MGF element. Hence
    // rsa-oaep (mgf1p) stays the default.
    const options = resolveOptions(
      baseOptions({ serviceProviders: [spWith({ certificate: keys.sp.certificate, keyAlgorithm: "rsa-oaep-sha256" })] }),
    );
    const res = buildSignedResponse(options, input(), undefined, options.serviceProviders[0]!.encryption);
    expect(await libxml2Validator().validate(res.xml, "protocol")).toEqual({
      valid: false,
      errors: [
        "line 1: Element '{http://www.w3.org/2009/xmlenc11#}MGF': No matching global element declaration available, but demanded by the strict wildcard.",
      ],
    });
  });

  it("signResponse: false still signs the (encrypted) assertion", () => {
    const { res } = build({ signResponse: false, signAssertion: true });
    expect(signatureOf(res.xml, "Response")).toBeUndefined();
    const assertion = decryptWithNode(res.xml, keys.sp.privateKey);
    expect(verify(assertion, signatureOf(assertion, "Assertion"))).toBe(true);
  });

  it("per-SP signing (signResponse: false for this SP) still signs the encrypted assertion", () => {
    const { options } = build();
    const res = buildSignedResponse(options, input(), { response: false, assertion: false }, options.serviceProviders[0]!.encryption);
    expect(signatureOf(res.xml, "Response")).toBeUndefined();
    const assertion = decryptWithNode(res.xml, keys.sp.privateKey);
    expect(verify(assertion, signatureOf(assertion, "Assertion"))).toBe(true);
  });

  it("defensive rule: even if options somehow say sign nothing, an encrypted assertion is signed", () => {
    const { options } = build();
    const bad = { ...options, signing: { ...options.signing, signResponse: false, signAssertion: false } };
    const res = buildSignedResponse(bad, input(), undefined, options.serviceProviders[0]!.encryption);
    const assertion = decryptWithNode(res.xml, keys.sp.privateKey);
    expect(verify(assertion, signatureOf(assertion, "Assertion"))).toBe(true);
  });

  it("signAssertion: false + signResponse: true: the Response signature covers the encrypted assertion", () => {
    const { res } = build({ signAssertion: false });
    expect(verify(res.xml, signatureOf(res.xml, "Response"))).toBe(true);
    expect(signatureOf(decryptWithNode(res.xml, keys.sp.privateKey), "Assertion")).toBeUndefined();
  });

  it("without encryption the Response is unchanged (plaintext assertion, encrypted: false)", () => {
    const options = resolveOptions(baseOptions());
    const res = buildSignedResponse(options, input());
    expect(res.encrypted).toBe(false);
    expect(res.xml).toContain("<saml:Assertion ID=");
    expect(res.xml).not.toContain("EncryptedAssertion");
  });
});

describe("options: encryption", () => {
  it("resolves defaults and parses the certificate once", () => {
    const enc = resolvedEncryption();
    expect(enc).toMatchObject({ dataAlgorithm: "aes256-gcm", keyAlgorithm: "rsa-oaep", recipient: SP_ENTITY_ID });
    expect(createPublicKey(enc.publicKeyPem).asymmetricKeyType).toBe("rsa");
    expect(enc.certificateBase64).toBe(certBody(keys.sp.certificate));
    expect(resolveOptions(baseOptions()).serviceProviders[0]!.encryption).toBeUndefined();
    expect(resolveOptions(baseOptions({ serviceProviders: [spWith({ certificate: keys.sp.certificate })] })).warnings).toEqual([]);
  });

  it("AES-CBC needs an explicit opt-in, and then logs a warning", () => {
    const issues = issuesFor(baseOptions({ serviceProviders: [spWith({ certificate: keys.sp.certificate, dataAlgorithm: "aes256-cbc" })] }));
    expect(issues).toEqual([
      "serviceProviders.0.encryption.dataAlgorithm: AES-CBC is vulnerable to padding-oracle attacks; use aes256-gcm, or set encryption.allowInsecureCbc: true for an SP that cannot do GCM",
    ]);
    const r = resolveOptions(
      baseOptions({ serviceProviders: [spWith({ certificate: keys.sp.certificate, dataAlgorithm: "aes256-cbc", allowInsecureCbc: true })] }),
    );
    expect(r.serviceProviders[0]!.encryption!.dataAlgorithm).toBe("aes256-cbc");
    expect(r.warnings).toEqual([
      "serviceProviders.0.encryption: AES-CBC is enabled (allowInsecureCbc). Only use this for SPs that cannot do AES-GCM.",
    ]);
  });

  it("rejects non-RSA, short-RSA, unparseable and non-PEM certificates; unknown algorithms and keys", () => {
    const one = (encryption: any) => issuesFor(baseOptions({ serviceProviders: [spWith(encryption)] }));
    expect(one({ certificate: keys.ec.certificate })).toEqual(["serviceProviders.0.encryption.certificate: must be an RSA certificate, got ec"]);
    expect(one({ certificate: keys.rsa1024.certificate })).toEqual([
      "serviceProviders.0.encryption.certificate: RSA key must be at least 2048 bits, got 1024",
    ]);
    expect(one({ certificate: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----" })[0]).toMatch(
      /^serviceProviders\.0\.encryption\.certificate: could not be parsed/,
    );
    expect(one({ certificate: "not a pem" })[0]).toMatch(/^serviceProviders\.0\.encryption\.certificate: must be a PEM CERTIFICATE/);
    expect(one({ certificate: keys.sp.certificate, dataAlgorithm: "aes192-gcm" })[0]).toMatch(/encryption\.dataAlgorithm/);
    expect(one({ certificate: keys.sp.certificate, extra: true })[0]).toMatch(/encryption/);
  });

  it("an expired encryption certificate only warns, like signing certificates", () => {
    const r = resolveOptions(baseOptions({ serviceProviders: [spWith({ certificate: keys.expired.certificate })] }));
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]).toMatch(/^serviceProviders\.0\.encryption\.certificate: EXPIRED on /);
    expect(r.serviceProviders[0]!.encryption).toBeDefined();
  });
});

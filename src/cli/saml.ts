// SAML reading helpers for the CLI: IdP metadata, enveloped-signature verification and
// XML Encryption decryption. Written for diagnostics: every step reports what it found.
import { constants, createDecipheriv, privateDecrypt } from "node:crypto";
import { SignedXml } from "xml-crypto";
import { precheckXml } from "../saml/validator";
import { parseXmlStrict } from "../saml/xml";
import { certFromBase64, UsageError } from "./util";

export const NS = {
  md: "urn:oasis:names:tc:SAML:2.0:metadata",
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  ds: "http://www.w3.org/2000/09/xmldsig#",
  xenc: "http://www.w3.org/2001/04/xmlenc#",
  xenc11: "http://www.w3.org/2009/xmlenc11#",
} as const;

/** Largest document the CLI will read (captured messages, metadata aggregates). */
export const MAX_DOC_BYTES = 4 * 1024 * 1024;

export function parseDoc(xml: string) {
  const pre = precheckXml(xml, MAX_DOC_BYTES);
  if (pre.length) throw new UsageError(`refusing to parse: ${pre.join("; ")}`);
  try {
    return parseXmlStrict(xml);
  } catch (e) {
    throw new UsageError(`not well-formed XML: ${(e as Error).message}`);
  }
}

export const children = (el: any, ns: string, name: string): any[] =>
  Array.from((el?.childNodes ?? []) as ArrayLike<any>).filter((n: any) => n.nodeType === 1 && n.namespaceURI === ns && n.localName === name);
export const child = (el: any, ns: string, name: string): any => children(el, ns, name)[0];
export const text = (el: any): string | undefined => (el ? (el.textContent ?? "").trim() : undefined);
export const descendants = (el: any, ns: string, name: string): any[] => Array.from(el.getElementsByTagNameNS(ns, name) as ArrayLike<any>);

// ---------------------------------------------------------------------------------------
// IdP metadata
// ---------------------------------------------------------------------------------------

export interface IdpMetadata {
  entityId: string;
  sso: { binding: string; location: string }[];
  nameIdFormats: string[];
  wantAuthnRequestsSigned: boolean;
  signingCertificates: string[];
  signed: boolean;
}

/** `https://host` → `https://host/api/auth/saml2/idp/metadata`; a URL ending in /metadata is kept. */
export function metadataUrl(input: string, basePath: string): string {
  const u = new URL(input);
  if (/\/metadata\/?$/.test(u.pathname)) return u.href;
  const base = `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
  const path = u.pathname.replace(/\/+$/, "").endsWith(basePath.replace(/\/+$/, "")) ? "" : basePath.replace(/\/+$/, "");
  return `${base}${path}/saml2/idp/metadata`;
}

export function readIdpMetadata(xml: string): IdpMetadata {
  const doc = parseDoc(xml);
  const root = doc.documentElement as any;
  if (root.namespaceURI !== NS.md || root.localName !== "EntityDescriptor") throw new UsageError("not an md:EntityDescriptor");
  const idp = child(root, NS.md, "IDPSSODescriptor");
  if (!idp) throw new UsageError("no IDPSSODescriptor: this is not IdP metadata");
  return {
    entityId: root.getAttribute("entityID") ?? "",
    sso: children(idp, NS.md, "SingleSignOnService").map((s) => ({ binding: s.getAttribute("Binding"), location: s.getAttribute("Location") })),
    nameIdFormats: children(idp, NS.md, "NameIDFormat").map((n) => text(n) ?? ""),
    wantAuthnRequestsSigned: idp.getAttribute("WantAuthnRequestsSigned") === "true",
    signingCertificates: children(idp, NS.md, "KeyDescriptor")
      .filter((k) => !k.getAttribute("use") || k.getAttribute("use") === "signing")
      .flatMap((k) => descendants(k, NS.ds, "X509Certificate").map((c) => certFromBase64(text(c) ?? ""))),
    signed: child(root, NS.ds, "Signature") !== undefined,
  };
}

// ---------------------------------------------------------------------------------------
// Enveloped signatures
// ---------------------------------------------------------------------------------------

export interface SignatureResult {
  present: boolean;
  /** undefined when no certificate was available to check against. */
  valid: boolean | undefined;
  algorithm?: string;
  digest?: string;
  /** Index into the certificates that verified it. */
  certIndex?: number;
  problem?: string;
}

const short = (uri: string | null | undefined) => (uri ? (uri.split("#")[1] ?? uri) : "?");

/**
 * Verify the ds:Signature that is a direct child of `el` against each certificate. Beyond the
 * cryptographic check, the signature must reference exactly `el` (URI="#<its ID>") and that ID
 * must be unique in the document — the checks that stop signature-wrapping attacks.
 */
export function verifyEnveloped(xml: string, doc: any, el: any, certs: string[]): SignatureResult {
  const sigEl = child(el, NS.ds, "Signature");
  if (!sigEl) return { present: false, valid: undefined };
  const signedInfo = child(sigEl, NS.ds, "SignedInfo");
  const algorithm = short(child(signedInfo, NS.ds, "SignatureMethod")?.getAttribute("Algorithm"));
  const refs = children(signedInfo, NS.ds, "Reference");
  const digest = short(child(refs[0], NS.ds, "DigestMethod")?.getAttribute("Algorithm"));
  const base = { present: true, algorithm, digest };
  const id = el.getAttribute("ID");
  if (refs.length !== 1) return { ...base, valid: false, problem: `${refs.length} References (expected exactly 1)` };
  if (!id || refs[0].getAttribute("URI") !== `#${id}`)
    return { ...base, valid: false, problem: `Reference URI ${refs[0].getAttribute("URI")} does not point at this element (ID ${id})` };
  const sameId = descendants(doc, "*", "*").filter((e) => e.getAttribute?.("ID") === id).length;
  if (sameId !== 1) return { ...base, valid: false, problem: `ID ${id} appears ${sameId} times (signature wrapping?)` };
  if (certs.length === 0) return { ...base, valid: undefined };
  let lastError = "signature value does not verify with any given certificate";
  for (const [i, cert] of certs.entries()) {
    try {
      const sig = new SignedXml({ publicCert: cert, getCertFromKeyInfo: () => null });
      sig.loadSignature(sigEl);
      if (sig.checkSignature(xml)) return { ...base, valid: true, certIndex: i };
    } catch (e) {
      lastError = (e as Error).message;
    }
  }
  return { ...base, valid: false, problem: lastError };
}

// ---------------------------------------------------------------------------------------
// XML Encryption (EncryptedAssertion)
// ---------------------------------------------------------------------------------------

const DATA: Record<string, { cipher: string; iv: number; gcm: boolean }> = {
  [`${NS.xenc11}aes256-gcm`]: { cipher: "aes-256-gcm", iv: 12, gcm: true },
  [`${NS.xenc11}aes192-gcm`]: { cipher: "aes-192-gcm", iv: 12, gcm: true },
  [`${NS.xenc11}aes128-gcm`]: { cipher: "aes-128-gcm", iv: 12, gcm: true },
  [`${NS.xenc}aes256-cbc`]: { cipher: "aes-256-cbc", iv: 16, gcm: false },
  [`${NS.xenc}aes192-cbc`]: { cipher: "aes-192-cbc", iv: 16, gcm: false },
  [`${NS.xenc}aes128-cbc`]: { cipher: "aes-128-cbc", iv: 16, gcm: false },
};

const HASH: Record<string, string> = {
  [`${NS.ds}sha1`]: "sha1",
  [`${NS.xenc}sha256`]: "sha256",
  [`${NS.xenc}sha512`]: "sha512",
};

export interface EncryptionInfo {
  dataAlgorithm: string;
  keyAlgorithm: string;
  keyDigest: string | undefined;
  recipient: string | undefined;
}

function encryptedParts(encryptedAssertion: any) {
  const ed = child(encryptedAssertion, NS.xenc, "EncryptedData");
  if (!ed) throw new UsageError("EncryptedAssertion has no xenc:EncryptedData");
  // The EncryptedKey sits in EncryptedData/KeyInfo, or beside EncryptedData (SAML Core §2.3.4).
  const ek = child(child(ed, NS.ds, "KeyInfo"), NS.xenc, "EncryptedKey") ?? child(encryptedAssertion, NS.xenc, "EncryptedKey");
  if (!ek) throw new UsageError("no xenc:EncryptedKey found");
  return { ed, ek, edMethod: child(ed, NS.xenc, "EncryptionMethod"), ekMethod: child(ek, NS.xenc, "EncryptionMethod") };
}

export function encryptionInfo(encryptedAssertion: any): EncryptionInfo {
  const { ek, edMethod, ekMethod } = encryptedParts(encryptedAssertion);
  return {
    dataAlgorithm: short(edMethod?.getAttribute("Algorithm")),
    keyAlgorithm: short(ekMethod?.getAttribute("Algorithm")),
    keyDigest: child(ekMethod, NS.ds, "DigestMethod") ? short(child(ekMethod, NS.ds, "DigestMethod").getAttribute("Algorithm")) : undefined,
    recipient: ek.getAttribute("Recipient") || undefined,
  };
}

const cipherValue = (el: any) => Buffer.from(text(child(child(el, NS.xenc, "CipherData"), NS.xenc, "CipherValue")) ?? "", "base64");

/** Decrypt an EncryptedAssertion with the SP's private key; returns the Assertion XML. */
export function decryptAssertion(encryptedAssertion: any, privateKeyPem: string): string {
  const { ed, ek, edMethod, ekMethod } = encryptedParts(encryptedAssertion);
  const keyAlg = ekMethod?.getAttribute("Algorithm");
  let oaepHash: string;
  if (keyAlg === `${NS.xenc}rsa-oaep-mgf1p`) oaepHash = "sha1";
  else if (keyAlg === `${NS.xenc11}rsa-oaep`) {
    const digest = HASH[child(ekMethod, NS.ds, "DigestMethod")?.getAttribute("Algorithm") ?? `${NS.ds}sha1`];
    const mgf = child(ekMethod, NS.xenc11, "MGF")?.getAttribute("Algorithm") ?? `${NS.xenc11}mgf1sha1`;
    if (!digest || mgf !== `${NS.xenc11}mgf1${digest}`)
      throw new UsageError(`unsupported rsa-oaep parameters (digest and MGF1 must use the same hash): ${digest} / ${short(mgf)}`);
    oaepHash = digest;
  } else throw new UsageError(`unsupported key transport ${keyAlg} (RSA PKCS#1 v1.5 is not decrypted: it is insecure)`);

  let key: Buffer;
  try {
    key = privateDecrypt({ key: privateKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash }, cipherValue(ek));
  } catch (e) {
    throw new UsageError(`cannot decrypt the key: wrong private key? (${(e as Error).message})`);
  }
  const d = DATA[edMethod?.getAttribute("Algorithm") ?? ""];
  if (!d) throw new UsageError(`unsupported data algorithm ${edMethod?.getAttribute("Algorithm")}`);
  const cv = cipherValue(ed);
  const iv = cv.subarray(0, d.iv);
  try {
    if (d.gcm) {
      const decipher = createDecipheriv(d.cipher as "aes-256-gcm", key, iv);
      decipher.setAuthTag(cv.subarray(-16));
      return Buffer.concat([decipher.update(cv.subarray(d.iv, -16)), decipher.final()]).toString("utf8");
    }
    // XML Encryption padding: the last byte is the pad length; the other pad bytes are arbitrary.
    const decipher = createDecipheriv(d.cipher, key, iv).setAutoPadding(false);
    const plain = Buffer.concat([decipher.update(cv.subarray(d.iv)), decipher.final()]);
    const pad = plain[plain.length - 1] ?? 0;
    if (pad < 1 || pad > 16) throw new Error("bad padding");
    return plain.subarray(0, plain.length - pad).toString("utf8");
  } catch (e) {
    throw new UsageError(`cannot decrypt the assertion: ${(e as Error).message}`);
  }
}

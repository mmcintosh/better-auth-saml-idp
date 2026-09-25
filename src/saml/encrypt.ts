// XML Encryption of a SAML <Assertion> into <EncryptedAssertion> (SAML Core §2.3.4,
// XML Encryption 1.1). Deliberately small: one EncryptedData of Type=Element, whose content
// key is transported to the SP in an EncryptedKey under the SP's RSA certificate.
//
// Only node:crypto primitives that exist on Cloudflare Workers (nodejs_compat) and Node 20+
// are used: createCipheriv (AES-GCM / AES-CBC) and publicEncrypt with OAEP padding. RSA
// PKCS#1 v1.5 key transport is not implemented at all (Bleichenbacher-style oracles), and
// AES-CBC is only reachable through an explicit opt-in checked at startup (padding oracles).
import { constants, createCipheriv, publicEncrypt } from "node:crypto";
import { escapeXml, newSamlId } from "./response";

export type EncryptionDataAlgorithm = "aes256-gcm" | "aes128-gcm" | "aes256-cbc";
export type EncryptionKeyAlgorithm = "rsa-oaep" | "rsa-oaep-sha256";

const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const SAML = "urn:oasis:names:tc:SAML:2.0:assertion";

interface DataAlgorithm {
  uri: string;
  cipher: "aes-256-gcm" | "aes-128-gcm" | "aes-256-cbc";
  keyBytes: number;
  ivBytes: number;
  gcm: boolean;
}

/** Content-encryption algorithms (XML Enc 1.1 §5.2). */
export const DATA_ALGORITHMS: Record<EncryptionDataAlgorithm, DataAlgorithm> = {
  "aes256-gcm": { uri: `${XENC11}aes256-gcm`, cipher: "aes-256-gcm", keyBytes: 32, ivBytes: 12, gcm: true },
  "aes128-gcm": { uri: `${XENC11}aes128-gcm`, cipher: "aes-128-gcm", keyBytes: 16, ivBytes: 12, gcm: true },
  "aes256-cbc": { uri: `${XENC}aes256-cbc`, cipher: "aes-256-cbc", keyBytes: 32, ivBytes: 16, gcm: false },
};

interface KeyAlgorithm {
  uri: string;
  /** OAEP digest; node:crypto (and WebCrypto) use the same hash for MGF1. */
  oaepHash: "sha1" | "sha256";
  /** Children of the EncryptedKey's EncryptionMethod that pin the parameters explicitly. */
  params: string;
}

/**
 * Key-transport algorithms (XML Enc 1.1 §5.5). Both are RSA-OAEP; there is intentionally no
 * entry for `xmlenc#rsa-1_5`.
 * - `rsa-oaep`: `xmlenc#rsa-oaep-mgf1p`, SHA-1 digest and MGF1-SHA1 (fixed by the URI). The
 *   most widely supported choice; SHA-1 inside OAEP is not a collision-resistance use.
 * - `rsa-oaep-sha256`: `xmlenc11#rsa-oaep` with a SHA-256 digest and MGF1-SHA256, declared
 *   with `ds:DigestMethod` and `xenc11:MGF`.
 */
export const KEY_ALGORITHMS: Record<EncryptionKeyAlgorithm, KeyAlgorithm> = {
  "rsa-oaep": {
    uri: `${XENC}rsa-oaep-mgf1p`,
    oaepHash: "sha1",
    params: `<ds:DigestMethod xmlns:ds="${DS}" Algorithm="${DS}sha1"/>`,
  },
  "rsa-oaep-sha256": {
    uri: `${XENC11}rsa-oaep`,
    oaepHash: "sha256",
    params: `<ds:DigestMethod xmlns:ds="${DS}" Algorithm="${XENC}sha256"/><xenc11:MGF xmlns:xenc11="${XENC11}" Algorithm="${XENC11}mgf1sha256"/>`,
  },
};

export interface AssertionEncryption {
  /**
   * The SP's RSA public key (from its encryption certificate) as SPKI PEM, checked at startup.
   * A PEM string, not a KeyObject: workerd's publicEncrypt() rejects KeyObjects.
   */
  publicKeyPem: string;
  /** The SP's certificate as base64 DER (PEM body), echoed in the EncryptedKey's KeyInfo. */
  certificateBase64: string;
  dataAlgorithm: EncryptionDataAlgorithm;
  keyAlgorithm: EncryptionKeyAlgorithm;
  /** Optional `Recipient` on the EncryptedKey (the SP's entity ID). */
  recipient?: string;
}

function b64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/**
 * Encrypt `plaintext` (an already serialized and, when configured, already signed element)
 * and return an `<xenc:EncryptedData Type="…#Element">` whose CipherValue is
 *   GCM: IV (12 bytes) ‖ ciphertext ‖ tag (16 bytes)   — XML Enc 1.1 §5.2.4
 *   CBC: IV (16 bytes) ‖ ciphertext (PKCS#7 padding, a valid XML Enc padding) — §5.2.1
 * A fresh random content key and IV are drawn for every call.
 */
export function encryptElement(plaintext: string, enc: AssertionEncryption): string {
  const data = DATA_ALGORITHMS[enc.dataAlgorithm];
  const transport = KEY_ALGORITHMS[enc.keyAlgorithm];
  // Unknown names must never fall through to some default; options validation already
  // restricts them, this is the last line.
  if (!data || !transport) throw new Error("unsupported encryption algorithm");

  const key = crypto.getRandomValues(new Uint8Array(data.keyBytes));
  const iv = crypto.getRandomValues(new Uint8Array(data.ivBytes));
  const cipher = createCipheriv(data.cipher, key, iv);
  const body = concat(new Uint8Array(cipher.update(plaintext, "utf8")), new Uint8Array(cipher.final()));
  const cipherValue = data.gcm
    ? concat(iv, body, new Uint8Array((cipher as import("node:crypto").CipherGCM).getAuthTag()))
    : concat(iv, body);

  // oaepHash is always passed explicitly: workerd has no SHA-1 default for OAEP, and a PEM
  // string (not a KeyObject) because workerd's publicEncrypt rejects KeyObjects.
  const encryptedKey = publicEncrypt(
    { key: enc.publicKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: transport.oaepHash },
    key,
  );
  key.fill(0);

  const recipient = enc.recipient ? ` Recipient="${escapeXml(enc.recipient)}"` : "";
  return (
    `<xenc:EncryptedData xmlns:xenc="${XENC}" Id="${newSamlId()}" Type="${XENC}Element">` +
    `<xenc:EncryptionMethod Algorithm="${data.uri}"/>` +
    `<ds:KeyInfo xmlns:ds="${DS}">` +
    `<xenc:EncryptedKey Id="${newSamlId()}"${recipient}>` +
    `<xenc:EncryptionMethod Algorithm="${transport.uri}">${transport.params}</xenc:EncryptionMethod>` +
    `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${enc.certificateBase64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    `<xenc:CipherData><xenc:CipherValue>${b64(new Uint8Array(encryptedKey))}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedKey>` +
    `</ds:KeyInfo>` +
    `<xenc:CipherData><xenc:CipherValue>${b64(cipherValue)}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedData>`
  );
}

const OPEN = "<saml:Assertion ";
const CLOSE = "</saml:Assertion>";

/**
 * Replace the single `<saml:Assertion>` in a serialized Response with a
 * `<saml:EncryptedAssertion>`. The plaintext is the exact serialized (and already signed)
 * assertion, plus an `xmlns:saml` declaration on its root: SPs parse the decrypted element on
 * its own, outside the Response that declares the prefix. Adding a declaration the element
 * already has in scope leaves its exclusive-c14n form, and so its signature, unchanged.
 * Values inside the assertion are escaped, so the open/close tags occur exactly once.
 */
export function encryptAssertionInResponse(responseXml: string, enc: AssertionEncryption): string {
  const start = responseXml.indexOf(OPEN);
  const end = responseXml.indexOf(CLOSE);
  if (start < 0 || end < start || responseXml.indexOf(OPEN, start + 1) >= 0 || responseXml.indexOf(CLOSE, end + 1) >= 0)
    throw new Error("expected exactly one saml:Assertion to encrypt");
  const assertion = responseXml.slice(start, end + CLOSE.length);
  const standalone = assertion.startsWith(`${OPEN}xmlns:saml=`) ? assertion : `${OPEN}xmlns:saml="${SAML}" ${assertion.slice(OPEN.length)}`;
  const encrypted = `<saml:EncryptedAssertion>${encryptElement(standalone, enc)}</saml:EncryptedAssertion>`;
  return responseXml.slice(0, start) + encrypted + responseXml.slice(end + CLOSE.length);
}

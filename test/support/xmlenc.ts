// Test-only XML Encryption *decryptor*, written independently of src/saml/encrypt.ts:
// it reads the algorithms from the XML (not from our tables) and decrypts with either
// node:crypto or WebCrypto, so a mismatch between what we advertise and what we do fails.
import { constants, createDecipheriv, createPrivateKey, privateDecrypt } from "node:crypto";
import { DOMParser, type Element } from "@xmldom/xmldom";

const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";
const DS = "http://www.w3.org/2000/09/xmldsig#";

export interface ParsedEncryptedData {
  dataAlgorithm: string;
  keyAlgorithm: string;
  keyDigest: string | undefined;
  keyMgf: string | undefined;
  encryptedKey: Uint8Array<ArrayBuffer>;
  cipherValue: Uint8Array<ArrayBuffer>;
  certificate: string | undefined;
  type: string | null;
  recipient: string | null;
}

const fromB64 = (s: string) => Uint8Array.from(atob(s.replace(/\s+/g, "")), (c) => c.charCodeAt(0));

function child(el: Element, ns: string, name: string): Element | undefined {
  for (let n = el.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === 1 && (n as Element).namespaceURI === ns && (n as Element).localName === name) return n as Element;
  }
  return undefined;
}

function need<T>(v: T | undefined, what: string): T {
  if (v === undefined) throw new Error(`missing ${what}`);
  return v;
}

/** Parse the (single) xenc:EncryptedData in `xml`, strictly by namespace and position. */
export function parseEncryptedData(xml: string): ParsedEncryptedData {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const all = doc.getElementsByTagNameNS(XENC, "EncryptedData");
  if (all.length !== 1) throw new Error(`expected one EncryptedData, found ${all.length}`);
  const ed = all[0]!;
  const edMethod = need(child(ed, XENC, "EncryptionMethod"), "EncryptedData/EncryptionMethod");
  const keyInfo = need(child(ed, DS, "KeyInfo"), "EncryptedData/KeyInfo");
  const ek = need(child(keyInfo, XENC, "EncryptedKey"), "KeyInfo/EncryptedKey");
  const ekMethod = need(child(ek, XENC, "EncryptionMethod"), "EncryptedKey/EncryptionMethod");
  const ekKeyInfo = child(ek, DS, "KeyInfo");
  const x509Data = ekKeyInfo && child(ekKeyInfo, DS, "X509Data");
  const cert = x509Data && child(x509Data, DS, "X509Certificate");
  const cv = (el: Element) => fromB64(need(child(need(child(el, XENC, "CipherData"), "CipherData"), XENC, "CipherValue"), "CipherValue").textContent ?? "");
  return {
    dataAlgorithm: edMethod.getAttribute("Algorithm")!,
    keyAlgorithm: ekMethod.getAttribute("Algorithm")!,
    keyDigest: child(ekMethod, DS, "DigestMethod")?.getAttribute("Algorithm") ?? undefined,
    keyMgf: child(ekMethod, XENC11, "MGF")?.getAttribute("Algorithm") ?? undefined,
    encryptedKey: cv(ek),
    cipherValue: cv(ed),
    certificate: cert?.textContent ?? undefined,
    type: ed.getAttribute("Type"),
    recipient: ek.getAttribute("Recipient"),
  };
}

/** The OAEP hash an EncryptedKey's EncryptionMethod calls for (XML Enc 1.1 §5.5.2). */
function oaepHashOf(p: ParsedEncryptedData): "sha1" | "sha256" {
  if (p.keyAlgorithm === `${XENC}rsa-oaep-mgf1p`) {
    if (p.keyDigest && p.keyDigest !== `${DS}sha1`) throw new Error(`unexpected digest ${p.keyDigest}`);
    return "sha1";
  }
  if (p.keyAlgorithm === `${XENC11}rsa-oaep`) {
    // node:crypto and WebCrypto tie MGF1's hash to the OAEP digest, so both must say SHA-256.
    if (p.keyDigest === `${XENC}sha256` && p.keyMgf === `${XENC11}mgf1sha256`) return "sha256";
    throw new Error(`unsupported rsa-oaep parameters ${p.keyDigest} / ${p.keyMgf}`);
  }
  throw new Error(`unsupported key transport ${p.keyAlgorithm}`);
}

const DATA: Record<string, { cipher: string; iv: number; gcm: boolean }> = {
  [`${XENC11}aes256-gcm`]: { cipher: "aes-256-gcm", iv: 12, gcm: true },
  [`${XENC11}aes128-gcm`]: { cipher: "aes-128-gcm", iv: 12, gcm: true },
  [`${XENC}aes256-cbc`]: { cipher: "aes-256-cbc", iv: 16, gcm: false },
};

/** Decrypt with node:crypto. Throws on a wrong key or a failed GCM tag. */
export function decryptWithNode(xml: string, privateKeyPem: string): string {
  const p = parseEncryptedData(xml);
  const key = privateDecrypt(
    { key: privateKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: oaepHashOf(p) },
    p.encryptedKey,
  );
  const d = DATA[p.dataAlgorithm];
  if (!d) throw new Error(`unsupported data algorithm ${p.dataAlgorithm}`);
  const iv = p.cipherValue.subarray(0, d.iv);
  const body = d.gcm ? p.cipherValue.subarray(d.iv, -16) : p.cipherValue.subarray(d.iv);
  const decipher = createDecipheriv(d.cipher, key, iv) as import("node:crypto").DecipherGCM;
  if (d.gcm) decipher.setAuthTag(p.cipherValue.subarray(-16));
  return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array([...decipher.update(body), ...decipher.final()]));
}

function pemToPkcs8(pem: string): ArrayBuffer {
  const der = createPrivateKey(pem).export({ type: "pkcs8", format: "der" });
  return new Uint8Array(der).buffer;
}

/** Decrypt with WebCrypto: an implementation independent of node:crypto's OAEP/AES API. */
export async function decryptWithWebCrypto(xml: string, privateKeyPem: string): Promise<string> {
  const p = parseEncryptedData(xml);
  const hash = oaepHashOf(p) === "sha256" ? "SHA-256" : "SHA-1";
  const rsa = await crypto.subtle.importKey("pkcs8", pemToPkcs8(privateKeyPem), { name: "RSA-OAEP", hash }, false, ["decrypt"]);
  const raw = new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsa, p.encryptedKey));
  const d = DATA[p.dataAlgorithm];
  if (!d) throw new Error(`unsupported data algorithm ${p.dataAlgorithm}`);
  const name = d.gcm ? "AES-GCM" : "AES-CBC";
  const aes = await crypto.subtle.importKey("raw", raw, { name }, false, ["decrypt"]);
  const iv = p.cipherValue.slice(0, d.iv);
  const plain = await crypto.subtle.decrypt(d.gcm ? { name, iv, tagLength: 128 } : { name, iv }, aes, p.cipherValue.slice(d.iv));
  return new TextDecoder("utf-8", { fatal: true }).decode(plain);
}

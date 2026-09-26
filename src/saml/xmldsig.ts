// Verifying an enveloped XML signature without signature-wrapping (XSW) exposure. Used for
// HTTP-POST signed AuthnRequests (D-025) and by the CLI's `decode`.
//
// The rules, all checked before the cryptographic verification:
//  - the ds:Signature is a direct child of the element it protects;
//  - SignedInfo has exactly one Reference, whose URI is "#" + that element's ID;
//  - that ID value appears on exactly one element (across ID/Id/id attributes, which is
//    everything xml-crypto may resolve a reference through), so the reference can't be
//    redirected to a copy placed elsewhere;
//  - canonicalization, transforms, signature and digest algorithms are on allow-lists
//    (SHA-1 only by explicit opt-in; no XPath/XSLT transforms, no WithComments variants);
//  - only the given certificates verify it: KeyInfo in the message is ignored.
import { createPublicKey, verify as verifyRaw } from "node:crypto";
import { SignedXml } from "xml-crypto";

const DS = "http://www.w3.org/2000/09/xmldsig#";

const C14N = new Set(["http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"]);
const TRANSFORMS = new Set(["http://www.w3.org/2000/09/xmldsig#enveloped-signature", ...C14N]);
const SIGNATURE: Record<string, { name: string; sha1: boolean }> = {
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": { name: "rsa-sha256", sha1: false },
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": { name: "rsa-sha512", sha1: false },
  "http://www.w3.org/2000/09/xmldsig#rsa-sha1": { name: "rsa-sha1", sha1: true },
};
const DIGEST: Record<string, { name: string; sha1: boolean }> = {
  "http://www.w3.org/2001/04/xmlenc#sha256": { name: "sha256", sha1: false },
  "http://www.w3.org/2001/04/xmlenc#sha512": { name: "sha512", sha1: false },
  "http://www.w3.org/2000/09/xmldsig#sha1": { name: "sha1", sha1: true },
};

export interface EnvelopedSignatureResult {
  present: boolean;
  /** true: verified; false: structurally unacceptable or doesn't verify; undefined: no certificate to check with. */
  valid: boolean | undefined;
  algorithm?: string;
  digest?: string;
  /** Which certificate verified it. */
  certIndex?: number;
  problem?: string;
}

const children = (el: any, ns: string, name: string): any[] =>
  Array.from((el?.childNodes ?? []) as ArrayLike<any>).filter((n: any) => n.nodeType === 1 && n.namespaceURI === ns && n.localName === name);

/** Every element carrying `value` in an ID-like attribute (any namespace). */
function elementsWithId(doc: any, value: string): number {
  let count = 0;
  const all = doc.getElementsByTagName("*") as ArrayLike<any>;
  for (let i = 0; i < all.length; i++) {
    const attrs = all[i].attributes as ArrayLike<any>;
    for (let j = 0; j < attrs.length; j++) {
      const a = attrs[j];
      if ((a.localName === "ID" || a.localName === "Id" || a.localName === "id") && a.value === value) {
        count++;
        break;
      }
    }
  }
  return count;
}

export function verifyEnvelopedSignature(
  xml: string,
  doc: any,
  el: any,
  certs: string[],
  policy: { allowSha1: boolean },
): EnvelopedSignatureResult {
  const sigs = children(el, DS, "Signature");
  if (sigs.length === 0) return { present: false, valid: undefined };
  const fail = (problem: string, extra: Partial<EnvelopedSignatureResult> = {}): EnvelopedSignatureResult => ({ present: true, valid: false, problem, ...extra });
  if (sigs.length > 1) return fail(`${sigs.length} Signature elements`);
  const sigEl = sigs[0];
  const signedInfo = children(sigEl, DS, "SignedInfo")[0];
  if (!signedInfo) return fail("no SignedInfo");

  const c14n = children(signedInfo, DS, "CanonicalizationMethod")[0]?.getAttribute("Algorithm");
  const sigUri = children(signedInfo, DS, "SignatureMethod")[0]?.getAttribute("Algorithm");
  const sig = SIGNATURE[sigUri ?? ""];
  const refs = children(signedInfo, DS, "Reference");
  const digestUri = children(refs[0], DS, "DigestMethod")[0]?.getAttribute("Algorithm");
  const digest = DIGEST[digestUri ?? ""];
  const names = { algorithm: sig?.name ?? sigUri ?? "?", digest: digest?.name ?? digestUri ?? "?" };

  if (!C14N.has(c14n)) return fail(`canonicalization ${c14n} is not allowed`, names);
  if (!sig) return fail(`signature algorithm ${sigUri} is not allowed`, names);
  if (!digest) return fail(`digest algorithm ${digestUri} is not allowed`, names);
  if ((sig.sha1 || digest.sha1) && !policy.allowSha1) return fail("SHA-1 is not accepted", names);
  if (refs.length !== 1) return fail(`${refs.length} References (expected exactly 1)`, names);
  const id = el.getAttribute("ID");
  const uri = refs[0].getAttribute("URI");
  if (!id || uri !== `#${id}`) return fail(`Reference URI ${uri} does not point at the signed element (ID ${id})`, names);
  const sameId = elementsWithId(doc, id);
  if (sameId !== 1) return fail(`ID ${id} appears on ${sameId} elements (signature wrapping?)`, names);
  const transforms = children(children(refs[0], DS, "Transforms")[0], DS, "Transform").map((t) => t.getAttribute("Algorithm"));
  const bad = transforms.find((t) => !TRANSFORMS.has(t));
  if (bad !== undefined) return fail(`transform ${bad} is not allowed`, names);
  if (!transforms.includes("http://www.w3.org/2000/09/xmldsig#enveloped-signature")) return fail("not an enveloped signature", names);

  if (certs.length === 0) return { present: true, valid: undefined, ...names };
  let problem = "signature does not verify with any configured certificate";
  // Pick the certificate before the expensive part (review 4, R4-2). xml-crypto validates the
  // Reference (re-parse, ID lookups, canonicalising the whole document) before it looks at the
  // key, so trying N certificates cost N full verifications. Canonicalise SignedInfo once, with
  // xml-crypto's own code, check the SignatureValue against each key (a cheap RSA operation), and
  // run the full verification only for a certificate that matches. If this pre-check can't run,
  // every certificate is tried in full as before; either way the full check decides.
  let candidates = [...certs.entries()];
  try {
    const probe = new SignedXml({ publicCert: certs[0], getCertFromKeyInfo: () => null });
    probe.loadSignature(sigEl);
    const canon = (probe as unknown as { getCanonSignedInfoXml(doc: unknown): string }).getCanonSignedInfoXml(doc);
    const value = Buffer.from(String((probe as unknown as { signatureValue?: string }).signatureValue ?? "").replace(/\s+/g, ""), "base64");
    const hash = sig.name.slice("rsa-".length);
    const data = Buffer.from(canon, "utf8");
    candidates = candidates.filter(([, cert]) => {
      try {
        return verifyRaw(hash, data, createPublicKey(cert), value);
      } catch {
        return false;
      }
    });
    if (candidates.length === 0) return fail(problem, names);
  } catch {
    candidates = [...certs.entries()];
  }
  for (const [i, cert] of candidates) {
    try {
      const v = new SignedXml({ publicCert: cert, getCertFromKeyInfo: () => null });
      v.loadSignature(sigEl);
      if (v.checkSignature(xml)) return { present: true, valid: true, certIndex: i, ...names };
    } catch (e) {
      problem = (e as Error).message;
    }
  }
  return fail(problem, names);
}

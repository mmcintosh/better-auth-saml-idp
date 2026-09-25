import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { ResolvedServiceProvider } from "../types";
import { precheckXml, type SchemaValidator } from "./validator";
import { parseXmlStrict } from "./xml";

export const NS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
export const NS_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
export const NS_DSIG = "http://www.w3.org/2000/09/xmldsig#";
const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

/** Maximum decoded AuthnRequest size. Real requests are well under 8 KiB. */
export const MAX_REQUEST_BYTES = 64 * 1024;
/** How old an AuthnRequest's IssueInstant may be (plus clock skew). */
export const REQUEST_MAX_AGE_SECONDS = 300;

export class SamlRequestError extends Error {
  constructor(
    readonly code: "INVALID_SAML_REQUEST" | "UNSIGNED_SAML_REQUEST" | "RELAY_STATE_TOO_LONG",
    /** Safe to log at debug level: never contains the raw payload. */
    readonly detail: string,
  ) {
    super(detail);
  }
}

const invalid = (detail: string) => new SamlRequestError("INVALID_SAML_REQUEST", detail);

export type Binding = "redirect" | "post";

export interface RawAuthnRequest {
  binding: Binding;
  samlRequest: string;
  relayState: string | undefined;
  /** Redirect binding only: the raw (still URL-encoded) query string, for signature checks. */
  rawQuery?: string;
  sigAlg?: string;
  signature?: string;
}

export interface AuthnRequestInfo {
  id: string;
  issuer: string;
  issueInstant: Date;
  destination: string | undefined;
  acsUrl: string | undefined;
  acsIndex: string | undefined;
  protocolBinding: string | undefined;
  forceAuthn: boolean;
  isPassive: boolean;
  nameIdFormat: string | undefined;
  signedRedirect: boolean;
}

function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) throw invalid("SAMLRequest is not valid base64");
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** raw DEFLATE (Redirect binding), stopping as soon as the output exceeds `limit` bytes. */
async function inflateRawLimited(data: Uint8Array, limit: number): Promise<Uint8Array> {
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        throw invalid(`inflated SAMLRequest exceeds ${limit} bytes`);
      }
      chunks.push(value);
    }
  } catch (e) {
    if (e instanceof SamlRequestError) throw e;
    throw invalid("SAMLRequest is not valid DEFLATE data");
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export async function decodeAuthnRequest(raw: RawAuthnRequest): Promise<string> {
  if (!raw.samlRequest) throw invalid("missing SAMLRequest");
  // base64 inflates by 4/3; bound the encoded size before decoding anything.
  if (raw.samlRequest.length > Math.ceil((MAX_REQUEST_BYTES * 4) / 3) + 1024) throw invalid("SAMLRequest too large");
  const bytes = base64ToBytes(raw.samlRequest);
  const xmlBytes = raw.binding === "redirect" ? await inflateRawLimited(bytes, MAX_REQUEST_BYTES) : bytes;
  if (xmlBytes.byteLength > MAX_REQUEST_BYTES) throw invalid(`SAMLRequest exceeds ${MAX_REQUEST_BYTES} bytes`);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(xmlBytes);
  } catch {
    throw invalid("SAMLRequest is not UTF-8");
  }
}

export function checkRelayState(relayState: string | undefined, maxBytes: number) {
  if (relayState === undefined) return;
  if (new TextEncoder().encode(relayState).byteLength > maxBytes)
    throw new SamlRequestError("RELAY_STATE_TOO_LONG", `RelayState exceeds ${maxBytes} bytes`);
}

function childElements(node: { childNodes: ArrayLike<any> }) {
  return Array.from(node.childNodes).filter((n: any) => n.nodeType === 1) as any[];
}

/**
 * Schema-validate and extract an AuthnRequest. Structural rules beyond the XSD:
 * the root must be samlp:AuthnRequest with Version 2.0 and exactly one direct saml:Issuer.
 */
export async function parseAuthnRequest(
  xml: string,
  validator: SchemaValidator,
  opts: { now: Date; clockSkewSeconds: number; ssoUrl: string },
): Promise<AuthnRequestInfo> {
  const pre = precheckXml(xml, MAX_REQUEST_BYTES);
  if (pre.length) throw invalid(pre.join("; "));
  const schema = await validator.validate(xml, "protocol");
  if (!schema.valid) throw invalid(`schema: ${schema.errors.slice(0, 3).join("; ")}`);

  let doc;
  try {
    doc = parseXmlStrict(xml);
  } catch (e) {
    throw invalid(`not well-formed: ${(e as Error).message}`);
  }
  const root = doc.documentElement!;
  if (root.namespaceURI !== NS_PROTOCOL || root.localName !== "AuthnRequest") throw invalid("root element is not samlp:AuthnRequest");
  if (root.getAttribute("Version") !== "2.0") throw invalid("Version must be 2.0");

  const issuers = childElements(root).filter((e) => e.namespaceURI === NS_ASSERTION && e.localName === "Issuer");
  if (issuers.length !== 1) throw invalid("AuthnRequest must have exactly one Issuer");
  const issuer = (issuers[0].textContent ?? "").trim();
  if (!issuer) throw invalid("empty Issuer");

  const id = root.getAttribute("ID") ?? "";
  if (!id || id.length > 256) throw invalid("missing or oversized ID");

  const issueInstant = new Date(root.getAttribute("IssueInstant") ?? "");
  if (Number.isNaN(issueInstant.getTime())) throw invalid("invalid IssueInstant");
  const skewMs = opts.clockSkewSeconds * 1000;
  if (issueInstant.getTime() > opts.now.getTime() + skewMs) throw invalid("IssueInstant is in the future");
  if (issueInstant.getTime() < opts.now.getTime() - REQUEST_MAX_AGE_SECONDS * 1000 - skewMs)
    throw invalid("AuthnRequest is too old");

  const destination = root.getAttribute("Destination") || undefined;
  if (destination !== undefined && destination !== opts.ssoUrl) throw invalid("Destination does not match this IdP's SSO URL");

  const protocolBinding = root.getAttribute("ProtocolBinding") || undefined;
  if (protocolBinding !== undefined && protocolBinding !== BINDING_POST)
    throw invalid("only the HTTP-POST response binding is supported");

  const acsUrl = root.getAttribute("AssertionConsumerServiceURL") || undefined;
  const acsIndex = root.getAttribute("AssertionConsumerServiceIndex") || undefined;
  if (acsIndex !== undefined && acsUrl === undefined)
    throw invalid("AssertionConsumerServiceIndex is not supported; send AssertionConsumerServiceURL");

  const policy = childElements(root).find((e) => e.namespaceURI === NS_PROTOCOL && e.localName === "NameIDPolicy");
  const nameIdFormat = policy?.getAttribute("Format") || undefined;

  return {
    id,
    issuer,
    issueInstant,
    destination,
    acsUrl,
    acsIndex,
    protocolBinding,
    forceAuthn: root.getAttribute("ForceAuthn") === "true" || root.getAttribute("ForceAuthn") === "1",
    isPassive: root.getAttribute("IsPassive") === "true" || root.getAttribute("IsPassive") === "1",
    nameIdFormat,
    signedRedirect: false,
  };
}

/** NameIDPolicy@Format must be absent, unspecified, or the SP's configured format. */
export function checkNameIdPolicy(info: AuthnRequestInfo, sp: ResolvedServiceProvider) {
  const f = info.nameIdFormat;
  if (f === undefined || f === NAMEID_UNSPECIFIED || f === sp.nameIdFormat) return;
  throw invalid(`NameIDPolicy Format ${f} is not configured for this service provider`);
}

const REDIRECT_SIG_ALGS: Record<string, { hash: string; sha1: boolean }> = {
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": { hash: "sha256", sha1: false },
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": { hash: "sha512", sha1: false },
  "http://www.w3.org/2000/09/xmldsig#rsa-sha1": { hash: "sha1", sha1: true },
};

/** Pull `name=value` pairs from a raw query string without decoding them. */
function rawParam(rawQuery: string, name: string): string | undefined {
  for (const part of rawQuery.split("&")) {
    const eq = part.indexOf("=");
    const k = eq < 0 ? part : part.slice(0, eq);
    if (k === name) return eq < 0 ? "" : part.slice(eq + 1);
  }
  return undefined;
}

/**
 * Enforce the SP's signing policy (SAML Bindings §3.4.4.1). Redirect binding signatures are
 * verified over the octet string built from the *raw* query parameters, in the order
 * SAMLRequest, RelayState, SigAlg. POST-binding (embedded XML) signatures are not supported
 * in v1 (DECISIONS.md D-012).
 */
export function checkRequestSignature(
  raw: RawAuthnRequest,
  sp: ResolvedServiceProvider,
  opts: { allowInsecureSha1: boolean },
): boolean {
  const hasRedirectSig = raw.binding === "redirect" && raw.signature !== undefined;
  if (raw.binding === "post") {
    if (sp.requireSignedAuthnRequests)
      throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "signed AuthnRequests must use the HTTP-Redirect binding");
    return false;
  }
  if (!hasRedirectSig) {
    if (sp.requireSignedAuthnRequests) throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "missing Signature");
    return false;
  }
  if (!sp.spCertificate) {
    // Unsolicited signature from an SP we hold no certificate for: nothing to verify against.
    if (sp.requireSignedAuthnRequests) throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "no SP certificate configured");
    return false;
  }
  const alg = REDIRECT_SIG_ALGS[raw.sigAlg ?? ""];
  if (!alg) throw invalid("unsupported SigAlg");
  if (alg.sha1 && !opts.allowInsecureSha1) throw invalid("SHA-1 signatures are not accepted");
  const q = raw.rawQuery ?? "";
  const req = rawParam(q, "SAMLRequest");
  const relay = rawParam(q, "RelayState");
  const sigAlg = rawParam(q, "SigAlg");
  const sig = rawParam(q, "Signature");
  if (req === undefined || sigAlg === undefined || sig === undefined) throw invalid("malformed signed query string");
  const octets = `SAMLRequest=${req}${relay !== undefined ? `&RelayState=${relay}` : ""}&SigAlg=${sigAlg}`;
  let ok = false;
  try {
    ok = cryptoVerify(
      alg.hash,
      new TextEncoder().encode(octets),
      createPublicKey(sp.spCertificate),
      base64ToBytes(decodeURIComponent(sig)),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "AuthnRequest signature is invalid");
  return true;
}

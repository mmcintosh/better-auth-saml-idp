import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { NAMEID_FORMAT, type ResolvedServiceProvider } from "../types";
import { precheckXml, type SchemaValidator } from "./validator";
import { parseXmlStrict } from "./xml";
import { verifyEnvelopedSignature } from "./xmldsig";

export const NS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
export const NS_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/** Maximum decoded AuthnRequest size. Real requests are well under 8 KiB. */
export const MAX_REQUEST_BYTES = 64 * 1024;
/** How old an AuthnRequest's IssueInstant may be (plus clock skew). */
export const REQUEST_MAX_AGE_SECONDS = 300;

export class SamlRequestError extends Error {
  constructor(
    readonly code: "INVALID_SAML_REQUEST" | "UNSIGNED_SAML_REQUEST" | "RELAY_STATE_TOO_LONG",
    /** For debug logs. May quote short, sanitised fragments of the request (see `logSafe`). */
    readonly detail: string,
  ) {
    super(detail);
  }
}

const invalid = (detail: string) => new SamlRequestError("INVALID_SAML_REQUEST", detail);

/** Attacker-controlled text in debug logs: bounded length, no control characters. */
export function logSafe(s: string, max = 120): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping control characters is the point
  const clean = s.replace(/[\u0000-\u001f\u007f]/g, "?");
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

export type Binding = "redirect" | "post";

export interface RawAuthnRequest {
  binding: Binding;
  samlRequest: string;
  relayState: string | undefined;
  /** Redirect binding: the exact raw parameters the signature covers (see parseRedirectQuery). */
  signed?: { octets: string; sigAlg: string; signature: string };
}

// ---------------------------------------------------------------------------------------
// HTTP-Redirect query parsing
// ---------------------------------------------------------------------------------------

const SAML_PARAMS = ["SAMLRequest", "RelayState", "SigAlg", "Signature"] as const;
type SamlParam = (typeof SAML_PARAMS)[number];

function formDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    throw invalid("malformed percent-encoding in query string");
  }
}

function percentDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    throw invalid("malformed percent-encoding in query string");
  }
}

/**
 * Parse the raw query string ourselves. Parameter NAMES are decoded before matching, so
 * `Relay%53tate` is RelayState here exactly as it would be for any URLSearchParams-based
 * reader; every SAML parameter may appear at most once; and the signed octet string is built
 * from the raw (undecoded) segments of precisely the parameters we then use (Bindings §3.4.4.1).
 */
export function parseRedirectQuery(rawQuery: string): RawAuthnRequest {
  const found: Partial<Record<SamlParam, { raw: string; value: string }>> = {};
  for (const part of rawQuery.split("&")) {
    if (!part) continue;
    const eq = part.indexOf("=");
    const rawKey = eq < 0 ? part : part.slice(0, eq);
    const rawValue = eq < 0 ? "" : part.slice(eq + 1);
    const key = formDecode(rawKey);
    if (!(SAML_PARAMS as readonly string[]).includes(key)) continue;
    if (found[key as SamlParam]) throw invalid(`duplicate ${key} parameter`);
    // Canonical raw form for the octet string: the parameter name as the spec spells it.
    // base64 values keep a literal "+" (some SPs don't escape it); RelayState is form-decoded.
    const value = key === "RelayState" || key === "SigAlg" ? formDecode(rawValue) : percentDecode(rawValue);
    found[key as SamlParam] = { raw: `${key}=${rawValue}`, value };
  }
  const req = found.SAMLRequest;
  if (!req) throw invalid("missing SAMLRequest");
  const out: RawAuthnRequest = { binding: "redirect", samlRequest: req.value, relayState: found.RelayState?.value };
  if (found.Signature || found.SigAlg) {
    if (!found.Signature || !found.SigAlg) throw invalid("Signature and SigAlg must be sent together");
    // A name that needed decoding cannot have been signed as "SAMLRequest"/"RelayState"/…:
    // rebuild the octets only from segments whose raw name is the canonical one.
    const octets = [found.SAMLRequest, found.RelayState, found.SigAlg]
      .flatMap((p) => (p ? [p.raw] : []))
      .join("&");
    out.signed = { octets, sigAlg: found.SigAlg.value, signature: found.Signature.value };
    const rawNames = rawQuery.split("&").map((p) => p.split("=")[0]);
    for (const name of ["SAMLRequest", "RelayState", "SigAlg"] as const)
      if (found[name] && !rawNames.includes(name)) throw invalid(`${name} parameter name is encoded; cannot verify signature`);
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------

function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) throw invalid("SAMLRequest is not valid base64");
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** raw DEFLATE, stopping as soon as the output exceeds `limit` bytes. */
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

/** First non-whitespace byte (after an optional UTF-8 BOM) is "<". */
function looksLikeXml(bytes: Uint8Array): boolean {
  let i = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  while (i < bytes.length && (bytes[i] === 0x20 || bytes[i] === 0x09 || bytes[i] === 0x0a || bytes[i] === 0x0d)) i++;
  return bytes[i] === 0x3c;
}

export async function decodeAuthnRequest(raw: RawAuthnRequest): Promise<string> {
  if (!raw.samlRequest) throw invalid("missing SAMLRequest");
  // base64 inflates by 4/3; bound the encoded size before decoding anything.
  if (raw.samlRequest.length > Math.ceil((MAX_REQUEST_BYTES * 4) / 3) + 1024) throw invalid("SAMLRequest too large");
  const bytes = base64ToBytes(raw.samlRequest);
  // HTTP-POST messages are plain base64 (Bindings §3.5.4), but node-saml/passport-saml DEFLATE
  // them anyway. If the POST payload is not XML text, accept raw DEFLATE too, same size cap.
  const xmlBytes =
    raw.binding === "redirect" || !looksLikeXml(bytes) ? await inflateRawLimited(bytes, MAX_REQUEST_BYTES) : bytes;
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

// ---------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------

export interface RequestedAuthnContext {
  comparison: "exact" | "minimum" | "maximum" | "better";
  classRefs: string[];
  /** AuthnContextDeclRef requests (never satisfiable here). */
  hasDeclRefs: boolean;
}

export interface AuthnRequestInfo {
  id: string;
  issuer: string;
  issueInstant: Date;
  destination: string | undefined;
  acsUrl: string | undefined;
  forceAuthn: boolean;
  isPassive: boolean;
  nameIdFormat: string | undefined;
  subject: { nameId: string; format: string | undefined } | undefined;
  requestedAuthnContext: RequestedAuthnContext | undefined;
}

function childElements(node: { childNodes: ArrayLike<any> }) {
  return Array.from(node.childNodes).filter((n: any) => n.nodeType === 1) as any[];
}

const child = (parent: any, ns: string, name: string) =>
  childElements(parent).filter((e) => e.namespaceURI === ns && e.localName === name);

/** xs:boolean after whitespace collapse. */
function xsBoolean(v: string | null): boolean {
  const t = (v ?? "").trim();
  return t === "true" || t === "1";
}

/** xs:dateTime that states its time zone (a bare local time would depend on our server's zone). */
const DATETIME_WITH_ZONE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

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
  if (!schema.valid) throw invalid(`schema: ${logSafe(schema.errors.slice(0, 2).join("; "), 300)}`);

  let doc: ReturnType<typeof parseXmlStrict>;
  try {
    doc = parseXmlStrict(xml);
  } catch (e) {
    throw invalid(`not well-formed: ${logSafe((e as Error).message)}`);
  }
  const root = doc.documentElement;
  if (!root) throw invalid("no root element");
  if (root.namespaceURI !== NS_PROTOCOL || root.localName !== "AuthnRequest") throw invalid("root element is not samlp:AuthnRequest");
  if ((root.getAttribute("Version") ?? "").trim() !== "2.0") throw invalid("Version must be 2.0");

  const issuers = child(root, NS_ASSERTION, "Issuer");
  if (issuers.length !== 1) throw invalid("AuthnRequest must have exactly one Issuer");
  const issuer = (issuers[0].textContent ?? "").trim();
  if (!issuer) throw invalid("empty Issuer");

  // xs:ID: whitespace-collapsed, so " _abc" and "_abc" are the same ID (and one replay key).
  const id = (root.getAttribute("ID") ?? "").trim();
  if (!id || id.length > 256) throw invalid("missing or oversized ID");

  const rawInstant = (root.getAttribute("IssueInstant") ?? "").trim();
  if (!DATETIME_WITH_ZONE.test(rawInstant)) throw invalid("IssueInstant must be an xs:dateTime with a time zone");
  const issueInstant = new Date(rawInstant);
  if (Number.isNaN(issueInstant.getTime())) throw invalid("invalid IssueInstant");
  const skewMs = opts.clockSkewSeconds * 1000;
  if (issueInstant.getTime() > opts.now.getTime() + skewMs) throw invalid("IssueInstant is in the future");
  if (issueInstant.getTime() < opts.now.getTime() - REQUEST_MAX_AGE_SECONDS * 1000 - skewMs)
    throw invalid("AuthnRequest is too old");

  const destination = root.getAttribute("Destination")?.trim() || undefined;
  if (destination !== undefined && destination !== opts.ssoUrl) throw invalid("Destination does not match this IdP's SSO URL");

  const protocolBinding = root.getAttribute("ProtocolBinding")?.trim() || undefined;
  if (protocolBinding !== undefined && protocolBinding !== BINDING_POST)
    throw invalid("only the HTTP-POST response binding is supported");

  const acsUrl = root.getAttribute("AssertionConsumerServiceURL")?.trim() || undefined;
  const acsIndex = root.getAttribute("AssertionConsumerServiceIndex")?.trim() || undefined;
  if (acsIndex !== undefined && acsUrl === undefined)
    throw invalid("AssertionConsumerServiceIndex is not supported; send AssertionConsumerServiceURL");

  const policy = child(root, NS_PROTOCOL, "NameIDPolicy")[0];
  const nameIdFormat = policy?.getAttribute("Format")?.trim() || undefined;

  // <saml:Subject><saml:NameID>…</saml:NameID></saml:Subject>: the assertion must be about
  // exactly this principal (Core §3.4.1.4). BaseID/EncryptedID can't be matched: refuse.
  let subject: AuthnRequestInfo["subject"];
  const subjectEl = child(root, NS_ASSERTION, "Subject")[0];
  if (subjectEl) {
    if (child(subjectEl, NS_ASSERTION, "BaseID").length || child(subjectEl, NS_ASSERTION, "EncryptedID").length)
      throw invalid("Subject BaseID/EncryptedID is not supported");
    const nameIdEl = child(subjectEl, NS_ASSERTION, "NameID")[0];
    if (nameIdEl) subject = { nameId: (nameIdEl.textContent ?? "").trim(), format: nameIdEl.getAttribute("Format")?.trim() || undefined };
  }

  let requestedAuthnContext: RequestedAuthnContext | undefined;
  const rac = child(root, NS_PROTOCOL, "RequestedAuthnContext")[0];
  if (rac) {
    const comparison = ((rac.getAttribute("Comparison") ?? "exact").trim() || "exact") as RequestedAuthnContext["comparison"];
    requestedAuthnContext = {
      comparison,
      classRefs: child(rac, NS_ASSERTION, "AuthnContextClassRef").map((e) => (e.textContent ?? "").trim()),
      hasDeclRefs: child(rac, NS_ASSERTION, "AuthnContextDeclRef").length > 0,
    };
  }

  return {
    id,
    issuer,
    issueInstant,
    destination,
    acsUrl,
    forceAuthn: xsBoolean(root.getAttribute("ForceAuthn")),
    isPassive: xsBoolean(root.getAttribute("IsPassive")),
    nameIdFormat,
    subject,
    requestedAuthnContext,
  };
}

// ---------------------------------------------------------------------------------------
// Policy: conditions answered with a SAML error Response (not an error page), because the
// SP and ACS URL are known-good by now (Core §3.2.2.2 status codes).
// ---------------------------------------------------------------------------------------

export interface SamlStatus {
  code: "Requester" | "Responder";
  subCode?: "InvalidNameIDPolicy" | "NoAuthnContext" | "NoPassive" | "UnknownPrincipal" | "RequestDenied";
  message: string;
}

/** NameIDPolicy@Format must be absent, unspecified, or the SP's configured format. */
export function nameIdPolicyStatus(info: AuthnRequestInfo, sp: ResolvedServiceProvider): SamlStatus | undefined {
  const f = info.nameIdFormat;
  if (f === undefined || f === NAMEID_FORMAT.unspecified || f === sp.nameIdFormat) return;
  return { code: "Responder", subCode: "InvalidNameIDPolicy", message: "The requested NameID format is not available" };
}

/**
 * The IdP asserts exactly one AuthnContextClassRef (`ours`) and knows no ordering between
 * classes, so: exact/minimum/maximum are satisfied only if `ours` is listed; "better" never is.
 */
export function authnContextStatus(info: AuthnRequestInfo, ours: string): SamlStatus | undefined {
  const r = info.requestedAuthnContext;
  if (!r) return;
  const ok = !r.hasDeclRefs && r.comparison !== "better" && r.classRefs.includes(ours);
  if (ok) return;
  return { code: "Responder", subCode: "NoAuthnContext", message: "The requested authentication context is not available" };
}

// ---------------------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------------------

const REDIRECT_SIG_ALGS: Record<string, { hash: string; sha1: boolean }> = {
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": { hash: "sha256", sha1: false },
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": { hash: "sha512", sha1: false },
  "http://www.w3.org/2000/09/xmldsig#rsa-sha1": { hash: "sha1", sha1: true },
};

/**
 * Enforce the SP's signing policy. Redirect-binding signatures are verified over octets built
 * by parseRedirectQuery; HTTP-POST signatures are enveloped XML signatures on the AuthnRequest,
 * verified with the XSW rules in xmldsig.ts (D-025). `xml` is the decoded request (POST only).
 */
export function checkRequestSignature(
  raw: RawAuthnRequest,
  sp: ResolvedServiceProvider,
  opts: { allowInsecureSha1: boolean },
  xml?: string,
): boolean {
  if (raw.binding === "post") return checkPostSignature(xml, sp, opts);
  if (!raw.signed) {
    if (sp.requireSignedAuthnRequests) throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "missing Signature");
    return false;
  }
  if (sp.spCertificates.length === 0) {
    if (sp.requireSignedAuthnRequests) throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "no SP certificate configured");
    return false;
  }
  const alg = REDIRECT_SIG_ALGS[raw.signed.sigAlg];
  if (!alg) throw invalid("unsupported SigAlg");
  if (alg.sha1 && !opts.allowInsecureSha1) throw invalid("SHA-1 signatures are not accepted");
  // Any configured certificate may have signed (SPs rotate keys; Cloudflare Access publishes two).
  const octets = new TextEncoder().encode(raw.signed.octets);
  let signature: Uint8Array;
  try {
    signature = base64ToBytes(raw.signed.signature);
  } catch {
    throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "AuthnRequest signature is not valid base64");
  }
  const ok = sp.spCertificates.some((cert) => {
    try {
      return cryptoVerify(alg.hash, octets, createPublicKey(cert), signature);
    } catch {
      return false;
    }
  });
  if (!ok) throw new SamlRequestError("UNSIGNED_SAML_REQUEST", "AuthnRequest signature is invalid");
  return true;
}

const unsigned = (detail: string) => new SamlRequestError("UNSIGNED_SAML_REQUEST", detail);

function hasComments(node: any): boolean {
  for (let n = node.firstChild; n; n = n.nextSibling) if (n.nodeType === 8 || (n.nodeType === 1 && hasComments(n))) return true;
  return false;
}

function checkPostSignature(xml: string | undefined, sp: ResolvedServiceProvider, opts: { allowInsecureSha1: boolean }): boolean {
  if (xml === undefined) throw new Error("checkRequestSignature: the POST binding needs the decoded XML");
  const doc = parseXmlStrict(xml);
  const count = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").length;
  if (count === 0) {
    if (sp.requireSignedAuthnRequests) throw unsigned("missing Signature");
    return false;
  }
  // As with the Redirect binding, a signature is only checked when the SP has certificates.
  if (sp.spCertificates.length === 0) {
    if (sp.requireSignedAuthnRequests) throw unsigned("no SP certificate configured");
    return false;
  }
  if (count > 1) throw unsigned(`${count} Signature elements`);
  // Comments are invisible to exclusive c14n, so text split by one is still "signed"; nothing
  // legitimate needs them, and refusing them closes the comment-truncation class of bugs.
  if (hasComments(doc)) throw unsigned("comments are not allowed in a signed AuthnRequest");
  const r = verifyEnvelopedSignature(xml, doc, doc.documentElement, sp.spCertificates, { allowSha1: opts.allowInsecureSha1 });
  if (!r.present) throw unsigned("the Signature is not a child of the AuthnRequest");
  if (r.valid !== true) throw unsigned(`AuthnRequest signature is invalid: ${logSafe(r.problem ?? "", 200)}`);
  return true;
}


// Single Logout messages (D-028): parse the SP's LogoutRequest / LogoutResponse, build ours, and
// encode them for the HTTP-Redirect (query-signed) or HTTP-POST (XML-signed) binding.
import { sign as cryptoSign } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import type { ResolvedSamlIdpOptions } from "../types";
import { SIGNATURE_ALGORITHM_URI } from "./idp";
import { child, DATETIME_WITH_ZONE, invalid, logSafe, MAX_REQUEST_BYTES, NS_ASSERTION, NS_PROTOCOL, REQUEST_MAX_AGE_SECONDS } from "./request";
import { escapeXml, newSamlId, signElement } from "./response";
import { precheckXml, type SchemaValidator } from "./validator";
import { parseXmlStrict } from "./xml";

export const SLO_PATH = "/saml2/idp/slo";
const STATUS = "urn:oasis:names:tc:SAML:2.0:status:";

export interface LogoutRequestInfo {
  id: string;
  issuer: string;
  nameId: string;
  nameIdFormat: string | undefined;
  sessionIndexes: string[];
}

export interface LogoutResponseInfo {
  id: string;
  issuer: string;
  inResponseTo: string;
  /** Top-level and second-level status codes, e.g. ["Success"] or ["Success", "PartialLogout"]. */
  status: string[];
}

type Doc = ReturnType<typeof parseXmlStrict>;

/** Shared checks: size, DOCTYPE, XSD, strict parse, root element, Version, Issuer, ID, time, Destination. */
async function parseMessage(xml: string, rootName: "LogoutRequest" | "LogoutResponse", validator: SchemaValidator, opts: { now: Date; clockSkewSeconds: number; sloUrl: string }) {
  const pre = precheckXml(xml, MAX_REQUEST_BYTES);
  if (pre.length) throw invalid(pre.join("; "));
  const schema = await validator.validate(xml, "protocol");
  if (!schema.valid) throw invalid(`schema: ${logSafe(schema.errors.slice(0, 2).join("; "), 300)}`);
  let doc: Doc;
  try {
    doc = parseXmlStrict(xml);
  } catch (e) {
    throw invalid(`not well-formed: ${logSafe((e as Error).message)}`);
  }
  const root = doc.documentElement as any;
  if (!root || root.namespaceURI !== NS_PROTOCOL || root.localName !== rootName) throw invalid(`root element is not samlp:${rootName}`);
  if ((root.getAttribute("Version") ?? "").trim() !== "2.0") throw invalid("Version must be 2.0");
  const issuers = child(root, NS_ASSERTION, "Issuer");
  if (issuers.length !== 1) throw invalid(`${rootName} must have exactly one Issuer`);
  const issuer = (issuers[0].textContent ?? "").trim();
  if (!issuer) throw invalid("empty Issuer");
  const id = (root.getAttribute("ID") ?? "").trim();
  if (!id || id.length > 256) throw invalid("missing or oversized ID");
  const rawInstant = (root.getAttribute("IssueInstant") ?? "").trim();
  if (!DATETIME_WITH_ZONE.test(rawInstant)) throw invalid("IssueInstant must be an xs:dateTime with a time zone");
  const instant = new Date(rawInstant).getTime();
  const skew = opts.clockSkewSeconds * 1000;
  if (Number.isNaN(instant) || instant > opts.now.getTime() + skew) throw invalid("IssueInstant is in the future");
  if (instant < opts.now.getTime() - REQUEST_MAX_AGE_SECONDS * 1000 - skew) throw invalid(`${rootName} is too old`);
  const destination = root.getAttribute("Destination")?.trim() || undefined;
  if (destination !== undefined && destination !== opts.sloUrl) throw invalid("Destination does not match this IdP's logout URL");
  return { root, issuer, id };
}

export async function parseLogoutRequest(xml: string, validator: SchemaValidator, opts: { now: Date; clockSkewSeconds: number; sloUrl: string }): Promise<LogoutRequestInfo> {
  const { root, issuer, id } = await parseMessage(xml, "LogoutRequest", validator, opts);
  const notOnOrAfter = root.getAttribute("NotOnOrAfter")?.trim();
  if (notOnOrAfter && !(new Date(notOnOrAfter).getTime() > opts.now.getTime() - opts.clockSkewSeconds * 1000)) throw invalid("LogoutRequest has expired");
  if (child(root, NS_ASSERTION, "BaseID").length || child(root, NS_ASSERTION, "EncryptedID").length)
    throw invalid("BaseID/EncryptedID in LogoutRequest is not supported");
  const nameIds = child(root, NS_ASSERTION, "NameID");
  if (nameIds.length !== 1) throw invalid("LogoutRequest must have exactly one NameID");
  return {
    id,
    issuer,
    nameId: (nameIds[0].textContent ?? "").trim(),
    nameIdFormat: nameIds[0].getAttribute("Format")?.trim() || undefined,
    sessionIndexes: child(root, NS_PROTOCOL, "SessionIndex").map((e: any) => (e.textContent ?? "").trim()),
  };
}

export async function parseLogoutResponse(xml: string, validator: SchemaValidator, opts: { now: Date; clockSkewSeconds: number; sloUrl: string }): Promise<LogoutResponseInfo> {
  const { root, issuer, id } = await parseMessage(xml, "LogoutResponse", validator, opts);
  const inResponseTo = (root.getAttribute("InResponseTo") ?? "").trim();
  if (!inResponseTo) throw invalid("LogoutResponse has no InResponseTo");
  const status: string[] = [];
  for (let s = child(child(root, NS_PROTOCOL, "Status")[0], NS_PROTOCOL, "StatusCode")[0]; s; s = child(s, NS_PROTOCOL, "StatusCode")[0])
    status.push((s.getAttribute("Value") ?? "").replace(STATUS, ""));
  return { id, issuer, inResponseTo, status };
}

const instant = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
const NS_DECL = `xmlns:samlp="${NS_PROTOCOL}" xmlns:saml="${NS_ASSERTION}"`;

export function buildLogoutRequest(o: {
  issuer: string;
  destination: string;
  nameId: string;
  nameIdFormat: string;
  sessionIndex: string;
  now: Date;
  lifetimeSeconds: number;
}): { id: string; xml: string } {
  const id = newSamlId();
  const xml =
    `<samlp:LogoutRequest ${NS_DECL} ID="${id}" Version="2.0" IssueInstant="${instant(o.now)}" Destination="${escapeXml(o.destination)}" ` +
    `NotOnOrAfter="${instant(new Date(o.now.getTime() + o.lifetimeSeconds * 1000))}" Reason="urn:oasis:names:tc:SAML:2.0:logout:user">` +
    `<saml:Issuer>${escapeXml(o.issuer)}</saml:Issuer>` +
    `<saml:NameID Format="${escapeXml(o.nameIdFormat)}">${escapeXml(o.nameId)}</saml:NameID>` +
    `<samlp:SessionIndex>${escapeXml(o.sessionIndex)}</samlp:SessionIndex>` +
    `</samlp:LogoutRequest>`;
  return { id, xml };
}

export function buildLogoutResponse(o: { issuer: string; destination: string; inResponseTo: string; status: string[]; now: Date }): string {
  const [top = "Success", sub] = o.status;
  const code = sub
    ? `<samlp:StatusCode Value="${STATUS}${top}"><samlp:StatusCode Value="${STATUS}${sub}"/></samlp:StatusCode>`
    : `<samlp:StatusCode Value="${STATUS}${top}"/>`;
  return (
    `<samlp:LogoutResponse ${NS_DECL} ID="${newSamlId()}" Version="2.0" IssueInstant="${instant(o.now)}" ` +
    `Destination="${escapeXml(o.destination)}" InResponseTo="${escapeXml(o.inResponseTo)}">` +
    `<saml:Issuer>${escapeXml(o.issuer)}</saml:Issuer><samlp:Status>${code}</samlp:Status></samlp:LogoutResponse>`
  );
}

type Signing = ResolvedSamlIdpOptions["signing"];

function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** HTTP-Redirect binding: DEFLATE + base64, query signed over SAMLx&RelayState&SigAlg (Bindings §3.4.4.1). */
export function redirectBindingUrl(url: string, param: "SAMLRequest" | "SAMLResponse", xml: string, relayState: string | undefined, signing: Signing): string {
  let q = `${param}=${encodeURIComponent(toBase64(deflateRawSync(new TextEncoder().encode(xml))))}`;
  if (relayState !== undefined) q += `&RelayState=${encodeURIComponent(relayState)}`;
  q += `&SigAlg=${encodeURIComponent(SIGNATURE_ALGORITHM_URI[signing.signatureAlgorithm])}`;
  const hash = signing.signatureAlgorithm === "rsa-sha512" ? "sha512" : signing.signatureAlgorithm === "rsa-sha1" ? "sha1" : "sha256";
  q += `&Signature=${encodeURIComponent(toBase64(cryptoSign(hash, new TextEncoder().encode(q), signing.keyObject)))}`;
  return `${url}${url.includes("?") ? "&" : "?"}${q}`;
}

/** HTTP-POST binding: an enveloped signature after the Issuer, base64 for the form. */
export function signedPostMessage(xml: string, root: "LogoutRequest" | "LogoutResponse", signing: Signing): string {
  const signed = signElement(xml, `/*[local-name(.)='${root}']`, { reference: `/*[local-name(.)='${root}']/*[local-name(.)='Issuer']`, action: "after" }, signing);
  return toBase64(new TextEncoder().encode(signed));
}

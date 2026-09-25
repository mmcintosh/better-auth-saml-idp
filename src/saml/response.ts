import type { KeyObject } from "node:crypto";
import { SignedXml } from "xml-crypto";
import type { SamlStatus } from "./request";
import type { DigestAlgorithm, ResolvedSamlIdpOptions, SamlAttributeValue, SignatureAlgorithm } from "../types";
import { SIGNATURE_ALGORITHM_URI } from "./idp";
import { type AssertionEncryption, encryptAssertionInResponse } from "./encrypt";

const DIGEST_URI: Record<DigestAlgorithm, string> = {
  sha256: "http://www.w3.org/2001/04/xmlenc#sha256",
  sha512: "http://www.w3.org/2001/04/xmlenc#sha512",
  sha1: "http://www.w3.org/2000/09/xmldsig#sha1",
};
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

export function escapeXml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c]!);
}

/** SAML IDs must be NCNames: start with a letter or underscore. */
export function newSamlId(): string {
  const b = crypto.getRandomValues(new Uint8Array(20));
  return `_${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;
}

const instant = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

export interface BuildResponseInput {
  requestId: string;
  acsUrl: string;
  audience: string;
  nameId: string;
  nameIdFormat: string;
  attributes: Record<string, SamlAttributeValue>;
  authnInstant: Date;
  sessionIndex: string;
  now: Date;
}

function attributeStatement(attributes: Record<string, SamlAttributeValue>): string {
  const entries = Object.entries(attributes).filter(([, v]) => v !== undefined && v !== null);
  if (!entries.length) return "";
  const attrs = entries
    .map(([name, value]) => {
      const values = (Array.isArray(value) ? value : [value])
        // No xsi:type="xs:string": the "xs" prefix would only appear inside an attribute
        // value, which exclusive c14n does not treat as visibly used, leaving the prefix's
        // namespace binding outside the signature.
        .map((v) => `<saml:AttributeValue>${escapeXml(String(v))}</saml:AttributeValue>`)
        .join("");
      return `<saml:Attribute Name="${escapeXml(name)}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">${values}</saml:Attribute>`;
    })
    .join("");
  return `<saml:AttributeStatement>${attrs}</saml:AttributeStatement>`;
}

/** The unsigned Response document, with every field from SPEC §6 step 7. */
export function buildResponseXml(options: ResolvedSamlIdpOptions, input: BuildResponseInput) {
  const responseId = newSamlId();
  const assertionId = newSamlId();
  const issueInstant = instant(input.now);
  const notBefore = instant(new Date(input.now.getTime() - options.clockSkewSeconds * 1000));
  const notOnOrAfter = instant(new Date(input.now.getTime() + options.assertionLifetimeSeconds * 1000));
  const e = escapeXml;
  const xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${e(input.acsUrl)}" InResponseTo="${e(input.requestId)}">` +
    `<saml:Issuer>${e(options.entityId)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `<saml:Assertion ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">` +
    `<saml:Issuer>${e(options.entityId)}</saml:Issuer>` +
    `<saml:Subject>` +
    `<saml:NameID Format="${e(input.nameIdFormat)}">${e(input.nameId)}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${e(input.acsUrl)}" InResponseTo="${e(input.requestId)}"/>` +
    `</saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestriction><saml:Audience>${e(input.audience)}</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${instant(input.authnInstant)}" SessionIndex="${e(input.sessionIndex)}">` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>${e(options.authnContextClassRef)}</saml:AuthnContextClassRef></saml:AuthnContext>` +
    `</saml:AuthnStatement>` +
    attributeStatement(input.attributes) +
    `</saml:Assertion>` +
    `</samlp:Response>`;
  return { xml, responseId, assertionId };
}

function sign(
  xml: string,
  target: "Assertion" | "Response",
  signing: { keyObject: KeyObject; certificate: string; signatureAlgorithm: SignatureAlgorithm; digestAlgorithm: DigestAlgorithm },
): string {
  const sig = new SignedXml({
    privateKey: signing.keyObject,
    publicCert: signing.certificate,
    signatureAlgorithm: SIGNATURE_ALGORITHM_URI[signing.signatureAlgorithm] as any,
    canonicalizationAlgorithm: EXC_C14N,
  });
  sig.addReference({
    xpath: `/*[local-name(.)='Response']${target === "Assertion" ? "/*[local-name(.)='Assertion']" : ""}`,
    transforms: [ENVELOPED, EXC_C14N],
    digestAlgorithm: DIGEST_URI[signing.digestAlgorithm],
  });
  // SAML schema order: the Signature element follows the Issuer.
  sig.computeSignature(xml, {
    prefix: "ds",
    location: {
      reference: `/*[local-name(.)='Response']${target === "Assertion" ? "/*[local-name(.)='Assertion']" : ""}/*[local-name(.)='Issuer']`,
      action: "after",
    },
  });
  return sig.getSignedXml();
}

/**
 * Build and sign per `options.signing`; returns the XML and its base64 form for the POST binding.
 * With `encryption` (the SP's, D-020): sign the Assertion, encrypt it into an
 * EncryptedAssertion, then sign the Response ("sign-then-encrypt", so the SP verifies the
 * assertion signature after decrypting). An encrypted assertion is always signed when the
 * Response is not, so the SP never receives an unsigned assertion.
 */
export function buildSignedResponse(options: ResolvedSamlIdpOptions, input: BuildResponseInput, encryption?: AssertionEncryption) {
  const built = buildResponseXml(options, input);
  let xml = built.xml;
  const signAssertion = options.signing.signAssertion || (encryption !== undefined && !options.signing.signResponse);
  if (signAssertion) xml = sign(xml, "Assertion", options.signing);
  if (encryption) xml = encryptAssertionInResponse(xml, encryption);
  if (options.signing.signResponse) xml = sign(xml, "Response", options.signing);
  return { ...built, xml, base64: toBase64(xml), encrypted: encryption !== undefined };
}

function toBase64(xml: string): string {
  const bytes = new TextEncoder().encode(xml);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

const STATUS = "urn:oasis:names:tc:SAML:2.0:status:";

/**
 * A signed, assertion-free Response carrying a SAML error status (Core §3.2.2.2), sent to a
 * validated ACS URL so the SP learns why (NoPassive, NoAuthnContext, …). Always signed.
 */
export function buildSignedErrorResponse(
  options: ResolvedSamlIdpOptions,
  input: { requestId: string; acsUrl: string; status: SamlStatus; now: Date },
) {
  const e = escapeXml;
  const responseId = newSamlId();
  const sub = input.status.subCode ? `<samlp:StatusCode Value="${STATUS}${input.status.subCode}"/>` : "";
  const xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${responseId}" Version="2.0" IssueInstant="${instant(input.now)}" Destination="${e(input.acsUrl)}" InResponseTo="${e(input.requestId)}">` +
    `<saml:Issuer>${e(options.entityId)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="${STATUS}${input.status.code}">${sub}</samlp:StatusCode>` +
    `<samlp:StatusMessage>${e(input.status.message)}</samlp:StatusMessage></samlp:Status>` +
    `</samlp:Response>`;
  const signed = sign(xml, "Response", options.signing);
  return { xml: signed, responseId, base64: toBase64(signed) };
}

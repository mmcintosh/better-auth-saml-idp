// The IdP's SAML metadata document (D-074), written directly. It replaced samlify's
// IdentityProvider().getMetadata(), the last thing the plugin used samlify for, and is the same
// document byte for byte: test/unit/metadata-builder.test.ts compares the two for every option
// that changes it. Two details keep that true:
//  - Element order follows the metadata schema (SSODescriptorType): KeyDescriptor,
//    SingleLogoutService, NameIDFormat, SingleSignOnService. samlify put SingleLogoutService
//    last, and the plugin moved it by re-parsing and re-serializing with xmldom (D-028).
//  - So with Single Logout, empty elements are self-closing and attributes are escaped as
//    xmldom serializes them; without it, as samlify wrote them (`<X …></X>`, all five entities).
import type { ResolvedSamlIdpOptions, ResolvedServiceProvider } from "../types";
import type { IdpIdentity } from "./identity";
import { escapeXml } from "./response";

export const BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
export const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

const MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

/** A PEM certificate as metadata carries it: the base64 body, no armour, no whitespace. */
export const certificateBody = (pem: string) => pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");

/** xmldom's serializer: `&`, `<`, `>` and `"` in attributes; `&`, `<`, `>` in text. */
const xmldomAttr = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] as string);
const xmldomText = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c] as string);

/**
 * Whether metadata may promise that every AuthnRequest is signed: only when every SP in code
 * requires it, and no registry could add one that doesn't. Per-SP enforcement is the SSO endpoint's.
 */
export function wantsSignedRequests(options: ResolvedSamlIdpOptions, serviceProviders: readonly ResolvedServiceProvider[]): boolean {
  return options.registry === undefined && serviceProviders.length > 0 && serviceProviders.every((sp) => sp.requestSignatures === "require");
}

/**
 * The unsigned metadata of one IdP identity (the root's, or a tenant's, D-052), advertising the
 * NameID formats of that identity's SPs in code, in order, without repeats.
 */
export function buildIdpMetadata(options: ResolvedSamlIdpOptions, identity: IdpIdentity, serviceProviders: readonly ResolvedServiceProvider[]): string {
  const slo = options.singleLogout;
  const attr = slo ? xmldomAttr : escapeXml;
  const text = slo ? xmldomText : escapeXml;
  const empty = (name: string, binding: string, location: string) =>
    slo ? `<${name} Binding="${attr(binding)}" Location="${attr(location)}"/>` : `<${name} Binding="${attr(binding)}" Location="${attr(location)}"></${name}>`;

  const certificates = [identity.signing.certificate, ...identity.signing.additionalCertificates];
  const keys = certificates
    .map((pem) => `<KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="${DS}"><ds:X509Data><ds:X509Certificate>${certificateBody(pem)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>`)
    .join("");
  const logout = slo ? empty("SingleLogoutService", BINDING_REDIRECT, identity.sloUrl) + empty("SingleLogoutService", BINDING_POST, identity.sloUrl) : "";
  const formats = [...new Set(serviceProviders.map((sp) => sp.nameIdFormat))].map((f) => `<NameIDFormat>${text(f)}</NameIDFormat>`).join("");
  const sso = empty("SingleSignOnService", BINDING_REDIRECT, identity.ssoUrl) + empty("SingleSignOnService", BINDING_POST, identity.ssoUrl);

  return (
    `<EntityDescriptor xmlns="${MD}" xmlns:assertion="${ASSERTION}" xmlns:ds="${DS}" entityID="${attr(identity.entityId)}">` +
    `<IDPSSODescriptor WantAuthnRequestsSigned="${wantsSignedRequests(options, serviceProviders)}" protocolSupportEnumeration="${PROTOCOL}">` +
    keys +
    logout +
    formats +
    sso +
    `</IDPSSODescriptor></EntityDescriptor>`
  );
}

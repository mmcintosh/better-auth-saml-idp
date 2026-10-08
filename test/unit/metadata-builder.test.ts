// D-074: the metadata builder that replaced samlify must produce the same document byte for byte.
// The reference below is the code it replaced: samlify's IdentityProvider().getMetadata(), then the
// schema reordering the metadata endpoint used to apply (D-028). samlify stays a devDependency for
// this comparison and for the test SPs; the published package no longer depends on it.
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import fc from "fast-check";
import * as samlify from "samlify";
import { describe, expect, inject, it } from "vitest";
import { resolveOptions } from "../../src/options";
import { type IdpIdentity, rootIdentity, tenantIdentity } from "../../src/saml/identity";
import { BINDING_POST, BINDING_REDIRECT, buildIdpMetadata, wantsSignedRequests } from "../../src/saml/metadata";
import { SIGNATURE_ALGORITHM_URI } from "../../src/saml/idp";
import { defaultSchemaValidator } from "../../src/saml/validator";
import { baseOptions } from "../support/config";
import type { ResolvedSamlIdpOptions, ResolvedServiceProvider } from "../../src/types";

const keys = inject("keys");
const MD = "urn:oasis:names:tc:SAML:2.0:metadata";

/** The removed code, verbatim in behaviour: samlify, then SingleLogoutService moved into schema order. */
function legacyMetadata(options: ResolvedSamlIdpOptions, identity: IdpIdentity, sps: readonly ResolvedServiceProvider[]): string {
  const warn = console.warn;
  console.warn = () => {};
  let xml: string;
  try {
    xml = samlify
      .IdentityProvider({
        entityID: identity.entityId,
        privateKey: identity.signing.privateKey,
        signingCert: [identity.signing.certificate, ...identity.signing.additionalCertificates],
        isAssertionEncrypted: false,
        wantAuthnRequestsSigned: options.registry === undefined && sps.length > 0 && sps.every((sp) => sp.requestSignatures === "require"),
        requestSignatureAlgorithm: SIGNATURE_ALGORITHM_URI[identity.signing.signatureAlgorithm],
        nameIDFormat: [...new Set(sps.map((sp) => sp.nameIdFormat))],
        singleSignOnService: [
          { Binding: BINDING_REDIRECT, Location: identity.ssoUrl },
          { Binding: BINDING_POST, Location: identity.ssoUrl },
        ],
        ...(options.singleLogout
          ? {
              singleLogoutService: [
                { Binding: BINDING_REDIRECT, Location: identity.sloUrl },
                { Binding: BINDING_POST, Location: identity.sloUrl },
              ],
            }
          : {}),
      })
      .getMetadata();
  } finally {
    console.warn = warn;
  }
  if (!xml.includes("SingleLogoutService")) return xml;
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const idp = doc.getElementsByTagNameNS(MD, "IDPSSODescriptor")[0]!;
  const kids = Array.from(idp.childNodes as ArrayLike<any>).filter((n: any) => n.nodeType === 1 && n.namespaceURI === MD);
  const slo = kids.filter((n: any) => n.localName === "SingleLogoutService");
  const anchor = kids.find((n: any) => n.localName === "ManageNameIDService" || n.localName === "NameIDFormat" || n.localName === "SingleSignOnService");
  for (const n of slo) idp.insertBefore(n, anchor);
  return new XMLSerializer().serializeToString(doc);
}

const sp = (id: string, extra: Record<string, unknown> = {}) => ({ id, entityId: `https://${id}.test/sp`, acsUrls: [`https://${id}.test/acs`], ...extra });

/** Every option that changes the document, alone and together. */
const variants: [string, Record<string, unknown>][] = [
  ["defaults", {}],
  ["Single Logout", { singleLogout: { enabled: true } }],
  ["a second certificate (rotation)", { signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate, additionalCertificates: [keys.idpNext.certificate] } }],
  ["no SPs in code (registry)", { serviceProviders: [], registry: { enabled: true } }],
  ["several NameID formats, with a repeat", { serviceProviders: [sp("a", { nameIdFormat: "persistent" }), sp("b"), sp("c", { nameIdFormat: "transient" }), sp("d", { nameIdFormat: "persistent" })] }],
  ["every SP requires signed requests", { serviceProviders: [sp("a", { requestSignatures: "require", spCertificates: keys.sp.certificate })] }],
  ["signed requests required, but a registry", { serviceProviders: [sp("a", { requestSignatures: "require", spCertificates: keys.sp.certificate })], registry: { enabled: true } }],
  ["SHA-512 signatures", { signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate, signatureAlgorithm: "rsa-sha512", digestAlgorithm: "sha512" } }],
  [
    "everything at once",
    {
      singleLogout: { enabled: true },
      signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate, additionalCertificates: [keys.idpNext.certificate] },
      serviceProviders: [sp("a", { nameIdFormat: "persistent", requestSignatures: "require", spCertificates: keys.sp.certificate }), sp("b", { nameIdFormat: "unspecified", requestSignatures: "require", spCertificates: keys.sp.certificate })],
    },
  ],
];

describe("IdP metadata builder = what samlify produced (D-074)", () => {
  for (const [label, overrides] of variants) {
    for (const base of ["https://auth.test/api/auth", "https://idp.example.com"]) {
      it(`${label} · ${base}`, () => {
        const options = resolveOptions(baseOptions(overrides as any));
        const identity = rootIdentity(options, base);
        expect(buildIdpMetadata(options, identity, options.serviceProviders)).toBe(legacyMetadata(options, identity, options.serviceProviders));
      });
    }
  }

  it("a tenant's identity (its own entity ID and URLs), with and without Single Logout", () => {
    for (const singleLogout of [false, true]) {
      const options = resolveOptions(baseOptions({ singleLogout: { enabled: singleLogout }, serviceProviders: [], registry: { enabled: true } } as any));
      const identity = tenantIdentity(options, "https://auth.test/api/auth", { organizationId: "org_1", tenantKey: "acme" });
      expect(buildIdpMetadata(options, identity, [])).toBe(legacyMetadata(options, identity, []));
    }
  });

  it("escaping: entity IDs and URLs with & < > \" ', with and without Single Logout", () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[a-z&<>"' ]{1,12}$/), fc.boolean(), (junk, singleLogout) => {
        const options = resolveOptions(baseOptions({ singleLogout: { enabled: singleLogout } } as any));
        const identity: IdpIdentity = { ...rootIdentity(options, "https://auth.test/api/auth"), entityId: `https://idp.test/${junk}`, ssoUrl: `https://idp.test/sso?q=${junk}`, sloUrl: `https://idp.test/slo?q=${junk}` };
        expect(buildIdpMetadata(options, identity, options.serviceProviders)).toBe(legacyMetadata(options, identity, options.serviceProviders));
      }),
      { numRuns: 200 },
    );
  });

  it("the document is valid against the SAML metadata schema, with and without Single Logout", async () => {
    for (const singleLogout of [false, true]) {
      const options = resolveOptions(baseOptions({ singleLogout: { enabled: singleLogout } } as any));
      const xml = buildIdpMetadata(options, rootIdentity(options, "https://auth.test/api/auth"), options.serviceProviders);
      expect(await defaultSchemaValidator().validate(xml, "metadata")).toEqual({ valid: true });
    }
  });

  it("wantsSignedRequests: only when every SP in code requires it and there's no registry", () => {
    const opts = (o: Record<string, unknown>) => resolveOptions(baseOptions(o as any));
    const strict = sp("a", { requestSignatures: "require", spCertificates: keys.sp.certificate });
    expect(wantsSignedRequests(opts({ serviceProviders: [strict] }), opts({ serviceProviders: [strict] }).serviceProviders)).toBe(true);
    expect(wantsSignedRequests(opts({ serviceProviders: [strict, sp("b")] }), opts({ serviceProviders: [strict, sp("b")] }).serviceProviders)).toBe(false);
    expect(wantsSignedRequests(opts({ serviceProviders: [strict], registry: { enabled: true } }), [])).toBe(false);
    expect(wantsSignedRequests(opts({ serviceProviders: [], registry: { enabled: true } }), [])).toBe(false);
  });
});

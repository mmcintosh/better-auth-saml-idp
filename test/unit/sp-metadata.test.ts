import { SAML } from "@node-saml/node-saml";
import * as samlify from "samlify";
import { describe, expect, inject, it } from "vitest";
import { serviceProviderFromMetadata, SpMetadataError } from "../../src/saml/sp-metadata";
import { NAMEID_FORMAT } from "../../src/types";
import cloudflare from "../fixtures/sp-metadata/cloudflare-access.xml?raw";

const keys = inject("keys");
const b64Body = (pem: string) => pem.replace(/-----[^-]+-----|\s+/g, "");

const md = (sp: string, extra = "") =>
  `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://sp.test/md"${extra}>${sp}</md:EntityDescriptor>`;
const spsso = (inner: string, attrs = "") =>
  `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"${attrs}>${inner}</md:SPSSODescriptor>`;
const acs = (binding: string, loc: string, index: number, isDefault?: boolean) =>
  `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:${binding}" Location="${loc}" index="${index}"${isDefault === undefined ? "" : ` isDefault="${isDefault}"`}/>`;
const keyDesc = (pem: string, use?: string) =>
  `<md:KeyDescriptor${use ? ` use="${use}"` : ""}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${b64Body(pem)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;

describe("serviceProviderFromMetadata", () => {
  it("reads Cloudflare Access's real (signed) SP metadata", async () => {
    const r = await serviceProviderFromMetadata(cloudflare, { id: "cf" });
    const sp = r.serviceProvider;
    expect(sp.id).toBe("cf");
    expect(sp.entityId).toBe("https://aged-bird-8df2.cloudflareaccess.com/cdn-cgi/access/callback");
    expect(sp.acsUrls[0]).toBe("https://aged-bird-8df2.cloudflareaccess.com/cdn-cgi/access/callback");
    expect(sp.requireSignedAuthnRequests).toBe(true);
    expect((sp.spCertificate as string[]).length).toBeGreaterThanOrEqual(1);
    for (const pem of sp.spCertificate as string[]) expect(pem).toMatch(/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n$/);
  });

  it("reads samlify-generated SP metadata", async () => {
    const xml = samlify
      .ServiceProvider({
        entityID: "https://samlify.test/sp",
        authnRequestsSigned: true,
        signingCert: keys.sp.certificate,
        nameIDFormat: [NAMEID_FORMAT.persistent],
        assertionConsumerService: [
          { Binding: samlify.Constants.namespace.binding.redirect, Location: "https://samlify.test/redirect-acs" },
          { Binding: samlify.Constants.namespace.binding.post, Location: "https://samlify.test/acs" },
        ],
      })
      .getMetadata();
    const r = await serviceProviderFromMetadata(xml, { id: "s" });
    expect(r.serviceProvider).toMatchObject({
      entityId: "https://samlify.test/sp",
      acsUrls: ["https://samlify.test/acs"],
      nameIdFormat: NAMEID_FORMAT.persistent,
      requireSignedAuthnRequests: true,
    });
    expect(b64Body((r.serviceProvider.spCertificate as string[])[0]!)).toBe(b64Body(keys.sp.certificate));
    expect(r.warnings.some((w) => w.includes("HTTP-Redirect"))).toBe(true);
  });

  it("reads node-saml-generated SP metadata, separating encryption and signing certificates", async () => {
    const saml = new SAML({
      issuer: "https://node-saml.test/sp",
      callbackUrl: "https://node-saml.test/acs",
      idpCert: keys.idp.certificate,
      entryPoint: "https://idp.test/sso",
      identifierFormat: NAMEID_FORMAT.emailAddress,
      decryptionPvk: keys.idpNext.privateKey,
      privateKey: keys.sp.privateKey,
    });
    const xml = saml.generateServiceProviderMetadata(keys.idpNext.certificate, keys.sp.certificate);
    const r = await serviceProviderFromMetadata(xml, { id: "n" });
    expect(r.serviceProvider).toMatchObject({
      entityId: "https://node-saml.test/sp",
      acsUrls: ["https://node-saml.test/acs"],
      nameIdFormat: NAMEID_FORMAT.emailAddress,
    });
    expect((r.serviceProvider.spCertificate as string[]).map(b64Body)).toEqual([b64Body(keys.sp.certificate)]);
    expect(r.encryptionCertificates.map(b64Body)).toEqual([b64Body(keys.idpNext.certificate)]);
  });

  it("orders ACS URLs: isDefault first, then by index; a KeyDescriptor without use counts for both", async () => {
    const xml = md(
      spsso(
        keyDesc(keys.sp.certificate) +
          acs("HTTP-POST", "https://sp.test/c", 3) +
          acs("HTTP-POST", "https://sp.test/a", 1) +
          acs("HTTP-POST", "https://sp.test/d", 7, true) +
          acs("HTTP-POST", "https://sp.test/b", 2, false),
      ),
    );
    const r = await serviceProviderFromMetadata(xml, { id: "x" });
    expect(r.serviceProvider.acsUrls).toEqual(["https://sp.test/d", "https://sp.test/a", "https://sp.test/b", "https://sp.test/c"]);
    expect(r.serviceProvider.requireSignedAuthnRequests).toBeUndefined();
    expect(r.serviceProvider.spCertificate).toHaveLength(1);
    expect(r.encryptionCertificates).toHaveLength(1);
  });

  it("explicit overrides win over the metadata", async () => {
    const xml = md(spsso(acs("HTTP-POST", "https://sp.test/acs", 0), ' AuthnRequestsSigned="true"'));
    const r = await serviceProviderFromMetadata(xml, { id: "x", acsUrls: ["https://sp.test/other"], nameIdFormat: NAMEID_FORMAT.transient });
    expect(r.serviceProvider.acsUrls).toEqual(["https://sp.test/other"]);
    expect(r.serviceProvider.nameIdFormat).toBe(NAMEID_FORMAT.transient);
    expect(r.warnings).toContain("AuthnRequestsSigned is true but no signing certificate is published");
  });

  it("selects an entity from an EntitiesDescriptor, and requires the selector", async () => {
    const one = (id: string) => md(spsso(acs("HTTP-POST", `${id}/acs`, 0))).replace('entityID="https://sp.test/md"', `entityID="${id}"`).replace(' xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"', "").replace(' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"', "");
    const xml = `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">${one("https://a.test")}${one("https://b.test")}</md:EntitiesDescriptor>`;
    await expect(serviceProviderFromMetadata(xml, { id: "x" })).rejects.toThrow(/pass options.entityId/);
    const r = await serviceProviderFromMetadata(xml, { id: "x" }, { entityId: "https://b.test" });
    expect(r.serviceProvider.acsUrls).toEqual(["https://b.test/acs"]);
    await expect(serviceProviderFromMetadata(xml, { id: "x" }, { entityId: "https://c.test" })).rejects.toThrow(/not found/);
  });

  it.each([
    ["a DOCTYPE", `<!DOCTYPE x [<!ENTITY e "boom">]>${md(spsso(acs("HTTP-POST", "https://sp.test/acs", 0)))}`],
    ["schema-invalid metadata", md(spsso(`<md:Bogus/>${acs("HTTP-POST", "https://sp.test/acs", 0)}`))],
    ["IdP (not SP) metadata", md(`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/></md:IDPSSODescriptor>`)],
    ["no HTTP-POST ACS", md(spsso(acs("HTTP-Artifact", "https://sp.test/acs", 0)))],
    ["a SAML protocol message", `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a" Version="2.0" IssueInstant="2026-09-24T10:00:00Z"><saml:Issuer>x</saml:Issuer></samlp:AuthnRequest>`],
  ])("rejects %s", async (_, xml) => {
    await expect(serviceProviderFromMetadata(xml, { id: "x" })).rejects.toBeInstanceOf(SpMetadataError);
  });
});

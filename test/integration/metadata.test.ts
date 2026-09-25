import * as samlify from "samlify";
import { SignedXml } from "xml-crypto";
import { describe, expect, inject, it } from "vitest";
import { libxml2Validator } from "../../src/saml/validator";
import { AUTH_BASE, createTestAuth } from "../support/auth";
import { baseOptions, IDP_ENTITY_ID } from "../support/config";

const keys = inject("keys");
const pemBody = (pem: string) => pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");

async function fetchMetadata(overrides = {}) {
  const { auth } = createTestAuth(overrides);
  const res = await auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`));
  return { res, xml: await res.text() };
}

describe("GET /saml2/idp/metadata", { timeout: 60_000 }, () => {
  it("serves SAML metadata with the right content type and caching", async () => {
    const { res } = await fetchMetadata();
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/samlmetadata+xml; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("private, max-age=300");
    expect(res.headers.get("vary")).toBe("Host, X-Forwarded-Host, X-Forwarded-Proto");
  });

  it("validates against the OASIS SAML 2.0 metadata XSD (Phase 1 gate)", async () => {
    const { xml } = await fetchMetadata();
    const result = await libxml2Validator().validate(xml, "metadata");
    expect(result).toEqual({ valid: true });
  });

  it("also validates with a rotation certificate published", async () => {
    const { xml } = await fetchMetadata({
      signing: { ...baseOptions().signing, additionalCertificates: [keys.idpNext.certificate] },
    });
    const r = await libxml2Validator().validate(xml, "metadata");
    if (!r.valid) console.log("ROTATION ERRORS", r.errors, xml.length);
    expect(r).toEqual({ valid: true });
    expect(xml).toContain(pemBody(keys.idp.certificate));
    expect(xml).toContain(pemBody(keys.idpNext.certificate));
  });

  it("advertises entity ID, both SSO bindings, NameID format and signing cert", async () => {
    const { xml } = await fetchMetadata();
    const idp = samlify.IdentityProvider({ metadata: xml });
    expect(idp.entityMeta.getEntityID()).toBe(IDP_ENTITY_ID);
    expect(idp.entityMeta.getSingleSignOnService("redirect")).toBe(`${AUTH_BASE}/saml2/idp/sso`);
    expect(idp.entityMeta.getSingleSignOnService("post")).toBe(`${AUTH_BASE}/saml2/idp/sso`);
    expect(xml).toMatch(/<(md:)?NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress<\/(md:)?NameIDFormat>/);
    expect(xml).toMatch(/WantAuthnRequestsSigned="false"/);
    expect(pemBody(String(idp.entityMeta.getX509Certificate("signing")))).toBe(pemBody(keys.idp.certificate));
  });

  it("advertises WantAuthnRequestsSigned only when every SP requires it", async () => {
    const { xml } = await fetchMetadata({
      serviceProviders: [
        {
          id: "s",
          entityId: "https://sp.test/metadata",
          acsUrls: ["https://sp.test/acs"],
          requireSignedAuthnRequests: true,
          spCertificate: keys.sp.certificate,
        },
      ],
    });
    expect(xml).toMatch(/WantAuthnRequestsSigned="true"/);
  });

  it("never contains private key material", async () => {
    const { xml } = await fetchMetadata();
    expect(xml).not.toMatch(/PRIVATE/);
    expect(xml).not.toContain(pemBody(keys.idp.privateKey).slice(0, 64));
  });

  it("has a stable shape (certificates redacted)", async () => {
    const { xml } = await fetchMetadata();
    const shape = xml
      .replace(/<ds:X509Certificate>[^<]+<\/ds:X509Certificate>/g, "<ds:X509Certificate>[redacted]</ds:X509Certificate>")
      .replace(/></g, ">\n<");
    expect(shape).toMatchSnapshot();
  });

  it("signMetadata: an enveloped signature over the EntityDescriptor that verifies and stays schema-valid", async () => {
    const { xml } = await fetchMetadata({ signMetadata: true });
    expect(await libxml2Validator().validate(xml, "metadata")).toEqual({ valid: true });
    const id = /<(?:md:)?EntityDescriptor [^>]*\bID="([^"]+)"/.exec(xml)?.[1];
    expect(id).toMatch(/^_/);
    const sig = /<ds:Signature[\s\S]*?<\/ds:Signature>/.exec(xml)![0];
    expect(sig).toContain(`URI="#${id}"`);
    const v = new SignedXml({ publicCert: keys.idp.certificate });
    v.loadSignature(sig);
    expect(v.checkSignature(xml)).toBe(true);
    // Tampering breaks it.
    const t = new SignedXml({ publicCert: keys.idp.certificate });
    t.loadSignature(sig);
    let tamperedOk: boolean;
    try {
      tamperedOk = t.checkSignature(xml.replace("/saml2/idp/sso", "/evil/sso"));
    } catch {
      tamperedOk = false;
    }
    expect(tamperedOk).toBe(false);
    // Still consumable by an SP library.
    expect(samlify.IdentityProvider({ metadata: xml }).entityMeta.getEntityID()).toBe(IDP_ENTITY_ID);
  });

  it("metadata is unsigned by default", async () => {
    const { xml } = await fetchMetadata();
    expect(xml).not.toContain("<ds:Signature");
  });
});

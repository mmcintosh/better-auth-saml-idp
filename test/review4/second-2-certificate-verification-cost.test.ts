// Second review 4 report, R4-2: verifying a signed HTTP-POST message costs a full re-parse and canonicalisation of the
// document PER CERTIFICATE (`verifyEnvelopedSignature` calls xml-crypto's `checkSignature(xml)` in a
// loop), about 215 ms per certificate for a 64 KiB request on this machine, and the number of
// signing certificates learned from an SP's metadata URL is not capped (a 1 MiB metadata document
// holds several hundred). An unauthenticated sender can therefore make the IdP spend
// certificates × ~200 ms of CPU per 64 KiB POST, and a hostile metadata host chooses the multiplier.
// Two independent fixes, either of which makes the matching test pass: canonicalise once and check
// the SignatureValue against every key (the cost test), and cap the certificates taken from
// metadata (the cap test).
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignedXml } from "xml-crypto";
import { describe, expect, inject, it } from "vitest";
import { verifyMessageSignature, MAX_REQUEST_BYTES } from "../../src/saml/request";
import { serviceProviderFromMetadata } from "../../src/saml/sp-metadata";
import { SpMetadataCache } from "../../src/saml/sp-metadata-refresh";
import { libxml2Validator } from "../../src/saml/validator";
import { isWorkerd } from "../support/host";

const keys = inject("keys");
const ALG = { sha256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", d256: "http://www.w3.org/2001/04/xmlenc#sha256", exc: "http://www.w3.org/2001/10/xml-exc-c14n#", enveloped: "http://www.w3.org/2000/09/xmldsig#enveloped-signature" };
const MAX_LEARNED_CERTIFICATES = 10; // the suggested cap; SPs publish one or two, at most a handful during rotation

/** N distinct self-signed RSA-2048 certificates (openssl, as test/support/global-setup.ts does). */
function certificates(n: number): string[] {
  const dir = mkdtempSync(join(tmpdir(), "r4-2-"));
  try {
    return Array.from({ length: n }, (_, i) => {
      execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1", "-subj", `/CN=c${i}`, "-keyout", join(dir, "k.pem"), "-out", join(dir, `${i}.pem`)], { stdio: "ignore" });
      return readFileSync(join(dir, `${i}.pem`), "utf8");
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function signedRequest(bytes: number): string {
  const pad = Array.from({ length: Math.floor(bytes / 46) }, (_, i) => `<e:p xmlns:e="urn:e" a="${i}">xxxxxxxxxxxx</e:p>`).join("");
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="${new Date().toISOString()}" AssertionConsumerServiceURL="https://sp.test/acs">` +
    `<saml:Issuer>https://sp.test/metadata</saml:Issuer><samlp:Extensions>${pad}</samlp:Extensions></samlp:AuthnRequest>`;
  const sig = new SignedXml({ privateKey: keys.sp.privateKey, publicCert: keys.sp.certificate, signatureAlgorithm: ALG.sha256, canonicalizationAlgorithm: ALG.exc });
  sig.addReference({ xpath: "/*[local-name(.)='AuthnRequest']", transforms: [ALG.enveloped, ALG.exc], digestAlgorithm: ALG.d256 });
  sig.computeSignature(xml, { location: { reference: "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']", action: "after" } });
  return sig.getSignedXml();
}

const metadataWith = (certs: string[]) =>
  `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://sp.test/metadata">` +
  `<md:SPSSODescriptor AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
  certs.map((c) => `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${c.replace(/-----[^-]+-----|\s/g, "")}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`).join("") +
  `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.test/acs" index="0"/>` +
  `</md:SPSSODescriptor></md:EntityDescriptor>`;

describe.skipIf(isWorkerd)("R4-2: signed-POST verification cost × certificates", () => {
  it("checking N certificates costs about the same as checking one (canonicalise once, verify each key)", async () => {
    const xml = signedRequest(52_000);
    expect(new TextEncoder().encode(xml).byteLength).toBeLessThanOrEqual(MAX_REQUEST_BYTES);
    expect((await libxml2Validator().validate(xml, "protocol")).valid).toBe(true);
    const wrong = certificates(12);
    const raw = { binding: "post" as const, samlRequest: "", relayState: undefined };
    const time = (certs: string[]) => {
      const t0 = performance.now();
      try {
        verifyMessageSignature(raw, xml, certs, { allowInsecureSha1: false });
      } catch {}
      return performance.now() - t0;
    };
    time([keys.idp.certificate]); // warm up
    const one = Math.min(time([wrong[0]!]), time([wrong[1]!]), time([wrong[2]!]));
    const twelve = time(wrong);
    // Today: ~12x (each certificate re-parses and re-canonicalises the whole document).
    expect(twelve).toBeLessThan(one * 3);
  });

  it("caps the signing certificates learned from an SP's metadata URL", async () => {
    const certs = certificates(MAX_LEARNED_CERTIFICATES + 2);
    const xml = metadataWith(certs);
    const parsed = await serviceProviderFromMetadata(xml, { id: "sp" });
    const learned = [parsed.serviceProvider.spCertificate ?? []].flat();
    expect(learned.length).toBeLessThanOrEqual(MAX_LEARNED_CERTIFICATES);

    // And through the refresh path an SP ends up with at most that many certificates to try.
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(xml, { status: 200 })) as typeof fetch;
    try {
      const cache = new SpMetadataCache(libxml2Validator());
      const sp = {
        id: "sp", entityId: "https://sp.test/metadata", acsUrls: ["https://sp.test/acs"] as [string], nameIdFormat: "x", nameId: undefined, attributes: () => ({}), attributeMap: undefined,
        organization: undefined, singleLogoutService: undefined, metadata: { url: "https://sp.test/metadata", refreshSeconds: 3600, signingCertificates: [] },
        requireSignedAuthnRequests: true, spCertificates: [], allowIdpInitiated: false, idpInitiatedRelayState: undefined, allowedRelayStates: [], authorize: () => true, signResponse: true, signAssertion: true,
      };
      const prepared = await cache.prepare(sp as any, { info() {}, warn() {} }, () => {});
      expect(prepared.spCertificates.length).toBeLessThanOrEqual(MAX_LEARNED_CERTIFICATES);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});

// SP metadata URL with refresh (D-026): certificates only, entity ID pinned, ACS URLs never taken.
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
import { SignedXml } from "xml-crypto";
import { afterEach, describe, expect, inject, it, vi } from "vitest";
import { resolveOptions, SamlIdpConfigError } from "../../src/options";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, deflateRaw, readAutoPost, SSO_URL } from "../support/sp";
import { decryptWithNode } from "../support/xmlenc";

const keys = inject("keys");
const MD_URL = "https://sp.test/saml/metadata.xml";
const body = (pem: string) => pem.replace(/-----[^-]+-----|\s+/g, "");
const kd = (pem: string, use: string) =>
  `<md:KeyDescriptor use="${use}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${body(pem)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;

function metadata(o: { entityId?: string; signing?: string[]; encryption?: string; acs?: string; validUntil?: string; signWith?: { key: string } } = {}) {
  const xml =
    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_md" entityID="${o.entityId ?? SP_ENTITY_ID}"${o.validUntil ? ` validUntil="${o.validUntil}"` : ""}>` +
    `<md:SPSSODescriptor AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
    (o.signing ?? [keys.sp.certificate]).map((c) => kd(c, "signing")).join("") +
    (o.encryption ? kd(o.encryption, "encryption") : "") +
    `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${o.acs ?? SP_ACS}" index="0"/>` +
    `</md:SPSSODescriptor></md:EntityDescriptor>`;
  if (!o.signWith) return xml;
  const exc = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const sig = new SignedXml({ privateKey: o.signWith.key, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: exc });
  sig.addReference({ xpath: "/*", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", exc], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  sig.computeSignature(xml, { prefix: "ds", location: { reference: "/*", action: "prepend" } });
  return sig.getSignedXml();
}

/** Serve `current()` at MD_URL and count fetches. */
function serve(current: () => string | Response) {
  const served = { count: 0 };
  vi.stubGlobal("fetch", async (url: string | URL | Request, init?: RequestInit) => {
    expect(String(url)).toBe(MD_URL);
    expect(init?.redirect).toBe("error");
    served.count++;
    const r = current();
    return typeof r === "string" ? new Response(r, { headers: { "content-type": "application/samlmetadata+xml" } }) : r;
  });
  return served;
}
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

async function signedRedirect(key: string, spec = {}) {
  const enc = encodeURIComponent;
  let q = `SAMLRequest=${enc(Buffer.from(await deflateRaw(authnRequestXml(spec).xml)).toString("base64"))}`;
  q += `&SigAlg=${enc("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")}`;
  q += `&Signature=${enc(cryptoSign("sha256", Buffer.from(q), createPrivateKey(key)).toString("base64"))}`;
  return `${SSO_URL}?${q}`;
}

async function host(sp: Record<string, unknown> = {}, logs: string[] = []) {
  const { auth } = await createHost({
    saml: {
      serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], requireSignedAuthnRequests: true, metadata: { url: MD_URL }, ...sp } as any],
    },
    auth: { logger: { level: "info", log: (_l: string, m: string) => logs.push(m) } },
  });
  const browser = new Browser(auth);
  await browser.signUp();
  return browser;
}
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const flush = () => new Promise((r) => setTimeout(r, 50));

describe("SP metadata URL with refresh", () => {
  it("first use waits for the metadata; its signing certificate verifies the SP's requests", async () => {
    const served = serve(() => metadata());
    const browser = await host();
    const res = await browser.fetch(await signedRedirect(keys.sp.privateKey));
    expect(res.status).toBe(200);
    expect(served.count).toBe(1);
    await browser.fetch(await signedRedirect(keys.sp.privateKey));
    expect(served.count).toBe(1); // cached until the refresh interval
  });

  it("picks up the SP's key rotation after the refresh interval", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    let current = metadata({ signing: [keys.sp.certificate] });
    const served = serve(() => current);
    const logs: string[] = [];
    const browser = await host({}, logs);
    expect((await browser.fetch(await signedRedirect(keys.sp.privateKey))).status).toBe(200);

    current = metadata({ signing: [keys.idpNext.certificate] }); // the SP rotated
    vi.setSystemTime(Date.now() + 86_400_000 + 1000);
    // This request triggers a background refresh and is judged on the cached copy.
    expect(await code(await browser.fetch(await signedRedirect(keys.idpNext.privateKey)))).toBe("UNSIGNED_SAML_REQUEST");
    await flush();
    expect(served.count).toBe(2);
    expect((await browser.fetch(await signedRedirect(keys.idpNext.privateKey))).status).toBe(200);
    // The old key is no longer trusted (it was only ever learned from metadata).
    expect(await code(await browser.fetch(await signedRedirect(keys.sp.privateKey)))).toBe("UNSIGNED_SAML_REQUEST");
    expect(logs.some((m) => /certificates from metadata changed/.test(m))).toBe(true);
  });

  it("configured certificates stay trusted; a failed fetch falls back to them and backs off", async () => {
    const served = serve(() => new Response("nope", { status: 503 }));
    const logs: string[] = [];
    const browser = await host({ spCertificate: keys.sp.certificate }, logs);
    expect((await browser.fetch(await signedRedirect(keys.sp.privateKey))).status).toBe(200);
    expect(await code(await browser.fetch(await signedRedirect(keys.idpNext.privateKey)))).toBe("UNSIGNED_SAML_REQUEST");
    expect(served.count).toBe(1); // no retry storm
    expect(logs.some((m) => /metadata refresh .* failed \(HTTP 503\); using the configured certificates/.test(m))).toBe(true);
  });

  it("never takes ACS URLs from metadata", async () => {
    serve(() => metadata({ acs: "https://evil.example/acs" }));
    const browser = await host();
    const res = await browser.fetch(await signedRedirect(keys.sp.privateKey, { acsUrl: "https://evil.example/acs" }));
    expect(await code(res)).toBe("ACS_URL_NOT_ALLOWED");
  });

  it.each([
    ["metadata for another entity ID", () => metadata({ entityId: "https://other.test/sp" }), {}],
    ["expired metadata (validUntil)", () => metadata({ validUntil: "2020-01-01T00:00:00Z" }), {}],
    ["unsigned metadata when the signature is pinned", () => metadata(), { signingCertificate: keys.idpNext.certificate }],
    ["metadata signed by another key than the pinned one", () => metadata({ signWith: { key: keys.sp.privateKey } }), { signingCertificate: keys.idpNext.certificate }],
    ["not XML", () => "<html>login</html>", {}],
  ])("rejects %s (nothing learned, so the unsigned-capable SP has no certificate)", async (_, doc, pin) => {
    const served = serve(doc);
    const logs: string[] = [];
    const browser = await host({ metadata: { url: MD_URL, ...pin } }, logs);
    expect(await code(await browser.fetch(await signedRedirect(keys.sp.privateKey)))).toBe("UNSIGNED_SAML_REQUEST");
    expect(served.count).toBe(1);
    expect(logs.some((m) => /metadata refresh .* failed/.test(m))).toBe(true);
  });

  it("accepts metadata signed with the pinned key", async () => {
    serve(() => metadata({ signWith: { key: keys.idpNext.privateKey } }));
    const browser = await host({ metadata: { url: MD_URL, signingCertificate: keys.idpNext.certificate } });
    expect((await browser.fetch(await signedRedirect(keys.sp.privateKey))).status).toBe(200);
  });

  it("the encryption certificate comes from metadata when encryption is on", async () => {
    serve(() => metadata({ encryption: keys.sp.certificate }));
    // Configured: encrypt to idpNext. Metadata: encrypt to sp. The metadata wins (it's the rotation point).
    const browser = await host({ encryption: { certificate: keys.idpNext.certificate } });
    const form = await readAutoPost(await browser.fetch(await signedRedirect(keys.sp.privateKey)));
    expect(form.xml).toContain("EncryptedAssertion");
    expect(decryptWithNode(form.xml, keys.sp.privateKey)).toMatch(/<saml:Assertion /);
    expect(() => decryptWithNode(form.xml, keys.idpNext.privateKey)).toThrow();
  });
});

describe("options: metadata", () => {
  const issues = (metadataOpt: unknown) => {
    try {
      resolveOptions(baseOptions({ serviceProviders: [{ id: "s", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], metadata: metadataOpt } as any] }));
      return [];
    } catch (e) {
      if (e instanceof SamlIdpConfigError) return e.issues;
      throw e;
    }
  };
  it("https only, bounded refresh interval, known keys only", () => {
    expect(issues({ url: "http://sp.test/md" }).join()).toMatch(/https/);
    expect(issues({ url: MD_URL, refreshSeconds: 10 }).length).toBe(1);
    expect(issues({ url: MD_URL, refreshSeconds: 30 * 86400 }).length).toBe(1);
    expect(issues({ url: MD_URL, extra: true }).length).toBe(1);
    expect(issues({ url: MD_URL })).toEqual([]);
  });
  it("warns when the metadata signature isn't pinned", () => {
    const r = resolveOptions(baseOptions({ serviceProviders: [{ id: "s", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], metadata: { url: MD_URL } }] }));
    expect(r.warnings.join()).toMatch(/isn't pinned/);
  });
});

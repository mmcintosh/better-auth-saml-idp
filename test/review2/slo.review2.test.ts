// Second adversarial review: Single Logout (D-028) proofs of concept.
// Every `it` here asserts the SECURE / documented behaviour; a failing test proves the finding.
import { createPrivateKey } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { afterEach, describe, expect, inject, it, vi } from "vitest";
import { redirectBindingUrl } from "../../src/saml/logout";
import { decodeAuthnRequest, parseRedirectQuery } from "../../src/saml/request";
import { resetSweepThrottle } from "../../src/storage/sweep";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, SSO_URL } from "../support/sp";

const keys = inject("keys");
const SLO = `${AUTH_BASE}/saml2/idp/slo`;
const A = { id: "sp-a", entityId: SP_ENTITY_ID, acs: SP_ACS, slo: "https://sp.test/slo" };
const B = { id: "sp-b", entityId: "https://b.test/sp", acs: "https://b.test/acs", slo: "https://b.test/slo" };
const C = { id: "sp-c", entityId: "https://c.test/sp", acs: "https://c.test/acs", slo: "https://c.test/slo" };

const spSigning = (pem: string) => ({ signatureAlgorithm: "rsa-sha256", digestAlgorithm: "sha256", keyObject: createPrivateKey(pem), certificate: "" }) as any;
const iso = (d = new Date()) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
let n = 0;
function logoutRequestXml(o: { issuer: string; nameId: string; sessionIndex?: string }) {
  const id = `_r2lr${Date.now().toString(36)}${n++}`;
  return {
    id,
    xml:
      `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${iso()}" Destination="${SLO}">` +
      `<saml:Issuer>${o.issuer}</saml:Issuer><saml:NameID>${o.nameId}</saml:NameID>` +
      (o.sessionIndex ? `<samlp:SessionIndex>${o.sessionIndex}</samlp:SessionIndex>` : "") +
      `</samlp:LogoutRequest>`,
  };
}
async function signIn(browser: Browser, sp: { entityId: string; acs: string }) {
  const url = `${SSO_URL}?SAMLRequest=${encodeURIComponent(deflateRawSync(authnRequestXml({ issuer: sp.entityId, acsUrl: sp.acs }).xml).toString("base64"))}`;
  const form = await readAutoPost(await browser.fetch(url));
  return { nameId: /<saml:NameID [^>]*>([^<]+)</.exec(form.xml)![1]!, sessionIndex: /SessionIndex="([^"]+)"/.exec(form.xml)![1]! };
}
const signedIn = async (browser: Browser) => (await (await browser.fetch(`${AUTH_BASE}/get-session`)).json()) !== null;
const unsignedGet = (browser: Browser, xml: string) => browser.fetch(`${SLO}?SAMLRequest=${encodeURIComponent(deflateRawSync(xml).toString("base64"))}`);

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("review2 SLO", () => {
  it("R2-SLO-1: logout reaches every SP that got an assertion, even after the IdP session was refreshed", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    const { auth } = await createHost({
      saml: {
        singleLogout: { enabled: true },
        serviceProviders: [
          { id: A.id, entityId: A.entityId, acsUrls: [A.acs], spCertificate: keys.sp.certificate, singleLogoutService: { url: A.slo } },
          { id: B.id, entityId: B.entityId, acsUrls: [B.acs], spCertificate: keys.idpNext.certificate, singleLogoutService: { url: B.slo } },
        ] as any,
      },
      // A short session that is refreshed on use (Better Auth's sliding expiry, scaled down:
      // the default is expiresIn 7 days / updateAge 1 day).
      auth: { session: { expiresIn: 600, updateAge: 60 } },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    const a = await signIn(browser, A);
    await signIn(browser, B); // participant row for B: expiresAt = session.expiresAt at THIS moment (t0 + 600 s)
    vi.setSystemTime(t0 + 500_000);
    expect(await signedIn(browser)).toBe(true); // sliding refresh: session now expires at t0 + 1100 s
    vi.setSystemTime(t0 + 700_000); // B's participant row has expired; the IdP session has not
    expect(await signedIn(browser)).toBe(true);
    resetSweepThrottle();
    const lr = logoutRequestXml({ issuer: A.entityId, nameId: a.nameId, sessionIndex: a.sessionIndex });
    const res = await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", lr.xml, "rs", spSigning(keys.sp.privateKey)));
    expect(await signedIn(browser)).toBe(false);
    const next = new URL(res.headers.get("location")!);
    // Secure: the chain goes to B (or at least A is told PartialLogout).
    const toA = next.origin === "https://sp.test" ? await decodeAuthnRequest(parseRedirectQuery(next.search.slice(1), "SAMLResponse")) : "";
    expect(next.origin === "https://b.test" || toA.includes("PartialLogout"), `went to ${next.origin}: ${toA.slice(0, 400)}`).toBe(true);
  });

  it("R2-SLO-2: one SP can't end the user's IdP session by impersonating another (certificate-less) SP", async () => {
    const { auth } = await createHost({
      saml: {
        singleLogout: { enabled: true },
        serviceProviders: [
          // B: a (less trusted) SP the user signed in to; it can read the SessionIndex in its assertion.
          { id: B.id, entityId: B.entityId, acsUrls: [B.acs], singleLogoutService: { url: B.slo } },
          // C: a certificate-less SP with SLO that the user never used.
          { id: C.id, entityId: C.entityId, acsUrls: [C.acs], singleLogoutService: { url: C.slo } },
          { id: A.id, entityId: A.entityId, acsUrls: [A.acs], spCertificate: keys.sp.certificate, singleLogoutService: { url: A.slo } },
        ] as any,
      },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    const a = await signIn(browser, A);
    const b = await signIn(browser, B);
    // Per-SP SessionIndex would stop B from learning the value A (or C) would present.
    expect(b.sessionIndex, "SessionIndex is identical for every SP in the session").not.toBe(a.sessionIndex);
  });

  it("R2-SLO-2b: forged, unsigned LogoutRequest 'from' an SP the user never used (SessionIndex learned by another SP)", async () => {
    const { auth } = await createHost({
      saml: {
        singleLogout: { enabled: true },
        serviceProviders: [
          { id: B.id, entityId: B.entityId, acsUrls: [B.acs] }, // B has no SLO at all
          { id: C.id, entityId: C.entityId, acsUrls: [C.acs], singleLogoutService: { url: C.slo } },
        ] as any,
      },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    const b = await signIn(browser, B);
    // B's page navigates the victim to /slo with an unsigned LogoutRequest claiming to be C.
    await unsignedGet(browser, logoutRequestXml({ issuer: C.entityId, nameId: "anything", sessionIndex: b.sessionIndex }).xml);
    expect(await signedIn(browser), "C never took part in this session, yet its unsigned request ended it").toBe(true);
  });

  it("R2-SLO-3: an SP whose certificates come only from metadata doesn't fall back to unsigned LogoutRequests when the fetch fails", async () => {
    vi.stubGlobal("fetch", async () => new Response("down", { status: 503 }));
    const { auth } = await createHost({
      saml: {
        singleLogout: { enabled: true },
        serviceProviders: [
          {
            id: A.id,
            entityId: A.entityId,
            acsUrls: [A.acs],
            requireSignedAuthnRequests: true, // the SP signs everything; its key is published in metadata
            metadata: { url: "https://sp.test/metadata.xml" },
            singleLogoutService: { url: A.slo },
          },
          { id: B.id, entityId: B.entityId, acsUrls: [B.acs] },
        ] as any,
      },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    const b = await signIn(browser, B); // an SP that only learned the SessionIndex
    await unsignedGet(browser, logoutRequestXml({ issuer: A.entityId, nameId: "x", sessionIndex: b.sessionIndex }).xml);
    expect(await signedIn(browser), "unsigned LogoutRequest accepted for an SP that requires signatures").toBe(true);
  });
  it("R2-SLO-4: a participant whose SingleLogoutService binding is 'post' gets its LogoutRequest over HTTP-POST", async () => {
    const D = { id: "sp-d", entityId: "https://d.test/sp", acs: "https://d.test/acs", slo: "https://d.test/slo" };
    const { auth } = await createHost({
      saml: {
        singleLogout: { enabled: true },
        // As serviceProviderFromMetadata produces for an SP that only publishes an HTTP-POST SingleLogoutService.
        serviceProviders: [{ id: D.id, entityId: D.entityId, acsUrls: [D.acs], singleLogoutService: { url: D.slo, binding: "post" } }] as any,
      },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    await signIn(browser, D);
    const res = await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=/bye`);
    // Secure/interop: an auto-POST form to D's POST-only endpoint, not a GET redirect it can't process.
    expect(res.status, `got ${res.status} -> ${res.headers.get("location")?.slice(0, 60)}`).toBe(200);
  });
  it("R2-SLO-5: SLO enforces relayStateMaxBytes like SSO (no unbounded, unauthenticated RelayState storage)", async () => {
    const { auth } = await createHost({
      saml: { singleLogout: { enabled: true }, serviceProviders: [{ id: C.id, entityId: C.entityId, acsUrls: [C.acs], singleLogoutService: { url: C.slo } }] as any },
    });
    const anon = new Browser(auth); // no account, no session
    const lr = logoutRequestXml({ issuer: C.entityId, nameId: "x", sessionIndex: "_x" });
    const res = await anon.fetch(SLO, {
      method: "POST",
      crossSite: true,
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://evil.example" },
      body: new URLSearchParams({ SAMLRequest: Buffer.from(lr.xml).toString("base64"), RelayState: "x".repeat(512 * 1024) }).toString(),
    });
    // 303 = a 512 KiB RelayState was stored as a verification value (and would be echoed to C).
    expect(res.status, "oversized RelayState accepted and stored").not.toBe(303);
  });
});

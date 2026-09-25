// R3-2: `listParticipants(...).catch(() => [])` in src/endpoints/slo.ts (endSession, and again in
// handleLogoutRequest) turns a failed database read into "no other participants". The IdP session
// is ended, the other SPs are silently NOT notified, and the originating SP is told plain
// `Success` instead of `Success/PartialLogout` (SAML Core §3.7.3.2: PartialLogout when the IdP
// could not propagate to every participant). Fail-open on the status the SP relies on.
import { createPrivateKey } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { describe, expect, inject, it } from "vitest";
import { redirectBindingUrl } from "../../src/saml/logout";
import { decodeAuthnRequest, parseRedirectQuery } from "../../src/saml/request";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, SSO_URL } from "../support/sp";

const keys = inject("keys");
const SLO = `${AUTH_BASE}/saml2/idp/slo`;
const A = { id: "sp-a", entityId: SP_ENTITY_ID, acs: SP_ACS, slo: "https://sp.test/slo" };
const B = { id: "sp-b", entityId: "https://b.test/sp", acs: "https://b.test/acs", slo: "https://b.test/slo" };
const spSigning = (pem: string) => ({ signatureAlgorithm: "rsa-sha256", digestAlgorithm: "sha256", keyObject: createPrivateKey(pem), certificate: "" }) as any;
const iso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

const logoutRequestXml = (o: { issuer: string; nameId: string; sessionIndex: string }) =>
  `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr${Date.now().toString(36)}" Version="2.0" IssueInstant="${iso()}" Destination="${SLO}">` +
  `<saml:Issuer>${o.issuer}</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${o.nameId}</saml:NameID>` +
  `<samlp:SessionIndex>${o.sessionIndex}</samlp:SessionIndex></samlp:LogoutRequest>`;

async function signIn(browser: Browser, sp: { entityId: string; acs: string }) {
  const url = `${SSO_URL}?SAMLRequest=${encodeURIComponent(Buffer.from(deflateRawSync(authnRequestXml({ issuer: sp.entityId, acsUrl: sp.acs }).xml)).toString("base64"))}`;
  const form = await readAutoPost(await browser.fetch(url));
  return { nameId: /<saml:NameID [^>]*>([^<]+)</.exec(form.xml)![1]!, sessionIndex: /SessionIndex="([^"]+)"/.exec(form.xml)![1]! };
}

describe("Single Logout: participant read failure", () => {
  it("a failed participant lookup must not be reported to the originator as a full Success", async () => {
    const { auth } = await createHost({
      saml: {
        singleLogout: { enabled: true },
        serviceProviders: [
          { id: A.id, entityId: A.entityId, acsUrls: [A.acs], spCertificate: keys.sp.certificate, singleLogoutService: { url: A.slo } },
          { id: B.id, entityId: B.entityId, acsUrls: [B.acs], singleLogoutService: { url: B.slo } },
        ],
      },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    const a = await signIn(browser, A);
    await signIn(browser, B); // B is now a participant that must be logged out too

    // The participant table becomes unreadable (outage, migration, renamed column...).
    const ctx = await auth.$context;
    const original = ctx.adapter.findMany.bind(ctx.adapter);
    ctx.adapter.findMany = async (args: any) => {
      if (args.model === "samlIdpSessionParticipant") throw new Error("simulated database failure");
      return original(args);
    };

    const res = await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", logoutRequestXml({ issuer: A.entityId, nameId: a.nameId, sessionIndex: a.sessionIndex }), "rs", spSigning(keys.sp.privateKey)));
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location")!);
    if (`${loc.origin}${loc.pathname}` === B.slo) return; // propagation happened after all: fine
    // Otherwise the IdP went straight to answering A: that answer must say PartialLogout,
    // because B was never told.
    expect(`${loc.origin}${loc.pathname}`).toBe(A.slo);
    const raw = parseRedirectQuery(loc.search.slice(1), "SAMLResponse");
    const xml = await decodeAuthnRequest(raw);
    expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:status:PartialLogout");
  });
});

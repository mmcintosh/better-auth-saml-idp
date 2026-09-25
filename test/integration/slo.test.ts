// SAML Single Logout (D-028): SP- and IdP-initiated, front-channel propagation, authentication.
import { createPrivateKey } from "node:crypto";
import { SAML } from "@node-saml/node-saml";
import { describe, expect, inject, it } from "vitest";
import { buildLogoutResponse, redirectBindingUrl, signedPostMessage } from "../../src/saml/logout";
import { decodeAuthnRequest, parseRedirectQuery, verifyMessageSignature } from "../../src/saml/request";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, SSO_URL } from "../support/sp";

const keys = inject("keys");
const SLO = `${AUTH_BASE}/saml2/idp/slo`;
const IDP_ENTITY = "https://auth.test/api/auth/saml2/idp";
const A = { id: "sp-a", entityId: SP_ENTITY_ID, acs: SP_ACS, slo: "https://sp.test/slo" };
const B = { id: "sp-b", entityId: "https://b.test/sp", acs: "https://b.test/acs", slo: "https://b.test/slo" };

const spSigning = (pem: string) => ({ signatureAlgorithm: "rsa-sha256", digestAlgorithm: "sha256", keyObject: createPrivateKey(pem), certificate: "" }) as any;
const iso = (d = new Date()) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
let n = 0;

function logoutRequestXml(o: { issuer: string; nameId: string; sessionIndex?: string; id?: string; destination?: string }) {
  const id = o.id ?? `_lr${Date.now().toString(36)}${n++}`;
  return {
    id,
    xml:
      `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${iso()}" Destination="${o.destination ?? SLO}">` +
      `<saml:Issuer>${o.issuer}</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${o.nameId}</saml:NameID>` +
      (o.sessionIndex ? `<samlp:SessionIndex>${o.sessionIndex}</samlp:SessionIndex>` : "") +
      `</samlp:LogoutRequest>`,
  };
}

async function host(sps: Record<string, unknown>[] = [], saml: Record<string, unknown> = {}) {
  const { auth } = await createHost({
    saml: {
      singleLogout: { enabled: true },
      serviceProviders: [
        { id: A.id, entityId: A.entityId, acsUrls: [A.acs], spCertificate: keys.sp.certificate, singleLogoutService: { url: A.slo } },
        { id: B.id, entityId: B.entityId, acsUrls: [B.acs], spCertificate: keys.idpNext.certificate, singleLogoutService: { url: B.slo } },
        ...sps,
      ] as any,
      ...saml,
    },
  });
  const browser = new Browser(auth);
  await browser.signUp();
  return { auth, browser };
}

/** Sign in to an SP; returns the NameID and SessionIndex it was given. */
async function signIn(browser: Browser, sp: { entityId: string; acs: string }) {
  const url = `${SSO_URL}?SAMLRequest=${encodeURIComponent(Buffer.from(await import("node:zlib").then((z) => z.deflateRawSync(authnRequestXml({ issuer: sp.entityId, acsUrl: sp.acs }).xml))).toString("base64"))}`;
  const form = await readAutoPost(await browser.fetch(url));
  return {
    nameId: /<saml:NameID [^>]*>([^<]+)</.exec(form.xml)![1]!,
    sessionIndex: /SessionIndex="([^"]+)"/.exec(form.xml)![1]!,
  };
}

/** The response expires the Better Auth session cookie (so a cookie cache can't keep the user in). */
const clearsSession = (res: Response) => res.headers.getSetCookie().some((c) => /session_token=;|session_token=[^;]*;.*Max-Age=0/i.test(c));
const signedIn = async (browser: Browser) => (await (await browser.fetch(`${AUTH_BASE}/get-session`)).json()) !== null;
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

/** Our outgoing Redirect-binding message at `location`: decoded, and its IdP signature checked. */
async function outgoing(location: string, param: "SAMLRequest" | "SAMLResponse") {
  const u = new URL(location);
  const raw = parseRedirectQuery(u.search.slice(1), param);
  const xml = await decodeAuthnRequest(raw);
  verifyMessageSignature(raw, xml, [keys.idp.certificate], { allowInsecureSha1: false }); // throws if not signed by the IdP
  return { url: `${u.origin}${u.pathname}`, xml, relayState: raw.relayState };
}

async function answer(browser: Browser, request: { xml: string; relayState?: string }, o: { key?: string; issuer?: string; status?: string[]; inResponseTo?: string } = {}) {
  const inResponseTo = o.inResponseTo ?? /ID="([^"]+)"/.exec(request.xml)![1]!;
  const xml = buildLogoutResponse({ issuer: o.issuer ?? B.entityId, destination: SLO, inResponseTo, status: o.status ?? ["Success"], now: new Date() });
  return browser.fetch(redirectBindingUrl(SLO, "SAMLResponse", xml, request.relayState, spSigning(o.key ?? keys.idpNext.privateKey)));
}

describe("SP-initiated Single Logout", () => {
  it("ends the IdP session, logs out the other SP, then answers the originator with Success", async () => {
    const { browser } = await host();
    const a = await signIn(browser, A);
    const b = await signIn(browser, B);
    const lr = logoutRequestXml({ issuer: A.entityId, nameId: a.nameId, sessionIndex: a.sessionIndex });
    const res = await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", lr.xml, "rs-a", spSigning(keys.sp.privateKey)));
    expect(res.status).toBe(302);
    expect(clearsSession(res)).toBe(true);
    expect(await signedIn(browser)).toBe(false); // ended before propagation
    // To SP B: a LogoutRequest signed by the IdP, about the NameID and SessionIndex B was given.
    const toB = await outgoing(res.headers.get("location")!, "SAMLRequest");
    expect(toB.url).toBe(B.slo);
    expect(toB.xml).toContain(`>${b.nameId}</saml:NameID>`);
    expect(toB.xml).toContain(`<samlp:SessionIndex>${b.sessionIndex}</samlp:SessionIndex>`);
    // B answers; the IdP answers A.
    const done = await answer(browser, toB);
    const toA = await outgoing(done.headers.get("location")!, "SAMLResponse");
    expect(toA.url).toBe(A.slo);
    expect(toA.relayState).toBe("rs-a");
    expect(toA.xml).toContain(`InResponseTo="${lr.id}"`);
    expect(toA.xml).toMatch(/StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"\/>/);
  });

  it("an SP that fails, answers for another request, or can't be reached makes it PartialLogout", async () => {
    for (const bad of ["failure", "wrong-inResponseTo", "wrong-key"] as const) {
      const { browser } = await host();
      const a = await signIn(browser, A);
      await signIn(browser, B);
      const lr = logoutRequestXml({ issuer: A.entityId, nameId: a.nameId, sessionIndex: a.sessionIndex });
      const toB = await outgoing((await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", lr.xml, undefined, spSigning(keys.sp.privateKey)))).headers.get("location")!, "SAMLRequest");
      const done = await answer(browser, toB, {
        ...(bad === "failure" ? { status: ["Responder"] } : {}),
        ...(bad === "wrong-inResponseTo" ? { inResponseTo: "_other" } : {}),
        ...(bad === "wrong-key" ? { key: keys.sp.privateKey } : {}),
      });
      const toA = await outgoing(done.headers.get("location")!, "SAMLResponse");
      expect(toA.xml, bad).toContain("status:PartialLogout");
    }
  });

  it("a logout state can't be replayed", async () => {
    const { browser } = await host();
    const a = await signIn(browser, A);
    await signIn(browser, B);
    const lr = logoutRequestXml({ issuer: A.entityId, nameId: a.nameId, sessionIndex: a.sessionIndex });
    const toB = await outgoing((await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", lr.xml, undefined, spSigning(keys.sp.privateKey)))).headers.get("location")!, "SAMLRequest");
    expect((await answer(browser, toB)).status).toBe(302);
    expect(await code(await answer(browser, toB))).toBe("LOGOUT_STATE_NOT_FOUND");
  });

  it("an SP with certificates must sign; unsigned or wrongly signed requests end nothing", async () => {
    const { browser } = await host();
    const a = await signIn(browser, A);
    const unsigned = logoutRequestXml({ issuer: A.entityId, nameId: a.nameId, sessionIndex: a.sessionIndex });
    const q = `SAMLRequest=${encodeURIComponent(Buffer.from((await import("node:zlib")).deflateRawSync(unsigned.xml)).toString("base64"))}`;
    expect(await code(await browser.fetch(`${SLO}?${q}`))).toBe("UNSIGNED_SAML_REQUEST");
    const forged = logoutRequestXml({ issuer: A.entityId, nameId: a.nameId, sessionIndex: a.sessionIndex });
    expect(await code(await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", forged.xml, undefined, spSigning(keys.idpNext.privateKey))))).toBe("UNSIGNED_SAML_REQUEST");
    expect(await signedIn(browser)).toBe(true);
  });

  it("without SP certificates, only the right SessionIndex (unguessable, per session) ends the session", async () => {
    const C = { id: "sp-c", entityId: "https://c.test/sp", acs: "https://c.test/acs", slo: "https://c.test/slo" };
    const { browser } = await host([{ id: C.id, entityId: C.entityId, acsUrls: [C.acs], singleLogoutService: { url: C.slo } }]);
    const c = await signIn(browser, C);
    const deflate = (await import("node:zlib")).deflateRawSync;
    const send = (xml: string) => browser.fetch(`${SLO}?SAMLRequest=${encodeURIComponent(Buffer.from(deflate(xml)).toString("base64"))}`);
    // Forged: right NameID, guessed SessionIndex → answered, but nothing ends.
    const forged = await send(logoutRequestXml({ issuer: C.entityId, nameId: c.nameId, sessionIndex: "_guess" }).xml);
    expect(new URL(forged.headers.get("location")!).origin).toBe("https://c.test");
    expect(await signedIn(browser)).toBe(true);
    // No SessionIndex and unsigned: can't be authenticated → nothing ends.
    await send(logoutRequestXml({ issuer: C.entityId, nameId: c.nameId }).xml);
    expect(await signedIn(browser)).toBe(true);
    // The real SessionIndex → logged out.
    await send(logoutRequestXml({ issuer: C.entityId, nameId: c.nameId, sessionIndex: c.sessionIndex }).xml);
    expect(await signedIn(browser)).toBe(false);
  });

  it("a replayed LogoutRequest is refused", async () => {
    const { browser } = await host();
    const a = await signIn(browser, A);
    const url = redirectBindingUrl(SLO, "SAMLRequest", logoutRequestXml({ issuer: A.entityId, nameId: a.nameId, sessionIndex: a.sessionIndex }).xml, undefined, spSigning(keys.sp.privateKey));
    expect((await browser.fetch(url)).status).toBe(302);
    expect(await code(await browser.fetch(url))).toBe("DUPLICATE_REQUEST_ID");
  });

  it("no session in this browser: answered with Success, nothing else happens", async () => {
    const { auth } = await host();
    const fresh = new Browser(auth);
    const res = await fresh.fetch(redirectBindingUrl(SLO, "SAMLRequest", logoutRequestXml({ issuer: A.entityId, nameId: "x@example.com", sessionIndex: "_x" }).xml, undefined, spSigning(keys.sp.privateKey)));
    expect((await outgoing(res.headers.get("location")!, "SAMLResponse")).xml).toContain("status:Success");
  });

  it("HTTP-POST binding: a cross-site POST (no Lax cookies) re-enters same-site and works; the answer can be POSTed too", async () => {
    const { browser } = await host([], {});
    const a = await signIn(browser, A);
    const lr = logoutRequestXml({ issuer: A.entityId, nameId: a.nameId, sessionIndex: a.sessionIndex });
    const res = await browser.fetch(SLO, {
      method: "POST",
      crossSite: true,
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://sp.test" },
      body: new URLSearchParams({ SAMLRequest: signedPostMessage(lr.xml, "LogoutRequest", spSigning(keys.sp.privateKey) as any), RelayState: "rs" }).toString(),
    });
    expect(res.status).toBe(303);
    const followed = await browser.fetch(res.headers.get("location")!);
    expect(await signedIn(browser)).toBe(false);
    // A's binding is redirect, so the answer is a Redirect-binding LogoutResponse.
    expect((await outgoing(followed.headers.get("location")!, "SAMLResponse")).xml).toContain(`InResponseTo="${lr.id}"`);
  });

  it("an originator with binding: post gets an auto-POSTed, XML-signed LogoutResponse", async () => {
    const D = { id: "sp-d", entityId: "https://d.test/sp", acs: "https://d.test/acs", slo: "https://d.test/slo" };
    const { browser } = await host([{ id: D.id, entityId: D.entityId, acsUrls: [D.acs], spCertificate: keys.sp.certificate, singleLogoutService: { url: D.slo, binding: "post" } }]);
    const d = await signIn(browser, D);
    const res = await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", logoutRequestXml({ issuer: D.entityId, nameId: d.nameId, sessionIndex: d.sessionIndex }).xml, undefined, spSigning(keys.sp.privateKey)));
    expect(clearsSession(res)).toBe(true); // also on a raw (auto-POST) Response
    const form = await readAutoPost(res);
    expect(form.action).toBe(D.slo);
    expect(form.xml).toMatch(/^<samlp:LogoutResponse [\s\S]*<ds:Signature/);
    verifyMessageSignature({ binding: "post", samlRequest: "", relayState: undefined }, form.xml, [keys.idp.certificate], { allowInsecureSha1: false });
  });

  it("an SP without singleLogoutService can't start a logout", async () => {
    const E = { id: "sp-e", entityId: "https://e.test/sp", acs: "https://e.test/acs" };
    const { browser } = await host([{ id: E.id, entityId: E.entityId, acsUrls: [E.acs], spCertificate: keys.sp.certificate }]);
    const res = await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", logoutRequestXml({ issuer: E.entityId, nameId: "x" }).xml, undefined, spSigning(keys.sp.privateKey)));
    expect(await code(res)).toBe("LOGOUT_NOT_SUPPORTED");
  });
});

describe("IdP-initiated logout", () => {
  it("logs out of every SP, then returns to a same-origin path", async () => {
    const { browser } = await host();
    await signIn(browser, A);
    await signIn(browser, B);
    let res = await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=/bye`);
    expect(await signedIn(browser)).toBe(false);
    const seen: string[] = [];
    for (let i = 0; i < 3 && res.status === 302 && new URL(res.headers.get("location")!).pathname.endsWith("/slo"); i++) {
      const req = await outgoing(res.headers.get("location")!, "SAMLRequest");
      seen.push(req.url);
      res = await answer(browser, req, { issuer: req.url === A.slo ? A.entityId : B.entityId, key: req.url === A.slo ? keys.sp.privateKey : keys.idpNext.privateKey });
    }
    expect(seen.sort()).toEqual([B.slo, A.slo].sort());
    expect(res.headers.get("location")).toBe("https://auth.test/bye");
  });

  it("returnTo must be same-origin or trusted; cross-site drive-bys must confirm", async () => {
    const { browser } = await host();
    const evil = await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=https://evil.example/`);
    expect(await code(evil)).toBe("INVALID_RETURN_TO");
    expect(await evil.text()).toContain("<h1>Sign-out could not be completed</h1>");
    expect(await code(await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=//evil.example/`))).toBe("INVALID_RETURN_TO");
    const driveBy = await browser.fetch(`${AUTH_BASE}/saml2/idp/logout`, { headers: { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate" } });
    expect(driveBy.status).toBe(200);
    expect(await signedIn(browser)).toBe(true);
  });
});

describe("Single Logout: interop and metadata", () => {
  it("node-saml SP: its signed LogoutRequest is accepted, and it validates our LogoutResponse", async () => {
    const { browser } = await host();
    const a = await signIn(browser, A);
    const sp = new SAML({
      issuer: A.entityId,
      callbackUrl: A.acs,
      entryPoint: SSO_URL,
      logoutUrl: SLO,
      idpCert: keys.idp.certificate,
      privateKey: keys.sp.privateKey,
      signatureAlgorithm: "sha256",
      validateInResponseTo: "never" as any,
    });
    const url = await sp.getLogoutUrlAsync({ issuer: IDP_ENTITY, nameID: a.nameId, nameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", sessionIndex: a.sessionIndex } as any, "rs", {});
    const res = await browser.fetch(url);
    expect(await signedIn(browser)).toBe(false);
    const location = new URL(res.headers.get("location")!);
    const query = Object.fromEntries(location.searchParams) as any;
    const r = await sp.validateRedirectAsync(query, location.search.slice(1));
    expect(r.loggedOut).toBe(true);
  });

  it("metadata advertises SingleLogoutService only when enabled", async () => {
    const { auth } = await host();
    const md = await (await auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`))).text();
    expect(md).toMatch(/SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https:\/\/auth\.test\/api\/auth\/saml2\/idp\/slo"/);
    const { auth: off } = await createHost({});
    expect(await (await off.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`))).text()).not.toContain("SingleLogoutService");
    expect((await off.handler(new Request(SLO))).status).toBe(404);
  });
});

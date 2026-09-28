// Multi-tenant IdP (D-052): with `tenants` unset, the plugin's output is exactly what it was before
// tenancy existed. The snapshots in __snapshots__/tenants-off.test.ts.snap were recorded from the
// code BEFORE any tenant change (commit "Pin today's output"), so a difference here is a change in
// what SPs see. Keys are generated per run, so only per-run values are normalised: certificates,
// random IDs, instants, digests and signature values (each signature is also verified), and the
// test's own random names. Everything else is compared byte for byte.
import { createHmac, createPrivateKey } from "node:crypto";
import { describe, expect, inject, it } from "vitest";
import { samlIdp } from "../../src/index";
import { buildLogoutResponse, redirectBindingUrl } from "../../src/saml/logout";
import { decodeAuthnRequest, parseRedirectQuery, verifyMessageSignature } from "../../src/saml/request";
import { base64url } from "../../src/storage/pending";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { authnRequestXml, Browser, newRequestId, postBinding, readAutoPost, redirectUrl, SSO_URL, strictSp } from "../support/sp";

const keys = inject("keys");
const SECRET = "test-secret-that-is-at-least-32-characters-long";
const SLO = `${AUTH_BASE}/saml2/idp/slo`;
const PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const A = { id: "sp-a", entityId: SP_ENTITY_ID, acs: SP_ACS, slo: "https://sp.test/slo" };
const B = { id: "sp-b", entityId: "https://b.test/sp", acs: "https://b.test/acs", slo: "https://b.test/slo" };
const P = { id: "sp-p", entityId: "https://p.test/sp", acs: "https://p.test/acs" };

const pemBody = (pem: string) => pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
const spSigning = (pem: string) => ({ signatureAlgorithm: "rsa-sha256", digestAlgorithm: "sha256", keyObject: createPrivateKey(pem), certificate: "" }) as any;

/** Replace per-run values with stable placeholders; `known` maps literal strings (emails, ids) to names. */
function normalise(text: string, known: Record<string, string> = {}): string {
  let out = text;
  for (const [name, cert] of Object.entries({ idp: keys.idp, idpNext: keys.idpNext, sp: keys.sp })) out = out.split(pemBody(cert.certificate)).join(`[cert:${name}]`);
  for (const [value, name] of Object.entries(known)) out = out.split(value).join(`[${name}]`);
  const ids = new Map<string, string>();
  out = out.replace(/_[0-9a-f]{40}/g, (m) => {
    if (!ids.has(m)) ids.set(m, `_ID${ids.size + 1}`);
    return ids.get(m)!;
  });
  return out
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/g, "[instant]")
    .replace(/<ds:DigestValue>[^<]*<\/ds:DigestValue>/g, "<ds:DigestValue>[digest]</ds:DigestValue>")
    .replace(/<ds:SignatureValue>[^<]*<\/ds:SignatureValue>/g, "<ds:SignatureValue>[signature]</ds:SignatureValue>")
    .replace(/_[A-Za-z0-9_-]{32}(?=["<])/g, "[session-index]")
    .replace(/(rid|cid|RelayState)(=|%3D)[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g, "$1$2[token]")
    .replace(/nonce="[^"]*"/g, 'nonce="[nonce]"');
}

async function host(saml: Record<string, unknown> = {}) {
  const { auth } = await createHost({
    saml: {
      singleLogout: { enabled: true },
      serviceProviders: [
        { id: A.id, entityId: A.entityId, acsUrls: [A.acs], spCertificates: keys.sp.certificate, singleLogoutService: { url: A.slo }, allowIdpInitiated: true },
        { id: B.id, entityId: B.entityId, acsUrls: [B.acs], spCertificates: keys.idpNext.certificate, singleLogoutService: { url: B.slo, binding: "post" } },
        { id: P.id, entityId: P.entityId, acsUrls: [P.acs], nameIdFormat: PERSISTENT, attributes: { email: "email", name: "name" } },
      ] as any,
      ...saml,
    },
  });
  const browser = new Browser(auth);
  const email = `off${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}@example.com`;
  const user = await browser.signUp(email);
  return { auth, browser, user, known: { [email]: "email", [user.id]: "userId" } as Record<string, string> };
}

const headers = (res: Response, known: Record<string, string>) =>
  normalise(
    [`status ${res.status}`, ...["content-type", "cache-control", "vary", "location"].map((h) => `${h}: ${res.headers.get(h) ?? "-"}`)].join("\n"),
    known,
  );

/** An outgoing HTTP-Redirect message: parameter names in order, the decoded XML, and its IdP signature checked. */
async function redirectMessage(location: string, param: "SAMLRequest" | "SAMLResponse") {
  const u = new URL(location);
  const raw = parseRedirectQuery(u.search.slice(1), param);
  const xml = await decodeAuthnRequest(raw);
  verifyMessageSignature(raw, xml, [keys.idp.certificate], { allowInsecureSha1: false });
  return { target: `${u.origin}${u.pathname}`, params: [...u.searchParams.keys()].join("&"), sigAlg: u.searchParams.get("SigAlg"), xml };
}

describe("tenants off: output is unchanged (D-052)", () => {
  it("metadata: plain, signed with Single Logout, and with a rotation certificate", async () => {
    const plain = await createHost();
    const signed = await createHost({ saml: { singleLogout: { enabled: true }, signMetadata: true } });
    const rotation = await createHost({ saml: { signing: { ...baseOptions().signing, additionalCertificates: [keys.idpNext.certificate] } } });
    for (const [name, { auth }] of Object.entries({ plain, signed, rotation })) {
      const res = await auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`));
      const xml = await res.text();
      expect(`${headers(res, {})}\n\n${normalise(xml)}`).toMatchSnapshot(name);
    }
  });

  it("SP-initiated SSO: the signed Response, the persistent NameID derivation, and the POST binding's re-entry", async () => {
    const { auth, browser, user, known } = await host();
    const id = newRequestId();
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ id }).xml, { relayState: "rs-1" }));
    expect(res.status).toBe(200);
    const html = await res.clone().text();
    const form = await readAutoPost(res);
    const k = { ...known, [id]: "request-id" };
    expect(`${headers(res, k)}\n\n${normalise(form.xml, k)}`).toMatchSnapshot("response");
    // The auto-POST page around it, with the SAMLResponse value itself left out.
    expect(normalise(html.replace(/name="SAMLResponse" value="[^"]*"/, 'name="SAMLResponse" value="[response]"'), k)).toMatchSnapshot("auto-post page");
    await (await strictSp(auth)).verify(form.samlResponse); // both signatures, under the root key

    // Persistent NameIDs: HMAC(secret, "saml-idp:persistent\0" + SP entity ID + "\0" + user id), as before.
    const p = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ issuer: P.entityId, acsUrl: P.acs }).xml)));
    const expected = base64url(new Uint8Array(createHmac("sha256", SECRET).update(`saml-idp:persistent\u0000${P.entityId}\u0000${user.id}`).digest()));
    expect(p.xml).toContain(`<saml:NameID Format="${PERSISTENT}">${expected}</saml:NameID>`);

    // HTTP-POST binding: a 303 back to the same SSO URL.
    const post = await browser.fetch(SSO_URL, {
      method: "POST",
      crossSite: true,
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://sp.test" },
      body: new URLSearchParams({ SAMLRequest: btoa(authnRequestXml().xml) }).toString(),
    });
    expect(headers(post, known)).toMatchSnapshot("post binding 303");
    expect((await postBinding(browser, authnRequestXml().xml)).status).toBe(200);
  });

  it("signed-out and refused requests: the login redirect, a SAML error Response, an error page", async () => {
    const { auth } = await host();
    const anon = new Browser(auth);
    const login = await anon.fetch(await redirectUrl(authnRequestXml().xml));
    expect(headers(login, {})).toMatchSnapshot("login redirect");
    const id = newRequestId();
    const passive = await anon.fetch(await redirectUrl(authnRequestXml({ id, isPassive: true }).xml));
    const k = { [id]: "request-id" };
    const form = await readAutoPost(passive);
    expect(normalise(form.xml, k)).toMatchSnapshot("NoPassive response");
    verifyMessageSignature({ binding: "post", samlRequest: "", relayState: undefined }, form.xml, [keys.idp.certificate], { allowInsecureSha1: false });
    const unknown = await anon.fetch(await redirectUrl(authnRequestXml({ issuer: "https://nobody.test/sp" }).xml));
    expect(normalise(`${headers(unknown, {})}\n\n${await unknown.text()}`)).toMatchSnapshot("unknown SP page");
  });

  it("IdP-initiated SSO", async () => {
    const { browser, known } = await host();
    const res = await browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=${A.id}`);
    const form = await readAutoPost(res);
    expect(normalise(form.xml, known)).toMatchSnapshot("unsolicited response");
  });

  it("Single Logout: the LogoutRequest to a participant (POST), and the LogoutResponse to the originator (Redirect)", async () => {
    const { browser, known } = await host();
    const a = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ issuer: B.entityId, acsUrl: B.acs }).xml)));
    const nameId = /<saml:NameID [^>]*>([^<]+)</.exec(a.xml)![1]!;
    const sessionIndex = /SessionIndex="([^"]+)"/.exec(a.xml)![1]!;
    const lrId = `_lr${Date.now().toString(36)}`;
    const lr =
      `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${lrId}" Version="2.0" IssueInstant="${new Date().toISOString().replace(/\.\d{3}Z$/, "Z")}" Destination="${SLO}">` +
      `<saml:Issuer>${A.entityId}</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>` +
      `<samlp:SessionIndex>${sessionIndex}</samlp:SessionIndex></samlp:LogoutRequest>`;
    const toB = await browser.fetch(redirectBindingUrl(SLO, "SAMLRequest", lr, "rs-a", spSigning(keys.sp.privateKey)));
    const k = { ...known, [lrId]: "logout-request-id" };
    expect(headers(toB, k)).toMatchSnapshot("to participant: headers");
    const postForm = await toB.text();
    const toBxml = new TextDecoder().decode(Uint8Array.from(atob(/name="SAMLRequest" value="([^"]*)"/.exec(postForm)![1]!), (c) => c.charCodeAt(0)));
    verifyMessageSignature({ binding: "post", samlRequest: "", relayState: undefined }, toBxml, [keys.idp.certificate], { allowInsecureSha1: false });
    expect(normalise(toBxml, k)).toMatchSnapshot("to participant: LogoutRequest");
    const relay = /name="RelayState" value="([^"]*)"/.exec(postForm)![1]!;
    const inResponseTo = /ID="([^"]+)"/.exec(toBxml)![1]!;
    const answer = buildLogoutResponse({ issuer: B.entityId, destination: SLO, inResponseTo, status: ["Success"], now: new Date() });
    const done = await browser.fetch(redirectBindingUrl(SLO, "SAMLResponse", answer, relay, spSigning(keys.idpNext.privateKey)));
    const toA = await redirectMessage(done.headers.get("location")!, "SAMLResponse");
    expect(normalise(JSON.stringify({ status: done.status, target: toA.target, params: toA.params, sigAlg: toA.sigAlg }, null, 1), k)).toMatchSnapshot("to originator: redirect");
    expect(normalise(toA.xml, k)).toMatchSnapshot("to originator: LogoutResponse");
  });

  it("the schema and the routes, with every optional feature on", () => {
    const all = samlIdp(
      baseOptions({
        registry: { enabled: true, canManage: () => true },
        singleLogout: { enabled: true },
        events: { onSessionEnded: () => {} },
        auditLog: { enabled: true },
      }),
    );
    const none = samlIdp(baseOptions());
    expect(JSON.stringify(all.schema, null, 1)).toMatchSnapshot("schema, all features");
    expect(JSON.stringify(none.schema, null, 1)).toMatchSnapshot("schema, defaults");
    const routes = (p: typeof all) => Object.entries(p.endpoints).map(([k, e]: [string, any]) => `${k} ${JSON.stringify(e.options?.method)} ${e.path ?? "(server only)"}`);
    expect(routes(all).join("\n")).toMatchSnapshot("routes, all features");
    expect(routes(none).join("\n")).toMatchSnapshot("routes, defaults");
  });
});

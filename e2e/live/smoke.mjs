#!/usr/bin/env node
// Live smoke test against a DEPLOYED IdP: the security behaviours the test suite proves,
// checked on the real thing. Unauthenticated only (no user needed), safe to repeat: it creates
// only short-lived pending/replay rows, which the IdP sweeps.
//
//   IDP_URL=https://<worker>.workers.dev SP_ENTITY_ID=<registered SP entity ID> node e2e/live/smoke.mjs
//
// SP_ENTITY_ID must be an SP registered on that IdP whose ACS URL equals its entity ID or is its
// first ACS URL (true for Cloudflare Access); set SP_ACS if different.
import { deflateRawSync } from "node:zlib";
import { SignedXml } from "xml-crypto";

const IDP = (process.env.IDP_URL ?? "").replace(/\/+$/, "");
const SP = process.env.SP_ENTITY_ID ?? "";
const ACS = process.env.SP_ACS ?? SP;
if (!IDP || !SP) {
  console.error("set IDP_URL and SP_ENTITY_ID");
  process.exit(2);
}
const AUTH = `${IDP}/api/auth`;
const SSO = `${AUTH}/saml2/idp/sso`;

const results = [];
async function check(name, fn) {
  try {
    const detail = await fn();
    results.push({ ok: true, name, detail });
  } catch (e) {
    results.push({ ok: false, name, detail: e.message });
  }
}
function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

let n = 0;
const iso = (d = new Date()) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
function authnRequest({ id = `_smoke${Date.now().toString(36)}${n++}`, issuer = SP, acs = ACS, issueInstant = iso(), extra = "", inner = "" } = {}) {
  return {
    id,
    xml:
      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
      `ID="${id}" Version="2.0" IssueInstant="${issueInstant}" Destination="${SSO}" AssertionConsumerServiceURL="${acs}" ${extra}>` +
      `<saml:Issuer>${issuer}</saml:Issuer>${inner}</samlp:AuthnRequest>`,
  };
}
const enc = (xml) => encodeURIComponent(deflateRawSync(xml).toString("base64"));
const redirect = (xml, extraQuery = "") => fetch(`${SSO}?SAMLRequest=${enc(xml)}${extraQuery}`, { redirect: "manual" });
const code = async (res) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const statusCodes = (xml) => [...xml.matchAll(/StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:([A-Za-z]+)"/g)].map((m) => m[1]);
function autoPost(html) {
  const b64 = /name="SAMLResponse" value="([^"]+)"/.exec(html)?.[1];
  const action = /<form method="post" action="([^"]+)"/.exec(html)?.[1];
  return b64 && { action: action.replace(/&amp;/g, "&"), xml: Buffer.from(b64, "base64").toString("utf8") };
}

const metadata = await (await fetch(`${AUTH}/saml2/idp/metadata`)).text();
const certB64 = /<ds:X509Certificate>([^<]+)</.exec(metadata)?.[1];
const certPem = `-----BEGIN CERTIFICATE-----\n${certB64?.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;

await check("metadata: served privately, varies by host, SAML content type", async () => {
  const r = await fetch(`${AUTH}/saml2/idp/metadata`);
  expect(r.status === 200, `status ${r.status}`);
  expect(r.headers.get("content-type")?.startsWith("application/samlmetadata+xml"), r.headers.get("content-type"));
  expect(r.headers.get("cache-control") === "private, max-age=300", r.headers.get("cache-control"));
  expect(/Host/.test(r.headers.get("vary") ?? ""), `vary=${r.headers.get("vary")}`);
  return r.headers.get("cache-control");
});

await check("unknown SP issuer → 400 UNKNOWN_SERVICE_PROVIDER, error-page headers", async () => {
  const r = await redirect(authnRequest({ issuer: "https://evil.example/sp", acs: "https://evil.example/acs" }).xml);
  expect(r.status === 400 && (await code(r)) === "UNKNOWN_SERVICE_PROVIDER", `got ${r.status} ${await code(r)}`);
  const csp = r.headers.get("content-security-policy") ?? "";
  expect(csp.includes("form-action 'none'") && csp.includes("default-src 'none'"), csp);
  expect(r.headers.get("x-frame-options") === "DENY" && r.headers.get("cache-control") === "no-store", "framing/caching headers");
  expect(!(await r.text()).includes("evil.example"), "reflected the issuer");
  return "400";
});

await check("ACS URL not on the allow-list → 400, never reflected", async () => {
  const r = await redirect(authnRequest({ acs: "https://evil.example/steal" }).xml);
  expect(r.status === 400 && (await code(r)) === "ACS_URL_NOT_ALLOWED", `got ${r.status} ${await code(r)}`);
  expect(!(await r.text()).includes("evil.example"), "reflected the ACS URL");
  return "400";
});

await check("replayed AuthnRequest ID → 400 DUPLICATE_REQUEST_ID", async () => {
  const { xml } = authnRequest();
  const first = await redirect(xml);
  expect(first.status === 302, `first ${first.status}`);
  const again = await redirect(xml);
  expect(again.status === 400 && (await code(again)) === "DUPLICATE_REQUEST_ID", `second ${again.status} ${await code(again)}`);
  return "302 then 400";
});

await check("duplicate / percent-encoded SAML parameters → 400", async () => {
  const a = await redirect(authnRequest().xml, "&RelayState=a&RelayState=b");
  const b = await redirect(authnRequest().xml, "&RelayState=a&Relay%53tate=b");
  expect(a.status === 400 && b.status === 400, `${a.status} ${b.status}`);
  return "400, 400";
});

await check("RelayState: 1025 bytes → 400; 200 bytes (Cloudflare-sized) → accepted", async () => {
  const big = await redirect(authnRequest().xml, `&RelayState=${"x".repeat(1025)}`);
  expect(big.status === 400 && (await code(big)) === "RELAY_STATE_TOO_LONG", `big ${big.status}`);
  const ok = await redirect(authnRequest().xml, `&RelayState=${"r".repeat(200)}`);
  expect(ok.status === 302, `200-byte ${ok.status}`);
  return "400, 302";
});

for (const [name, xml] of [
  ["DOCTYPE / entity", `<!DOCTYPE x [<!ENTITY e "boom">]>${authnRequest().xml}`],
  ["schema-invalid element", authnRequest({ inner: "<samlp:Bogus/>" }).xml],
  ["IssueInstant 10 minutes old", authnRequest({ issueInstant: iso(new Date(Date.now() - 600_000)) }).xml],
  ["IssueInstant without a time zone", authnRequest({ issueInstant: iso().slice(0, -1) }).xml],
  ["a LogoutRequest instead of an AuthnRequest", `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x${n++}" Version="2.0" IssueInstant="${iso()}"><saml:Issuer>${SP}</saml:Issuer><saml:NameID>a</saml:NameID></samlp:LogoutRequest>`],
]) {
  await check(`${name} → 400 INVALID_SAML_REQUEST`, async () => {
    const r = await redirect(xml);
    expect(r.status === 400 && (await code(r)) === "INVALID_SAML_REQUEST", `got ${r.status} ${await code(r)}`);
    return "400";
  });
}

await check("DEFLATE bomb (5 MB inflated) → 400 fast", async () => {
  const t0 = Date.now();
  const bomb = encodeURIComponent(deflateRawSync(`<a>${" ".repeat(5_000_000)}</a>`).toString("base64"));
  const r = await fetch(`${SSO}?SAMLRequest=${bomb}`, { redirect: "manual" });
  expect(r.status === 400, `status ${r.status}`);
  return `400 in ${Date.now() - t0} ms`;
});

await check("IsPassive without a session → signed NoPassive Response to the ACS, no assertion", async () => {
  const { id, xml } = authnRequest({ extra: 'IsPassive="true"' });
  const r = await redirect(xml);
  const html = await r.text();
  const form = autoPost(html);
  expect(r.status === 200 && form, `status ${r.status}`);
  expect(form.action === ACS, `action ${form.action}`);
  expect(statusCodes(form.xml).join("/") === "Responder/NoPassive", statusCodes(form.xml).join("/"));
  expect(form.xml.includes(`InResponseTo="${id}"`) && !form.xml.includes("<saml:Assertion"), "InResponseTo/assertion");
  expect(!/form-action/.test(r.headers.get("content-security-policy") ?? ""), "auto-POST page must not set form-action");
  // Verify the XML signature with the certificate from metadata.
  const sig = /<ds:Signature[\s\S]*?<\/ds:Signature>/.exec(form.xml)?.[0];
  expect(sig, "no signature");
  const v = new SignedXml({ publicCert: certPem });
  v.loadSignature(sig);
  expect(v.checkSignature(form.xml), "signature does not verify against the metadata certificate");
  const alg = /SignatureMethod Algorithm="([^"]+)"/.exec(sig)?.[1];
  expect(alg?.endsWith("rsa-sha256"), `algorithm ${alg}`);
  return `signed (${alg.split("#")[1]}) and verified`;
});

await check("HTTP-POST binding → 303 same-site re-entry; single-use", async () => {
  const body = new URLSearchParams({ SAMLRequest: Buffer.from(authnRequest().xml).toString("base64") });
  const r = await fetch(SSO, { method: "POST", body, redirect: "manual", headers: { origin: new URL(SP).origin } });
  expect(r.status === 303, `status ${r.status}`);
  const loc = r.headers.get("location");
  expect(loc?.startsWith(`${SSO}?cid=`), `location ${loc}`);
  const first = await fetch(loc, { redirect: "manual" });
  expect(first.status === 302 && new URL(first.headers.get("location")).pathname === "/sign-in", `first ${first.status}`);
  const again = await fetch(loc, { redirect: "manual" });
  expect(again.status === 400, `reuse ${again.status}`);
  return "303 → 302 sign-in; reuse 400";
});

await check("resume with a malformed or unknown rid → 400", async () => {
  const bad = await fetch(`${AUTH}/saml2/idp/resume?rid=../../etc`, { redirect: "manual" });
  const unknown = await fetch(`${AUTH}/saml2/idp/resume?rid=${"A".repeat(43)}`, { redirect: "manual" });
  expect(bad.status === 400, `malformed ${bad.status}`);
  // Without a session, an unknown-but-well-formed rid is sent to sign in (not consumed).
  expect(unknown.status === 302 || unknown.status === 400, `unknown ${unknown.status}`);
  return `${bad.status}, ${unknown.status}`;
});

await check("dev mailbox is off in production", async () => {
  const r = await fetch(`${IDP}/dev/mailbox?email=someone@example.com`);
  expect(r.status === 404, `status ${r.status}`);
  return "404";
});

const failed = results.filter((r) => !r.ok).length;
console.log(`\nLive smoke: ${IDP}\n`);
for (const r of results) console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  — ${r.detail}` : ""}`);
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);

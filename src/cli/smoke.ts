// `smoke`: the plugin's security behaviours, checked against a DEPLOYED IdP. Unauthenticated
// only (no user needed) and safe to repeat: it leaves only short-lived pending/replay rows,
// which the IdP sweeps.
import { deflateRawSync } from "node:zlib";
import { newSamlId } from "../saml/response";
import { buildAuthnRequest } from "./request";
import { metadataUrl, parseDoc, readIdpMetadata, verifyEnveloped } from "./saml";
import { fetchText, httpsOnly, Report, UsageError } from "./util";

export interface SmokeOptions {
  sp?: string;
  acs?: string;
  basePath: string;
  allowHttp: boolean;
}

const iso = (d = new Date()) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
const enc = (xml: string) => encodeURIComponent(deflateRawSync(Buffer.from(xml)).toString("base64"));
const pageCode = (html: string) => /<code>([A-Z_]+)<\/code>/.exec(html)?.[1];
const statusCodes = (xml: string) => [...xml.matchAll(/StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:([A-Za-z]+)"/g)].map((m) => m[1]).join("/");

function autoPost(html: string) {
  const b64 = /name="SAMLResponse" value="([^"]+)"/.exec(html)?.[1];
  const action = /<form method="post" action="([^"]+)"/.exec(html)?.[1];
  return b64 && action ? { action: action.replace(/&amp;/g, "&"), xml: Buffer.from(b64, "base64").toString("utf8") } : undefined;
}

export async function smoke(target: string | undefined, opts: SmokeOptions): Promise<Report> {
  if (!target) throw new UsageError("smoke needs the IdP URL");
  if (!opts.sp) throw new UsageError("--sp <entity ID of an SP registered on that IdP> is required");
  const SP = opts.sp;
  const ACS = opts.acs ?? SP;
  const report = new Report();
  const mdUrl = metadataUrl(httpsOnly(target, opts.allowHttp).href, opts.basePath);
  const { res: mdRes, text: mdXml } = await fetchText(mdUrl);
  if (!mdRes.ok) throw new UsageError(`${mdUrl}: HTTP ${mdRes.status}`);
  const md = readIdpMetadata(mdXml);
  const SSO = md.sso.find((s) => s.binding.endsWith("HTTP-Redirect"))?.location;
  if (!SSO) throw new UsageError("no HTTP-Redirect SSO endpoint in metadata");
  const AUTH = SSO.replace(/\/saml2\/idp\/sso$/, "");
  report.section("Target", { Metadata: mdUrl, SSO, SP, ACS });

  const req = (o: { issuer?: string; acs?: string; issueInstant?: string; extra?: string; inner?: string; id?: string } = {}) => {
    const id = o.id ?? newSamlId();
    let xml = buildAuthnRequest({ id, issuer: o.issuer ?? SP, destination: SSO, acs: o.acs ?? ACS });
    if (o.issueInstant) xml = xml.replace(/IssueInstant="[^"]+"/, `IssueInstant="${o.issueInstant}"`);
    if (o.extra) xml = xml.replace("<samlp:AuthnRequest ", `<samlp:AuthnRequest ${o.extra} `);
    if (o.inner) xml = xml.replace("</samlp:AuthnRequest>", `${o.inner}</samlp:AuthnRequest>`);
    return { id, xml };
  };
  const redirect = (xml: string, extra = "") => fetchText(`${SSO}?SAMLRequest=${enc(xml)}${extra}`);

  async function check(name: string, fn: () => Promise<string>) {
    try {
      report.pass(`${name}  (${await fn()})`);
    } catch (e) {
      report.fail(`${name}: ${(e as Error).message}`);
    }
  }
  const expect = (cond: unknown, msg: string) => {
    if (!cond) throw new Error(msg);
  };

  await check("metadata: private caching, varies by host, SAML content type", async () => {
    expect(mdRes.headers.get("content-type")?.startsWith("application/samlmetadata+xml"), `content-type ${mdRes.headers.get("content-type")}`);
    expect(mdRes.headers.get("cache-control")?.startsWith("private"), `cache-control ${mdRes.headers.get("cache-control")}`);
    expect(/Host/.test(mdRes.headers.get("vary") ?? ""), `vary ${mdRes.headers.get("vary")}`);
    return mdRes.headers.get("cache-control") ?? "";
  });

  await check("unknown SP → 400 UNKNOWN_SERVICE_PROVIDER, locked-down error page, not reflected", async () => {
    const { res, text } = await redirect(req({ issuer: "https://evil.example/sp", acs: "https://evil.example/acs" }).xml);
    expect(res.status === 400 && pageCode(text) === "UNKNOWN_SERVICE_PROVIDER", `got ${res.status} ${pageCode(text)}`);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp.includes("default-src 'none'") && csp.includes("form-action 'none'"), `CSP ${csp}`);
    expect(res.headers.get("x-frame-options") === "DENY" && res.headers.get("cache-control") === "no-store", "framing/caching headers");
    expect(!text.includes("evil.example"), "reflected the issuer");
    return "400";
  });

  const first = await redirect(req().xml);
  if (first.res.status === 400 && pageCode(first.text) === "UNKNOWN_SERVICE_PROVIDER") {
    report.fail(`${SP} is not registered on this IdP: the remaining checks need a registered SP (--sp, and --acs if its first ACS URL is not the entity ID)`);
    return report;
  }

  await check("ACS URL not on the allow-list → 400, not reflected", async () => {
    const { res, text } = await redirect(req({ acs: "https://evil.example/steal" }).xml);
    expect(res.status === 400 && pageCode(text) === "ACS_URL_NOT_ALLOWED", `got ${res.status} ${pageCode(text)}`);
    expect(!text.includes("evil.example"), "reflected the ACS URL");
    return "400";
  });

  await check("replayed AuthnRequest ID → 400 DUPLICATE_REQUEST_ID", async () => {
    const { xml } = req();
    const a = await redirect(xml);
    expect(a.res.status === 302, `first ${a.res.status} ${pageCode(a.text) ?? ""}`);
    const b = await redirect(xml);
    expect(b.res.status === 400 && pageCode(b.text) === "DUPLICATE_REQUEST_ID", `second ${b.res.status} ${pageCode(b.text)}`);
    return "302 then 400";
  });

  await check("duplicate / percent-encoded SAML parameter names → 400", async () => {
    const a = await redirect(req().xml, "&RelayState=a&RelayState=b");
    const b = await redirect(req().xml, "&RelayState=a&Relay%53tate=b");
    expect(a.res.status === 400 && b.res.status === 400, `${a.res.status} ${b.res.status}`);
    return "400, 400";
  });

  await check("RelayState over 1024 bytes → 400; 200 bytes → accepted", async () => {
    const big = await redirect(req().xml, `&RelayState=${"x".repeat(1025)}`);
    expect(big.res.status === 400 && pageCode(big.text) === "RELAY_STATE_TOO_LONG", `1025 bytes: ${big.res.status}`);
    const ok = await redirect(req().xml, `&RelayState=${"r".repeat(200)}`);
    expect(ok.res.status === 302, `200 bytes: ${ok.res.status}`);
    return "400, 302";
  });

  const invalid: [string, string][] = [
    ["DOCTYPE / entity", `<!DOCTYPE x [<!ENTITY e "boom">]>${req().xml}`],
    ["schema-invalid element", req({ inner: "<samlp:Bogus/>" }).xml],
    ["IssueInstant 10 minutes old", req({ issueInstant: iso(new Date(Date.now() - 600_000)) }).xml],
    ["IssueInstant without a time zone", req({ issueInstant: iso().slice(0, -1) }).xml],
    [
      "a LogoutRequest instead of an AuthnRequest",
      `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${newSamlId()}" Version="2.0" IssueInstant="${iso()}"><saml:Issuer>${SP}</saml:Issuer><saml:NameID>a</saml:NameID></samlp:LogoutRequest>`,
    ],
  ];
  for (const [name, xml] of invalid)
    await check(`${name} → 400 INVALID_SAML_REQUEST`, async () => {
      const { res, text } = await redirect(xml);
      expect(res.status === 400 && pageCode(text) === "INVALID_SAML_REQUEST", `got ${res.status} ${pageCode(text)}`);
      return "400";
    });

  await check("DEFLATE bomb (5 MB inflated) → 400", async () => {
    const t0 = Date.now();
    const bomb = encodeURIComponent(deflateRawSync(Buffer.from(`<a>${" ".repeat(5_000_000)}</a>`)).toString("base64"));
    const { res } = await fetchText(`${SSO}?SAMLRequest=${bomb}`);
    expect(res.status === 400, `status ${res.status}`);
    return `400 in ${Date.now() - t0} ms`;
  });

  await check("IsPassive without a session → signed NoPassive Response, no assertion", async () => {
    const { id, xml } = req({ extra: 'IsPassive="true"' });
    const { res, text } = await redirect(xml);
    const form = autoPost(text);
    expect(res.status === 200 && form, `status ${res.status}`);
    if (!form) throw new Error("no auto-POST form");
    expect(form.action === ACS, `posted to ${form.action}`);
    expect(statusCodes(form.xml) === "Responder/NoPassive", statusCodes(form.xml));
    expect(form.xml.includes(`InResponseTo="${id}"`) && !/<(\w+:)?Assertion[\s>]/.test(form.xml), "InResponseTo/assertion");
    expect(!/form-action/.test(res.headers.get("content-security-policy") ?? ""), "auto-POST page must not set form-action");
    const doc = parseDoc(form.xml);
    const sig = verifyEnveloped(form.xml, doc, doc.documentElement, md.signingCertificates);
    expect(sig.valid, `signature: ${sig.problem ?? "not signed"}`);
    return `signed (${sig.algorithm}) and verified with the metadata certificate`;
  });

  await check("HTTP-POST binding → 303 same-site re-entry, single use", async () => {
    const body = new URLSearchParams({ SAMLRequest: Buffer.from(req().xml).toString("base64") });
    const { res } = await fetchText(SSO, { method: "POST", body, headers: { origin: new URL(ACS).origin } });
    expect(res.status === 303, `status ${res.status}`);
    const loc = res.headers.get("location") ?? "";
    expect(loc.startsWith(`${SSO}?cid=`), `location ${loc}`);
    const a = await fetchText(loc);
    expect(a.res.status === 302, `first ${a.res.status}`);
    const b = await fetchText(loc);
    expect(b.res.status === 400, `reuse ${b.res.status}`);
    return "303 → 302; reuse 400";
  });

  await check("resume with a malformed rid → 400", async () => {
    const { res } = await fetchText(`${AUTH}/saml2/idp/resume?rid=../../etc`);
    expect(res.status === 400, `status ${res.status}`);
    return "400";
  });

  return report;
}

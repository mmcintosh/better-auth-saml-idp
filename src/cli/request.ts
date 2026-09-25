// `request`: build an AuthnRequest to try an IdP by hand (open the URL in a browser).
import { createPrivateKey, sign } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { escapeXml, newSamlId } from "../saml/response";
import { metadataUrl, readIdpMetadata } from "./saml";
import { fetchText, httpsOnly, readFileArg, Report, UsageError } from "./util";

export interface RequestOptions {
  sp?: string;
  acs?: string;
  binding: string;
  relayState?: string;
  forceAuthn: boolean;
  passive: boolean;
  nameIdFormat?: string;
  authnContext?: string;
  signKey?: string;
  sigAlg: string;
  basePath: string;
  allowHttp: boolean;
}

const SIG_ALGS: Record<string, { uri: string; hash: string }> = {
  "rsa-sha256": { uri: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", hash: "sha256" },
  "rsa-sha512": { uri: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", hash: "sha512" },
};

const NAMEID: Record<string, string> = {
  email: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
};

export function buildAuthnRequest(o: { id: string; issuer: string; destination: string; acs?: string; forceAuthn?: boolean; passive?: boolean; nameIdFormat?: string; authnContext?: string; now?: Date }): string {
  const attrs = [
    `ID="${o.id}"`,
    `Version="2.0"`,
    `IssueInstant="${(o.now ?? new Date()).toISOString().replace(/\.\d{3}Z$/, "Z")}"`,
    `Destination="${escapeXml(o.destination)}"`,
    o.acs ? `AssertionConsumerServiceURL="${escapeXml(o.acs)}"` : "",
    `ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`,
    o.forceAuthn ? `ForceAuthn="true"` : "",
    o.passive ? `IsPassive="true"` : "",
  ].filter(Boolean);
  const policy = o.nameIdFormat ? `<samlp:NameIDPolicy Format="${escapeXml(o.nameIdFormat)}" AllowCreate="true"/>` : "";
  const rac = o.authnContext
    ? `<samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>${escapeXml(o.authnContext)}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`
    : "";
  return (
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ${attrs.join(" ")}>` +
    `<saml:Issuer>${escapeXml(o.issuer)}</saml:Issuer>${policy}${rac}</samlp:AuthnRequest>`
  );
}

export async function request(target: string | undefined, opts: RequestOptions): Promise<Report> {
  if (!target) throw new UsageError("request needs the IdP URL");
  if (!opts.sp) throw new UsageError("--sp <entity ID of a registered SP> is required");
  if (opts.binding !== "redirect" && opts.binding !== "post") throw new UsageError("--binding must be redirect or post");
  if (opts.signKey && opts.binding === "post") throw new UsageError("--sign-key works with --binding redirect (the IdP verifies Redirect-binding signatures only)");
  const report = new Report();

  const url = metadataUrl(httpsOnly(target, opts.allowHttp).href, opts.basePath);
  const { res, text } = await fetchText(url);
  if (!res.ok) throw new UsageError(`${url}: HTTP ${res.status}`);
  const md = readIdpMetadata(text);
  const binding = opts.binding === "post" ? "HTTP-POST" : "HTTP-Redirect";
  const sso = md.sso.find((s) => s.binding.endsWith(binding))?.location;
  if (!sso) throw new UsageError(`the IdP publishes no ${binding} SSO endpoint`);

  const id = newSamlId();
  const nameIdFormat = opts.nameIdFormat ? (NAMEID[opts.nameIdFormat] ?? opts.nameIdFormat) : undefined;
  const xml = buildAuthnRequest({ id, issuer: opts.sp, destination: sso, acs: opts.acs, forceAuthn: opts.forceAuthn, passive: opts.passive, nameIdFormat, authnContext: opts.authnContext });
  report.section("AuthnRequest", {
    ID: id,
    Issuer: opts.sp,
    Destination: sso,
    "ACS URL": opts.acs ?? "(not sent: the SP's first registered ACS URL is used)",
    ForceAuthn: opts.forceAuthn || undefined,
    IsPassive: opts.passive || undefined,
    NameIDPolicy: nameIdFormat,
    RequestedAuthnContext: opts.authnContext,
    RelayState: opts.relayState,
  });
  report.data = { id, xml, sso };

  if (opts.binding === "post") {
    const form =
      `<!doctype html><meta charset="utf-8"><title>SAML AuthnRequest</title>` +
      `<form method="post" action="${escapeXml(sso)}">` +
      `<input type="hidden" name="SAMLRequest" value="${Buffer.from(xml).toString("base64")}">` +
      (opts.relayState ? `<input type="hidden" name="RelayState" value="${escapeXml(opts.relayState)}">` : "") +
      `<button>Send AuthnRequest (${escapeXml(id)})</button></form>`;
    report.data.html = form;
    report.info("HTTP-POST: save the HTML below to a file and open it in a browser");
    report.output = form;
    return report;
  }

  // HTTP-Redirect: the signature covers the exact encoded octets, in this order (Bindings §3.4.4.1).
  let query = `SAMLRequest=${encodeURIComponent(deflateRawSync(Buffer.from(xml)).toString("base64"))}`;
  if (opts.relayState !== undefined) query += `&RelayState=${encodeURIComponent(opts.relayState)}`;
  if (opts.signKey) {
    const alg = SIG_ALGS[opts.sigAlg];
    if (!alg) throw new UsageError(`--sig-alg must be one of ${Object.keys(SIG_ALGS).join(", ")}`);
    query += `&SigAlg=${encodeURIComponent(alg.uri)}`;
    const key = createPrivateKey(readFileArg(opts.signKey, "signing key"));
    query += `&Signature=${encodeURIComponent(sign(alg.hash, Buffer.from(query), key).toString("base64"))}`;
    report.pass(`signed with ${opts.sigAlg}`);
  }
  const out = `${sso}${sso.includes("?") ? "&" : "?"}${query}`;
  report.data.url = out;
  report.info("open this URL in a browser; `decode` explains what comes back");
  report.output = out;
  return report;
}

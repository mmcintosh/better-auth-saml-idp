// A small, strict SAML SP built on @node-saml/node-saml, shaped like the hosted SPs we target:
//  - sends AuthnRequests with the HTTP-POST binding (auto-submitting form) or HTTP-Redirect,
//  - after its ACS consumes the Response, 302s the browser to a DIFFERENT site (app.test),
//    as Cloudflare Access, AWS and HubSpot do. Both behaviours are what hid review findings
//    #5 (CSP form-action) and #6 (SameSite on POST) from the scripted browser.
import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import { TLS } from "./tls.mjs";
import { SAML } from "@node-saml/node-saml";
import { IDP_ENTITY, IDP_SSO, TEST_APP, TEST_SP } from "./config.mjs";

function samlFor(cert, variant) {
  return new SAML({
    issuer: `${TEST_SP}/metadata`,
    callbackUrl: `${TEST_SP}/acs`,
    entryPoint: IDP_SSO,
    idpIssuer: IDP_ENTITY,
    idpCert: cert,
    audience: `${TEST_SP}/metadata`,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    validateInResponseTo: "always",
    acceptedClockSkewMs: 60_000,
    signatureAlgorithm: "sha256",
    // RequestedAuthnContext is exercised in the integration tests; the IdP here asserts
    // "unspecified", which an exact PasswordProtectedTransport request can't match.
    disableRequestedAuthnContext: true,
    authnRequestBinding: variant.binding === "post" ? "HTTP-POST" : "HTTP-Redirect",
    passive: variant.passive,
  });
}

const VARIANTS = {
  post: { binding: "post", passive: false },
  redirect: { binding: "redirect", passive: false },
  "post-passive": { binding: "post", passive: true },
};

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let s = "";
    req.on("data", (c) => (s += c));
    req.on("end", () => resolve(s));
    req.on("error", reject);
  });

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export function startTestSp(cert) {
  // One SAML instance per variant: InResponseTo is validated against that instance's cache.
  const sp = Object.fromEntries(Object.entries(VARIANTS).map(([k, v]) => [k, samlFor(cert, v)]));

  const tls = { key: readFileSync(TLS.key), cert: readFileSync(TLS.cert) };
  const spServer = createServer(tls, async (req, res) => {
    try {
      const url = new URL(req.url, TEST_SP);
      if (req.method === "GET" && url.pathname === "/login") {
        const variant = url.searchParams.get("variant") ?? "post";
        const saml = sp[variant];
        if (!saml) return void res.writeHead(400).end("unknown variant");
        if (VARIANTS[variant].binding === "post") {
          const html = await saml.getAuthorizeFormAsync(variant);
          return void res.writeHead(200, { "content-type": "text/html" }).end(html);
        }
        const location = await saml.getAuthorizeUrlAsync(variant, undefined, {});
        return void res.writeHead(302, { location }).end();
      }
      if (req.method === "POST" && url.pathname === "/acs") {
        const form = new URLSearchParams(await readBody(req));
        const variant = form.get("RelayState") ?? "post";
        const saml = sp[variant] ?? sp.post;
        const result = { variant };
        try {
          const { profile } = await saml.validatePostResponseAsync(Object.fromEntries(form));
          // node-saml reports a (signed) NoPassive status as "no user" rather than an error.
          if (!profile) Object.assign(result, { ok: false, noPassive: true });
          else Object.assign(result, { ok: true, nameID: profile.nameID, email: profile.email, issuer: profile.issuer });
        } catch (e) {
          Object.assign(result, { ok: false, error: String(e?.message ?? e) });
        }
        const done = new URL("/done", TEST_APP);
        done.searchParams.set("result", JSON.stringify(result));
        return void res.writeHead(302, { location: done.href }).end(); // cross-site redirect
      }
      if (url.pathname === "/metadata") {
        return void res.writeHead(200, { "content-type": "application/xml" }).end(sp.post.generateServiceProviderMetadata(null, null));
      }
      res.writeHead(404).end("not found");
    } catch (e) {
      res.writeHead(500).end(String(e?.stack ?? e));
    }
  });

  const appServer = createServer(tls, (req, res) => {
    const url = new URL(req.url, TEST_APP);
    if (url.pathname !== "/done") return void res.writeHead(404).end();
    const result = url.searchParams.get("result") ?? "{}";
    res
      .writeHead(200, { "content-type": "text/html" })
      .end(`<!doctype html><title>Test app</title><h1>Test app</h1><pre id="result">${esc(result)}</pre>`);
  });

  return new Promise((resolve) => {
    spServer.listen(9100, "127.0.0.1", () =>
      appServer.listen(9101, "127.0.0.1", () => resolve({ close: () => (spServer.close(), appServer.close()) })),
    );
  });
}

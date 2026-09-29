// Server routes for the demo UI (src/web/) and a built-in demo SP, so the whole SAML round trip
// can be tried in a browser without an outside service provider.
//
// The demo SP is only a viewer: it decodes the Response and shows what an SP would read, and which
// published certificate signed it. It does NOT verify the signature; a real SP must, with the
// certificate from the IdP's metadata.
import { serviceProviderFromMetadata, SpMetadataError } from "better-auth-saml-idp";
import type { Context, Hono } from "hono";
import { isSamlAdmin } from "./saml.ts";

// biome-ignore lint/suspicious/noExplicitAny: CharDB's Hono env, with c.var.auth
type C = Context<any>;
type Auth = { api: { getSession(o: { headers: Headers }): Promise<{ user: { id: string; email: string; emailVerified: boolean; isAnonymous?: boolean | null } } | null> }; handler(r: Request): Promise<Response>; $context: Promise<{ adapter: { findMany(o: object): Promise<unknown[]> } }> };

const auth = (c: C) => c.var.auth as Auth;
/** The IdP's own origin: BETTER_AUTH_URL, which pins its entity IDs (a request may arrive through a proxy). */
const baseOf = (c: C) => (process.env.BETTER_AUTH_URL ?? new URL(c.req.url).origin).replace(/\/+$/, "");
const idpOf = (origin: string) => `${origin}/api/auth/saml2/idp`;
/** The demo SP's entity ID in one IdP identity: "" for the root, else the tenant key. */
export const demoSpEntityId = (origin: string, tenantKey: string) => `${origin}/demo-sp/${tenantKey || "root"}`;
const DEMO_ACS = "/demo-sp/acs";

async function signedIn(c: C) {
  const session = await auth(c).api.getSession({ headers: c.req.raw.headers });
  return session && !session.user.isAnonymous ? session.user : null;
}
const sameOrigin = (c: C) => c.req.header("origin") === baseOf(c);
const esc = (s: string) => s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

export function registerDemo(app: Hono<any>) {
  // Who is signed in, and what the UI should offer them.
  app.get("/api/demo/me", async (c) => {
    const user = await signedIn(c);
    return c.json({
      user: user && { id: user.id, email: user.email, emailVerified: user.emailVerified },
      samlAdmin: user ? isSamlAdmin(user) : false,
      devMailbox: process.env.DEV_MAILBOX === "true",
      idp: idpOf(baseOf(c)),
    });
  });

  // Every organization, for the host's admins (Better Auth lists only your own).
  app.get("/api/demo/organizations", async (c) => {
    const user = await signedIn(c);
    if (!user || !isSamlAdmin(user)) return c.json({ error: "not allowed" }, 403);
    const rows = (await (await auth(c).$context).adapter.findMany({ model: "organization", limit: 500 })) as { id: string; name: string; slug: string }[];
    return c.json({ organizations: rows.map(({ id, name, slug }) => ({ id, name, slug })).sort((a, b) => a.name.localeCompare(b.name)) });
  });

  // An SP's metadata XML, turned into a configuration to review before saving.
  app.post("/api/demo/from-metadata", async (c) => {
    if (!(await signedIn(c)) || !sameOrigin(c)) return c.json({ error: "not allowed" }, 403);
    if (Number(c.req.header("content-length") ?? 0) > 1_100_000) return c.json({ error: "metadata too large" }, 413);
    const body = (await c.req.json().catch(() => null)) as { xml?: unknown; id?: unknown } | null;
    if (typeof body?.xml !== "string" || typeof body.id !== "string") return c.json({ error: "send { id, xml }" }, 400);
    try {
      return c.json(await serviceProviderFromMetadata(body.xml, { id: body.id }));
    } catch (e) {
      return c.json({ error: e instanceof SpMetadataError ? e.message : "could not read the metadata" }, 400);
    }
  });

  // The demo SP starts a sign-in (SP-initiated): an AuthnRequest over HTTP-Redirect.
  app.get("/demo-sp/login", async (c) => {
    const origin = baseOf(c);
    const tenantKey = c.req.query("tenant") ?? "";
    if (tenantKey && !/^[A-Za-z0-9_-]{1,64}$/.test(tenantKey)) return c.text("bad tenant", 400);
    const sso = `${idpOf(origin)}/sso${tenantKey ? `/${tenantKey}` : ""}`;
    const xml =
      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
      `ID="_${crypto.randomUUID()}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${sso}" ` +
      `AssertionConsumerServiceURL="${origin}${DEMO_ACS}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">` +
      `<saml:Issuer>${demoSpEntityId(origin, tenantKey)}</saml:Issuer></samlp:AuthnRequest>`;
    const deflated = new Uint8Array(await new Response(new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());
    const request = btoa(Array.from(deflated, (b) => String.fromCharCode(b)).join(""));
    return c.redirect(`${sso}?SAMLRequest=${encodeURIComponent(request)}&RelayState=${encodeURIComponent(tenantKey || "root")}`);
  });

  // The demo SP's ACS: what an SP would read from the Response.
  app.post(DEMO_ACS, async (c) => {
    const origin = baseOf(c);
    const form = await c.req.formData();
    const encoded = form.get("SAMLResponse");
    if (typeof encoded !== "string") return c.text("no SAMLResponse", 400);
    const xml = new TextDecoder().decode(Uint8Array.from(atob(encoded), (ch) => ch.charCodeAt(0)));
    const one = (re: RegExp) => re.exec(xml)?.[1] ?? "";
    const issuer = one(/<saml:Issuer[^>]*>([^<]+)<\/saml:Issuer>/);
    const status = one(/<samlp:StatusCode[^>]*Value="([^"]+)"/).split(":").pop() ?? "";
    const attributes = [...xml.matchAll(/<saml:Attribute Name="([^"]+)"[^>]*>([\s\S]*?)<\/saml:Attribute>/g)].map((m) => [
      m[1] ?? "",
      [...(m[2] ?? "").matchAll(/<saml:AttributeValue[^>]*>([^<]*)<\/saml:AttributeValue>/g)].map((v) => v[1]).join(", "),
    ]);
    const signingCert = one(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/).replace(/\s/g, "");
    // Which certificate in the issuer's own metadata is it? (Tenant entity IDs are their metadata
    // URLs; the root's metadata is at …/idp/metadata.) Asked of this Worker's own IdP.
    let certNote = "not an issuer of this IdP";
    if (issuer === idpOf(origin) || issuer.startsWith(`${idpOf(origin)}/metadata/`)) {
      const metadataUrl = issuer === idpOf(origin) ? `${issuer}/metadata` : issuer;
      const metadata = await (await auth(c).handler(new Request(metadataUrl))).text();
      const published = [...metadata.matchAll(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g)].map((m) => (m[1] ?? "").replace(/\s/g, ""));
      const at = published.indexOf(signingCert);
      certNote = at === -1 ? "NOT in the issuer's metadata" : `published in the issuer's metadata (certificate ${at + 1} of ${published.length})`;
    }
    const fingerprint = signingCert
      ? Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(atob(signingCert), (ch) => ch.charCodeAt(0)))), (b) => b.toString(16).padStart(2, "0").toUpperCase()).join(":")
      : "";
    const rows: [string, string][] = [
      ["Status", status],
      ["Issuer (the IdP identity)", issuer],
      ["Destination", one(/<samlp:Response[^>]*Destination="([^"]+)"/)],
      ["InResponseTo", one(/<samlp:Response[^>]*InResponseTo="([^"]+)"/) || "(IdP-initiated)"],
      ["Audience", one(/<saml:Audience>([^<]+)<\/saml:Audience>/)],
      ["NameID", one(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/)],
      ["NameID format", one(/<saml:NameID[^>]*Format="([^"]+)"/)],
      ["Signing certificate (SHA-256)", fingerprint],
      ["That certificate is", certNote],
      ["RelayState", String(form.get("RelayState") ?? "")],
      ...attributes.map(([n, v]) => [`Attribute: ${n}`, v] as [string, string]),
    ];
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12))));
    return new Response(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Demo SP: signed in</title>
<style nonce="${nonce}">body{font:15px/1.5 system-ui;margin:0;background:#f5f6f8;color:#1a1d24}main{max-width:52rem;margin:2rem auto;padding:0 1rem}
.card{background:#fff;border:1px solid #e2e5ea;border-radius:12px;padding:1.25rem 1.5rem;margin:1rem 0}h1{font-size:1.3rem;margin:0}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:.45rem .5rem;border-top:1px solid #eef0f3;vertical-align:top}th{width:16rem;color:#5b6270;font-weight:500}td{word-break:break-all;font:13px ui-monospace,monospace}
.ok{color:#067647}.warn{color:#b54708}details pre{white-space:pre-wrap;word-break:break-all;font-size:12px;background:#f5f6f8;padding:1rem;border-radius:8px}a{color:#1b57d0}</style></head><body><main>
<div class="card"><h1>Demo SP: <span class="${status === "Success" ? "ok" : "warn"}">${esc(status || "no status")}</span></h1>
<p>This is what a service provider receives at its ACS URL. The demo SP decodes it and shows the fields a real SP reads; a real SP also <b>verifies the signature</b> with the certificate from the IdP's metadata, which this page does not.</p>
<table>${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("")}</table></div>
<div class="card"><details><summary>The Response XML</summary><pre>${esc(xml)}</pre></details></div>
<p><a href="/#/try">Back to the demo</a></p></main></body></html>`,
      { headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": `default-src 'none'; style-src 'nonce-${nonce}'; frame-ancestors 'none'; base-uri 'none'`, "cache-control": "no-store" } },
    );
  });
}

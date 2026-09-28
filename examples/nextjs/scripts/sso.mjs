// A full SP-initiated sign-in against a running example, with @node-saml/node-saml as the SP:
// AuthnRequest → /sign-in → sign up → sign in → resume → signed Response, verified by the SP
// with the certificate from the IdP's metadata (InResponseTo, audience and signatures).
//
// TEST SHORTCUT: instead of clicking the verification link, this script marks the new user's
// email verified directly in ./data.db (the plugin only asserts verified emails). Run it from
// examples/nextjs, against the server using that database.
// Usage: node scripts/sso.mjs [base URL] (default http://localhost:3000)
import { DatabaseSync } from "node:sqlite";
import { SAML } from "@node-saml/node-saml";

const base = (process.argv[2] ?? "http://localhost:3000").replace(/\/+$/, "");
const SP = "http://localhost:4000/saml/metadata"; // the test SP from scripts/dev-keys.mjs
const ACS = "http://localhost:4000/saml/acs";
const email = `sso-${Date.now()}@example.com`;
const password = "correct horse battery staple";

function assert(ok, message) {
  if (!ok) {
    console.error(`FAIL ${message}`);
    process.exit(1);
  }
  console.log(`ok   ${message}`);
}

/** A one-origin browser: keeps cookies, never follows redirects. */
const jar = new Map();
async function browse(url, init = {}) {
  const headers = new Headers(init.headers);
  if (jar.size) headers.set("cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
  const res = await fetch(url, { ...init, headers, redirect: "manual" });
  for (const cookie of res.headers.getSetCookie()) {
    const [pair] = cookie.split(";");
    const i = pair.indexOf("=");
    jar.set(pair.slice(0, i), pair.slice(i + 1));
  }
  return res;
}
const postJSON = (path, body) =>
  browse(`${base}/api/auth${path}`, { method: "POST", headers: { "content-type": "application/json", origin: base }, body: JSON.stringify(body) });
const unescapeHtml = (s) => s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n))).replace(/&amp;/g, "&").replace(/&quot;/g, '"');

// The SP trusts the certificate the IdP publishes.
const metadata = await (await fetch(`${base}/api/auth/saml2/idp/metadata`)).text();
const certBody = /<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/.exec(metadata)?.[1];
assert(Boolean(certBody), "IdP certificate read from the metadata");
const sp = new SAML({
  issuer: SP,
  callbackUrl: ACS,
  entryPoint: `${base}/api/auth/saml2/idp/sso`,
  idpCert: `-----BEGIN CERTIFICATE-----\n${certBody}\n-----END CERTIFICATE-----`,
  audience: SP,
  wantAssertionsSigned: true,
  wantAuthnResponseSigned: true,
  validateInResponseTo: "always",
  signatureAlgorithm: "sha256",
});

// 1. The SP sends the signed-out browser to the IdP, which parks the request.
const toLogin = await browse(await sp.getAuthorizeUrlAsync("relay-123", undefined, {}));
const login = new URL(toLogin.headers.get("location") ?? "", base);
const callbackURL = login.searchParams.get("callbackURL") ?? "";
assert(toLogin.status === 302 && login.pathname === "/sign-in", "AuthnRequest → 302 /sign-in");
assert(callbackURL.startsWith(`${base}/api/auth/saml2/idp/resume?rid=`), "callbackURL is the resume link");

// 2. Sign up (as the sign-in page does), verify (shortcut, see above), sign in.
const signUp = await postJSON("/sign-up/email", { email, password, name: "Ada Lovelace", callbackURL });
assert(signUp.ok, `sign-up ${email} (${signUp.status})`);
const db = new DatabaseSync(process.env.DATABASE_PATH || "./data.db");
const changed = db.prepare('UPDATE "user" SET "emailVerified" = 1 WHERE "email" = ?').run(email).changes;
db.close();
assert(changed === 1, "email marked verified in data.db (test shortcut)");
const signIn = await postJSON("/sign-in/email", { email, password });
assert(signIn.ok, `sign-in (${signIn.status})`);

// 3. Follow callbackURL: the IdP issues a signed Response as an auto-POST form to the ACS.
const resume = await browse(callbackURL);
const html = await resume.text();
const action = unescapeHtml(/<form method="post" action="([^"]*)"/.exec(html)?.[1] ?? "");
const SAMLResponse = unescapeHtml(/name="SAMLResponse" value="([^"]*)"/.exec(html)?.[1] ?? "");
const RelayState = unescapeHtml(/name="RelayState" value="([^"]*)"/.exec(html)?.[1] ?? "");
assert(resume.status === 200 && action === ACS && SAMLResponse !== "", `resume → auto-POST to ${ACS} (${resume.status})`);
assert(RelayState === "relay-123", "RelayState returned unchanged");

// 4. The SP validates it.
const { profile } = await sp.validatePostResponseAsync({ SAMLResponse, RelayState });
assert(profile?.nameID === email, `node-saml accepted the Response: NameID ${profile?.nameID}`);
assert(profile?.issuer === `${base}/api/auth/saml2/idp`, `issuer ${profile?.issuer}`);
assert(profile?.email === email && profile?.firstName === "Ada" && profile?.lastName === "Lovelace", "attributes email, firstName, lastName");
console.log("sso: signed in to the test SP");

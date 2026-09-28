// Smoke test for a running example (`next start` or `next dev`), used by CI:
//  1. the metadata is an EntityDescriptor for this IdP, valid against the SAML schema (`inspect`);
//  2. an SP-initiated AuthnRequest redirects a signed-out browser to /sign-in?callbackURL=…resume;
//  3. the plugin's 15 security checks (`smoke`).
// Usage: node scripts/smoke.mjs [base URL] (default http://localhost:3000). The SP defaults to
// the test SP that scripts/dev-keys.mjs registers; override with SMOKE_SP and SMOKE_ACS.
import { execFileSync } from "node:child_process";
import { join } from "node:path";

const base = (process.argv[2] ?? "http://localhost:3000").replace(/\/+$/, "");
const sp = process.env.SMOKE_SP ?? "http://localhost:4000/saml/metadata";
const acs = process.env.SMOKE_ACS ?? "http://localhost:4000/saml/acs";
const cli = join("node_modules", "better-auth-saml-idp", "dist", "cli", "bin.js");
const http = base.startsWith("http://") ? ["--allow-http"] : [];

function run(args, stdio = "inherit") {
  try {
    return execFileSync(process.execPath, [cli, ...args, ...http], { stdio, encoding: "utf8" });
  } catch {
    console.error(`FAIL better-auth-saml-idp ${args[0]} (exit code 1 means a check failed)`);
    process.exit(1);
  }
}
function assert(ok, message) {
  if (!ok) {
    console.error(`FAIL ${message}`);
    process.exit(1);
  }
  console.log(`ok   ${message}`);
}

// Wait for the server (CI starts it in the background just before).
const metadataURL = `${base}/api/auth/saml2/idp/metadata`;
let res;
for (let i = 0; i < 60; i++) {
  res = await fetch(metadataURL).catch(() => undefined);
  if (res) break;
  await new Promise((r) => setTimeout(r, 1000));
}
assert(res?.status === 200, `GET ${metadataURL} → 200`);
const xml = await res.text();
assert(/^(<\?xml[^>]*>\s*)?<(\w+:)?EntityDescriptor\b/.test(xml), "metadata is an EntityDescriptor");
assert(xml.includes(`entityID="${base}/api/auth/saml2/idp"`), `entity ID is ${base}/api/auth/saml2/idp`);
assert(xml.includes(`Location="${base}/api/auth/saml2/idp/sso"`), "SSO URL advertised");
run(["inspect", base]);

// SP-initiated SSO, signed out: the IdP parks the request and sends the browser to loginPage.
const url = run(["request", base, "--sp", sp, "--acs", acs], ["ignore", "pipe", "ignore"]).trim();
const sso = await fetch(url, { redirect: "manual" });
const location = new URL(sso.headers.get("location") ?? "", base);
const callbackURL = location.searchParams.get("callbackURL") ?? "";
assert(sso.status === 302 && location.pathname === "/sign-in", `AuthnRequest → 302 /sign-in (got ${sso.status} ${location.pathname})`);
assert(callbackURL.startsWith(`${base}/api/auth/saml2/idp/resume?rid=`), `callbackURL is the resume link (${callbackURL})`);
const page = await fetch(location);
assert(page.status === 200, "the sign-in page renders");

run(["smoke", base, "--sp", sp, "--acs", acs]);
console.log("smoke: all checks passed");

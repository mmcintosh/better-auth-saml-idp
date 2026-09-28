// Runtime smoke test (roadmap: Bun and Deno): the built package (dist/, what users install) on
// the runtime running this file. Plain JavaScript, no test framework, so every runtime runs it
// as-is: `node`, `bun` and `deno run -A` on test/runtimes/smoke.mjs, after `pnpm build`.
//
// It generates a key with the package's own CLI, starts Better Auth with the plugin on the memory
// adapter, and checks the metadata and a full SP-initiated sign-in, verifying the Response's
// signature with the certificate. It exits non-zero on the first failure.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { SignedXml } from "xml-crypto";
import { samlIdp } from "../../dist/index.js";

const runtime = typeof Bun !== "undefined" ? `bun ${Bun.version}` : typeof Deno !== "undefined" ? `deno ${Deno.version.deno}` : `node ${process.version}`;
const BASE = "https://idp.smoke.test";
const SP = { id: "app", entityId: "https://app.smoke.test/sp", acsUrls: ["https://app.smoke.test/acs"] };
const check = (ok, what) => {
  if (!ok) throw new Error(`[${runtime}] ${what}`);
  console.log(`ok  ${what}`);
};

// 1. A key and certificate from the package's CLI, run by this same runtime.
const dir = mkdtempSync(join(tmpdir(), "saml-smoke-"));
try {
  execFileSync(process.execPath, [...(typeof Deno !== "undefined" ? ["run", "-A"] : []), "dist/cli/bin.js", "keygen", "--cert-out", join(dir, "idp.crt"), "--key-out", join(dir, "idp.key"), "--bits", "2048"], { stdio: "pipe" });
  const certificate = readFileSync(join(dir, "idp.crt"), "utf8");
  const privateKey = readFileSync(join(dir, "idp.key"), "utf8");
  check(certificate.includes("BEGIN CERTIFICATE") && privateKey.includes("PRIVATE KEY"), "CLI keygen");

  // 2. Better Auth with the plugin.
  const db = { user: [], session: [], account: [], verification: [], samlIdpSeenRequest: [] };
  const auth = betterAuth({
    baseURL: BASE,
    secret: "smoke-secret-that-is-at-least-32-characters-long",
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    telemetry: { enabled: false },
    plugins: [samlIdp({ entityId: `${BASE}/api/auth/saml2/idp`, loginPage: "/sign-in", signing: { privateKey, certificate }, serviceProviders: [{ ...SP, attributes: { email: "email" } }] })],
  });

  const cookies = new Map();
  const call = async (path, init = {}) => {
    const res = await auth.handler(
      new Request(path.startsWith("http") ? path : `${BASE}${path}`, {
        ...init,
        redirect: "manual",
        headers: { origin: BASE, cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "), ...(init.headers ?? {}) },
      }),
    );
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [kv] = c.split(";");
      const i = kv.indexOf("=");
      cookies.set(kv.slice(0, i), kv.slice(i + 1));
    }
    return res;
  };

  // 3. Metadata.
  const metadata = await (await call("/api/auth/saml2/idp/metadata")).text();
  check(metadata.includes("EntityDescriptor") && metadata.includes(`${BASE}/api/auth/saml2/idp/sso`), "metadata");

  // 4. A verified user.
  const email = `smoke-${Date.now()}@example.com`;
  const signUp = await call("/api/auth/sign-up/email", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password: "correct-horse-battery", name: "Smoke" }) });
  check(signUp.status === 200, "sign-up");
  db.user.find((u) => u.email === email).emailVerified = true;

  // 5. SP-initiated sign-in over HTTP-Redirect.
  const id = `_smoke${Date.now()}`;
  const request = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${BASE}/api/auth/saml2/idp/sso" AssertionConsumerServiceURL="${SP.acsUrls[0]}"><saml:Issuer>${SP.entityId}</saml:Issuer></samlp:AuthnRequest>`;
  const res = await call(`/api/auth/saml2/idp/sso?SAMLRequest=${encodeURIComponent(deflateRawSync(request).toString("base64"))}`);
  const page = await res.text();
  const b64 = /name="SAMLResponse" value="([^"]+)"/.exec(page)?.[1];
  check(res.status === 200 && b64, "SSO answered with an auto-POST form");
  const xml = Buffer.from(b64, "base64").toString("utf8");
  check(xml.includes(`InResponseTo="${id}"`) && xml.includes(`>${email}</saml:NameID>`), "Response for this request and user");

  // 6. The Response signature verifies with the certificate.
  const sig = new SignedXml({ publicCert: certificate });
  const node = /<ds:Signature[\s\S]*?<\/ds:Signature>/.exec(xml)?.[0];
  sig.loadSignature(node);
  check(sig.checkSignature(xml), "Response signature verifies");

  console.log(`smoke passed on ${runtime}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

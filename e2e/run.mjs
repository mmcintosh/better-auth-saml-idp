#!/usr/bin/env node
// Phase 3 e2e: two independent, widely used SAML SPs (Keycloak 26 identity brokering and
// SimpleSAMLphp 2.5) sign users in through the example IdP running on workerd (`wrangler dev`,
// local D1). A scripted browser follows redirects and auto-submits SAML forms like a real one.
//
//   pnpm e2e            # needs docker + openssl; ports 8787, 8080, 8081 free
//   KEEP=1 pnpm e2e     # leave the containers and IdP running afterwards
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const example = join(here, "../examples/workers-hono");
const IDP = "http://localhost:8787";
const IDP_ENTITY = `${IDP}/api/auth/saml2/idp`;
const KC = "http://localhost:8080";
const SSP = "http://localhost:8081";

const SERVICE_PROVIDERS = [
  { id: "keycloak", entityId: `${KC}/realms/e2e`, acsUrls: [`${KC}/realms/e2e/broker/our-idp/endpoint`] },
  {
    id: "simplesamlphp",
    entityId: `${SSP}/simplesaml/module.php/saml/sp/metadata/default-sp`,
    acsUrls: [`${SSP}/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp`],
  },
];

const results = [];
const log = (...a) => console.log("[e2e]", ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, { stdio: "inherit", ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed (${r.status})`);
};

// `docker compose` (v2 plugin) if available, else the standalone `docker-compose`.
const compose = spawnSync("docker", ["compose", "version"], { stdio: "ignore" }).status === 0
  ? ["docker", ["compose"]]
  : ["docker-compose", []];
const dockerCompose = (args, opts) => run(compose[0], [...compose[1], "-f", join(here, "docker-compose.yml"), ...args], opts);

async function portFree(port) {
  try {
    await fetch(`http://localhost:${port}/`, { redirect: "manual", signal: AbortSignal.timeout(1000) });
    return false;
  } catch {
    return true;
  }
}

async function waitFor(url, label, timeoutMs = 180_000) {
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await fetch(url, { redirect: "manual" });
      if (r.status < 500) return;
    } catch {}
    if (Date.now() - t0 > timeoutMs) throw new Error(`timed out waiting for ${label} (${url})`);
    await sleep(1000);
  }
}

/** A tiny browser: cookie jar per origin, manual redirects, auto-submits SAML POST forms. */
class Browser {
  jars = new Map();
  jar(origin) {
    if (!this.jars.has(origin)) this.jars.set(origin, new Map());
    return this.jars.get(origin);
  }
  async request(url, init = {}) {
    const u = new URL(url);
    const jar = this.jar(u.origin);
    const headers = new Headers(init.headers);
    if (jar.size) headers.set("cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
    const res = await fetch(u, { ...init, headers, redirect: "manual" });
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(";");
      const i = pair.indexOf("=");
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1).trim();
      const expired = attrs.some((a) => /^\s*max-age=0/i.test(a) || /^\s*expires=Thu, 01 Jan 1970/i.test(a));
      if (expired || value === "") jar.delete(name);
      else jar.set(name, value);
    }
    return res;
  }
  /** Follow redirects and SAML auto-POST pages until `stop(url, res)` or a non-SAML page. */
  async navigate(url, { stop = () => false, init } = {}) {
    let res = await this.request(url, init);
    for (let hops = 0; hops < 25; hops++) {
      if (stop(url, res)) return { url, res };
      if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
        url = new URL(res.headers.get("location"), url).href;
        res = await this.request(url);
        continue;
      }
      if (res.status === 200 && (res.headers.get("content-type") ?? "").includes("html")) {
        const html = await res.clone().text();
        const form = autoPostForm(html);
        if (form) {
          url = new URL(form.action, url).href;
          res = await this.request(url, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams(form.fields).toString(),
          });
          continue;
        }
      }
      return { url, res };
    }
    throw new Error("too many hops");
  }
}

const decode = (s) => s.replace(/&(amp|lt|gt|quot|#39|apos|#x2F|#x3D);/g, (_, e) => ({ amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'", apos: "'", "#x2F": "/", "#x3D": "=" })[e]);

function autoPostForm(html) {
  if (!/name="(SAMLResponse|SAMLRequest)"/.test(html)) return null;
  const action = /<form[^>]*action="([^"]+)"/i.exec(html)?.[1];
  if (!action) return null;
  const fields = {};
  for (const m of html.matchAll(/<input[^>]*type="hidden"[^>]*>/gi)) {
    const name = /name="([^"]+)"/.exec(m[0])?.[1];
    const value = /value="([^"]*)"/.exec(m[0])?.[1];
    if (name) fields[decode(name)] = decode(value ?? "");
  }
  return { action: decode(action), fields };
}

/** Our example IdP's login: create the account through the API, then continue to callbackURL. */
async function idpLogin(browser, signInUrl, email, { create }) {
  const callback = new URL(signInUrl).searchParams.get("callbackURL");
  if (!callback) throw new Error(`expected the IdP sign-in page, got ${signInUrl}`);
  const res = await browser.request(`${IDP}/api/auth/${create ? "sign-up" : "sign-in"}/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: IDP },
    body: JSON.stringify({ email, password: "correct-horse-battery", name: "Erin E2E" }),
  });
  if (!res.ok) throw new Error(`IdP ${create ? "sign-up" : "sign-in"} failed: ${res.status} ${await res.text()}`);
  return callback;
}

async function main() {
  for (const port of [8787, 8080, 8081])
    if (!(await portFree(port))) throw new Error(`port ${port} is already in use; stop whatever is listening there first`);

  // 1. IdP: example app on workerd with both SPs registered.
  if (!existsSync(join(example, ".dev.vars"))) run("sh", ["scripts/dev-keys.sh"], { cwd: example });
  run("npx", ["wrangler", "d1", "migrations", "apply", "saml-idp-example", "--local"], { cwd: example, stdio: "ignore" });
  const idp = spawn(
    "npx",
    ["wrangler", "dev", "--ip", "0.0.0.0", "--port", "8787", "--var", `SAML_SERVICE_PROVIDERS:${JSON.stringify(SERVICE_PROVIDERS)}`],
    { cwd: example, stdio: ["ignore", "ignore", "inherit"], detached: true },
  );
  idp.unref();
  const cleanup = () => {
    if (process.env.KEEP) return;
    try { process.kill(-idp.pid); } catch {}
    try { dockerCompose(["down", "-v"], { stdio: "ignore" }); } catch {}
  };
  process.on("exit", cleanup);
  await waitFor(`${IDP}/api/auth/saml2/idp/metadata`, "IdP");
  const metadata = await (await fetch(`${IDP}/api/auth/saml2/idp/metadata`)).text();
  const cert = /<ds:X509Certificate>([^<]+)</.exec(metadata)[1];
  log("IdP up:", IDP_ENTITY);

  // 2. SimpleSAMLphp needs our IdP in its remote-IdP metadata.
  mkdirSync(join(here, ".generated"), { recursive: true });
  writeFileSync(
    join(here, ".generated/saml20-idp-remote.php"),
    `<?php\n$metadata['${IDP_ENTITY}'] = [\n  'entityid' => '${IDP_ENTITY}',\n  'SingleSignOnService' => [['Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'Location' => '${IDP}/api/auth/saml2/idp/sso']],\n  'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',\n  'certData' => '${cert}',\n  'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',\n];\n`,
  );

  // 3. Third-party SPs.
  dockerCompose(["up", "-d", "--force-recreate"]);
  await waitFor(`${KC}/realms/master`, "Keycloak", 240_000);
  await waitFor(`${SSP}/simplesaml/`, "SimpleSAMLphp");
  log("SPs up");

  await keycloak(cert);
  await simplesamlphp();

  console.log("\n==== e2e results ====");
  for (const r of results) console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  — ${r.detail}` : ""}`);
  const failed = results.filter((r) => !r.ok).length;
  process.exit(failed ? 1 : 0); // runs the exit cleanup (IdP + containers) unless KEEP=1
}

async function check(name, fn) {
  try {
    const detail = await fn();
    results.push({ name, ok: true, detail });
  } catch (e) {
    results.push({ name, ok: false, detail: e.message });
  }
}

async function keycloak(cert) {
  const tok = await (
    await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
      method: "POST",
      body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: "admin", password: "admin" }),
    })
  ).json();
  const admin = (path, init = {}) =>
    fetch(`${KC}/admin${path}`, {
      ...init,
      headers: { authorization: `Bearer ${tok.access_token}`, "content-type": "application/json", ...(init.headers ?? {}) },
    });
  await admin("/realms/e2e", { method: "DELETE" });
  let r = await admin("/realms", { method: "POST", body: JSON.stringify({ realm: "e2e", enabled: true }) });
  if (!r.ok) throw new Error(`create realm: ${r.status} ${await r.text()}`);
  r = await admin("/realms/e2e/identity-provider/instances", {
    method: "POST",
    body: JSON.stringify({
      alias: "our-idp",
      providerId: "saml",
      enabled: true,
      trustEmail: true,
      config: {
        entityId: `${KC}/realms/e2e`,
        idpEntityId: IDP_ENTITY,
        singleSignOnServiceUrl: `${IDP}/api/auth/saml2/idp/sso`,
        nameIDPolicyFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        principalType: "SUBJECT",
        postBindingResponse: "true",
        postBindingAuthnRequest: "false",
        validateSignature: "true",
        signingCertificate: cert,
        wantAssertionsSigned: "true",
        wantAuthnRequestsSigned: "false",
        syncMode: "IMPORT",
        allowedClockSkew: "30",
      },
    }),
  });
  if (!r.ok) throw new Error(`create IdP: ${r.status} ${await r.text()}`);
  for (const [attr, userAttr] of [["email", "email"], ["firstName", "firstName"], ["lastName", "lastName"]]) {
    await admin("/realms/e2e/identity-provider/instances/our-idp/mappers", {
      method: "POST",
      body: JSON.stringify({
        name: attr,
        identityProviderAlias: "our-idp",
        identityProviderMapper: "saml-user-attribute-idp-mapper",
        config: { "attribute.name": attr, "user.attribute": userAttr, syncMode: "INHERIT" },
      }),
    });
  }
  log("Keycloak realm e2e configured (SAML broker → our IdP, signatures required)");

  const email = `kc-${Date.now()}@example.com`;
  await check("Keycloak 26.4 identity broker: new user signs in through our IdP", async () => {
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const redirect = `${KC}/realms/e2e/account/`;
    const auth = new URL(`${KC}/realms/e2e/protocol/openid-connect/auth`);
    Object.entries({
      client_id: "account-console",
      redirect_uri: redirect,
      response_type: "code",
      scope: "openid",
      kc_idp_hint: "our-idp",
      state: randomBytes(8).toString("hex"),
      nonce: randomBytes(8).toString("hex"),
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).forEach(([k, v]) => auth.searchParams.set(k, v));

    const b = new Browser();
    const toIdp = await b.navigate(auth.href, { stop: (u) => u.startsWith(`${IDP}/sign-in`) });
    if (!toIdp.url.startsWith(`${IDP}/sign-in`)) throw new Error(`did not reach IdP sign-in; ended at ${toIdp.url} (${toIdp.res.status})`);
    const callback = await idpLogin(b, toIdp.url, email, { create: true });
    const end = await b.navigate(callback, { stop: (u) => u.startsWith(redirect) });
    const final = new URL(end.url);
    if (!end.url.startsWith(redirect) || !final.searchParams.get("code")) {
      const body = (await end.res.text()).replace(/\s+/g, " ").slice(0, 300);
      throw new Error(`no authorization code; ended at ${end.url} (${end.res.status}): ${body}`);
    }
    const users = await (await admin(`/realms/e2e/users?email=${encodeURIComponent(email)}&exact=true`)).json();
    if (users.length !== 1) throw new Error(`expected 1 Keycloak user for ${email}, got ${users.length}`);
    const links = await (await admin(`/realms/e2e/users/${users[0].id}/federated-identity`)).json();
    const link = links.find((l) => l.identityProvider === "our-idp");
    if (!link || link.userName !== email) throw new Error(`federated identity missing: ${JSON.stringify(links)}`);
    return `user ${email} created in Keycloak, linked to our-idp as ${link.userName}; first/last name ${users[0].firstName}/${users[0].lastName}`;
  });
}

async function simplesamlphp() {
  const email = `ssp-${Date.now()}@example.com`;
  await check("SimpleSAMLphp 2.5 SP: new user signs in through our IdP", async () => {
    const b = new Browser();
    const toIdp = await b.navigate(`${SSP}/whoami.php`, { stop: (u) => u.startsWith(`${IDP}/sign-in`) });
    if (!toIdp.url.startsWith(`${IDP}/sign-in`)) throw new Error(`did not reach IdP sign-in; ended at ${toIdp.url} (${toIdp.res.status})`);
    const callback = await idpLogin(b, toIdp.url, email, { create: true });
    const end = await b.navigate(callback, { stop: (u) => u.startsWith(`${SSP}/whoami.php`) && false });
    const text = await end.res.text();
    let who;
    try {
      who = JSON.parse(text);
    } catch {
      throw new Error(`expected whoami JSON; ended at ${end.url} (${end.res.status}): ${text.replace(/\s+/g, " ").slice(0, 400)}`);
    }
    if (who.nameId !== email) throw new Error(`NameID ${who.nameId} != ${email}`);
    if (who.idp !== IDP_ENTITY) throw new Error(`IdP ${who.idp}`);
    if (who.attributes?.email?.[0] !== email) throw new Error(`attributes ${JSON.stringify(who.attributes)}`);
    return `NameID ${who.nameId}; attributes ${Object.keys(who.attributes).join(", ")}`;
  });

  await check("SimpleSAMLphp 2.5 SP: existing IdP session → immediate sign-in (no login page)", async () => {
    const b = new Browser();
    // Sign in at the IdP first, then visit the SP: the IdP must answer without the login page.
    const r = await b.request(`${IDP}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: IDP },
      body: JSON.stringify({ email, password: "correct-horse-battery" }),
    });
    if (!r.ok) throw new Error(`IdP sign-in ${r.status}`);
    let sawLogin = false;
    const end = await b.navigate(`${SSP}/whoami.php`, { stop: (u) => ((sawLogin ||= u.startsWith(`${IDP}/sign-in`)), false) });
    if (sawLogin) throw new Error("was sent to the IdP login page despite an IdP session");
    const who = JSON.parse(await end.res.text());
    if (who.nameId !== email) throw new Error(`NameID ${who.nameId}`);
    return `NameID ${who.nameId}`;
  });
}

main().catch((e) => {
  console.error("[e2e] fatal:", e);
  process.exit(1);
});

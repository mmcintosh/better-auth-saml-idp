import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { TLS } from "./tls.mjs";
import { E2E_DIR, EXAMPLE_DIR, GENERATED, IDP, IDP_ENTITY, IDP_SSO, PORTS, SERVICE_PROVIDERS, SSP } from "./config.mjs";

const STATE_DIR = join(GENERATED, "wrangler-state");

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "inherit", ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed (${r.status})`);
}

// `docker compose` (v2 plugin) if available, else the standalone `docker-compose`.
const composeCmd =
  spawnSync("docker", ["compose", "version"], { stdio: "ignore" }).status === 0 ? ["docker", ["compose"]] : ["docker-compose", []];
export const compose = (args, opts) =>
  run(composeCmd[0], [...composeCmd[1], "-f", join(E2E_DIR, "docker-compose.yml"), ...args], opts);

/** Requests go to 127.0.0.1 with the *.test Host header, as Chromium's resolver rule does. */
export async function hostFetch(url, init) {
  const u = new URL(url);
  const local = `${u.protocol}//127.0.0.1:${u.port}${u.pathname}${u.search}`; // cert has IP:127.0.0.1
  return fetch(local, { ...init, headers: { ...(init?.headers ?? {}), host: u.host } });
}

export async function assertPortsFree() {
  for (const port of PORTS) {
    const busy = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1000) }).catch((e) =>
      e?.cause?.code === "ECONNREFUSED" ? Promise.reject(e) : true, // TLS/HTTP mismatch still means "listening"
    ).then(
      () => true,
      () => false,
    );
    if (busy) throw new Error(`port ${port} is already in use; stop whatever is listening there first`);
  }
}

export async function waitFor(url, label, timeoutMs = 240_000) {
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await hostFetch(url, { redirect: "manual" });
      if (r.status < 500) return;
    } catch {}
    if (Date.now() - t0 > timeoutMs) throw new Error(`timed out waiting for ${label} (${url})`);
    await sleep(1000);
  }
}

/** examples/workers-hono on workerd (`wrangler dev`, local D1), with the e2e SPs and dev mailbox. */
export async function startIdp() {
  if (!existsSync(join(EXAMPLE_DIR, ".dev.vars"))) run("sh", ["scripts/dev-keys.sh"], { cwd: EXAMPLE_DIR });
  // A fresh local D1 for every run, separate from the developer's `pnpm dev` state.
  rmSync(STATE_DIR, { recursive: true, force: true });
  run("npx", ["wrangler", "d1", "migrations", "apply", "saml-idp-example", "--local", "--persist-to", STATE_DIR], {
    cwd: EXAMPLE_DIR,
    stdio: "ignore",
  });
  const child = spawn(
    "npx",
    [
      "wrangler", "dev", "--ip", "0.0.0.0", "--port", "8787",
      "--local-protocol", "https", "--https-key-path", TLS.key, "--https-cert-path", TLS.cert,
      "--var", `SAML_SERVICE_PROVIDERS:${JSON.stringify(SERVICE_PROVIDERS)}`,
      "--var", "DEV_MAILBOX:true",
      "--persist-to", STATE_DIR,
    ],
    { cwd: EXAMPLE_DIR, stdio: ["ignore", "ignore", "inherit"], detached: true, env: { ...process.env, WRANGLER_SEND_METRICS: "false" } },
  );
  child.unref();
  await waitFor(`${IDP}/api/auth/saml2/idp/metadata`, "IdP");
  const metadata = await (await hostFetch(`${IDP}/api/auth/saml2/idp/metadata`)).text();
  const cert = /<ds:X509Certificate>([^<]+)</.exec(metadata)[1];
  return { pid: child.pid, cert, metadata };
}

export function stopProcessGroup(pid) {
  try {
    process.kill(-pid);
  } catch {}
}

/** wrangler's workerd can outlive its process group: stop whatever still listens on `port`. */
export function stopListener(port) {
  const out = spawnSync("ss", ["-ltnpH", "sport", "=", `:${port}`], { encoding: "utf8" }).stdout ?? "";
  for (const m of out.matchAll(/pid=(\d+)/g)) {
    try {
      process.kill(Number(m[1]));
    } catch {}
  }
}

/** SimpleSAMLphp needs our IdP in its remote-IdP metadata. */
export function writeSimpleSamlphpMetadata(cert) {
  mkdirSync(GENERATED, { recursive: true });
  writeFileSync(
    join(GENERATED, "saml20-idp-remote.php"),
    `<?php\n$metadata['${IDP_ENTITY}'] = [\n  'entityid' => '${IDP_ENTITY}',\n  'SingleSignOnService' => [['Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'Location' => '${IDP_SSO}']],\n  'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',\n  'certData' => '${cert}',\n  'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',\n];\n`,
  );
  void SSP;
}

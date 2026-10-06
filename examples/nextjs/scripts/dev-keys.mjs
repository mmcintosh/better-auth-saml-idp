// Writes .env.local (gitignored) for local development: a throwaway IdP key pair from the
// plugin's CLI (`keygen`), a BETTER_AUTH_SECRET, BETTER_AUTH_URL and a test SP.
// For production, create the key pair once, keep it in your secret store, and set the same
// variables there. Usage: node scripts/dev-keys.mjs [--force] [--url http://localhost:3000]
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const force = args.includes("--force");
const urlIndex = args.indexOf("--url");
const baseURL = urlIndex >= 0 ? args[urlIndex + 1] : "http://localhost:3000";

// The plugin's CLI, from the installed package (a workspace link in this repo).
const cli = join("node_modules", "better-auth-saml-idp", "dist", "cli", "bin.js");
const dir = mkdtempSync(join(tmpdir(), "saml-idp-keys-"));
try {
  const cert = join(dir, "idp.crt");
  const key = join(dir, "idp.key");
  try {
    execFileSync(process.execPath, [cli, "keygen", "--cn", "better-auth-saml-idp nextjs dev", "--cert-out", cert, "--key-out", key], { stdio: "pipe" });
  } catch (error) {
    // keygen's report is on stderr; only worth showing when it failed.
    console.error(String(error.stderr ?? error));
    rmSync(dir, { recursive: true, force: true });
    process.exit(1);
  }
  // A test SP for `smoke` and scripts/sso.mjs. Replace or extend it with your real SPs.
  const sps = [{ id: "test-sp", entityId: "http://localhost:4000/saml/metadata", acsUrls: ["http://localhost:4000/saml/acs"] }];
  const lines = [
    `BETTER_AUTH_URL=${baseURL}`,
    `BETTER_AUTH_SECRET=${randomBytes(32).toString("base64")}`,
    `SAML_IDP_PRIVATE_KEY="${readFileSync(key, "utf8").trim()}"`,
    `SAML_IDP_CERT="${readFileSync(cert, "utf8").trim()}"`,
    `SAML_SERVICE_PROVIDERS='${JSON.stringify(sps)}'`,
  ];
  // Without --force, "wx" refuses an existing .env.local in the same step that writes it (no
  // separate check, so nothing can appear in between).
  try {
    writeFileSync(".env.local", `${lines.join("\n")}\n`, { mode: 0o600, flag: force ? "w" : "wx" });
    console.log("wrote .env.local (dev-only key pair, secret, test SP)");
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    console.error(".env.local exists; pass --force to replace it (the old key pair is lost)");
    process.exitCode = 1;
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}

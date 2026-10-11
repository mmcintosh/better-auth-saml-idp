// Writes .dev.vars (gitignored) for local development: a throwaway IdP key pair from the plugin's
// CLI (`keygen`), a BETTER_AUTH_SECRET and a test SP. `wrangler dev` and `pnpm db:migrate` read it.
// For production, create the key pair once and set the same names as Worker secrets (README.md).
// Usage: node scripts/dev-keys.mjs [--force]
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const force = process.argv.includes("--force");

// The plugin's CLI, from the installed package (a workspace link in this repo).
const cli = join("node_modules", "better-auth-saml-idp", "dist", "cli", "bin.js");
const dir = mkdtempSync(join(tmpdir(), "saml-idp-keys-"));
try {
  const cert = join(dir, "idp.crt");
  const key = join(dir, "idp.key");
  try {
    execFileSync(process.execPath, [cli, "keygen", "--cn", "better-auth-saml-idp workers-neon dev", "--cert-out", cert, "--key-out", key], { stdio: "pipe" });
  } catch (error) {
    // keygen's report is on stderr; only worth showing when it failed.
    console.error(String(error.stderr ?? error));
    rmSync(dir, { recursive: true, force: true });
    process.exit(1);
  }
  // A test SP for `pnpm smoke` and `pnpm sso`. Replace or extend it with your real SPs.
  const sps = [{ id: "test-sp", entityId: "http://localhost:4000/saml/metadata", acsUrls: ["http://localhost:4000/saml/acs"] }];
  const lines = [
    `BETTER_AUTH_SECRET=${randomBytes(32).toString("base64")}`,
    `SAML_IDP_PRIVATE_KEY="${readFileSync(key, "utf8").trim()}"`,
    `SAML_IDP_CERT="${readFileSync(cert, "utf8").trim()}"`,
    `SAML_SERVICE_PROVIDERS='${JSON.stringify(sps)}'`,
    // Prints verification links to the console, and only on a localhost URL.
    "DEV_PRINT_VERIFICATION_LINKS=true",
  ];
  // Without --force, "wx" refuses an existing .dev.vars in the same step that writes it.
  try {
    writeFileSync(".dev.vars", `${lines.join("\n")}\n`, { mode: 0o600, flag: force ? "w" : "wx" });
    console.log("wrote .dev.vars (dev-only key pair, secret, test SP)");
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    console.error(".dev.vars exists; pass --force to replace it (the old key pair is lost)");
    process.exitCode = 1;
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}

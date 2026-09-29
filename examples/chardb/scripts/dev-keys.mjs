// Writes .dev.vars (gitignored) for local development: a throwaway IdP key pair from
// better-auth-saml-idp's own `keygen`, the local origin as BETTER_AUTH_URL, the dev mailbox, and
// the registry admin (SAML_REGISTRY_ADMINS, default admin@example.test).
// Production: create a key pair yourself and `wrangler secret put` each value (README).
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "saml-dev-keys-"));
try {
  const cli = Bun.spawnSync(["node", "node_modules/better-auth-saml-idp/dist/cli/bin.js", "keygen", "--cn", "chardb-saml-idp dev", "--key-out", join(dir, "key.pem"), "--cert-out", join(dir, "cert.pem")], { stderr: "pipe" });
  if (cli.exitCode !== 0) throw new Error("keygen failed: " + cli.stderr.toString());
  const esc = (file) => readFileSync(join(dir, file), "utf8").trim().replace(/\n/g, "\\n");
  // The web app's origin: Vite serves the UI and passes /api, /sign-in and /demo-sp to the Worker,
  // so the whole browser flow (and the IdP's entity IDs) stay on one origin.
  const origin = process.env.CHARDB_DEV_WEB_URL ?? "http://127.0.0.1:5173";
  writeFileSync(
    ".dev.vars",
    `BETTER_AUTH_URL="${origin}"\nSAML_IDP_PRIVATE_KEY="${esc("key.pem")}"\nSAML_IDP_CERT="${esc("cert.pem")}"\n` +
      `SAML_REGISTRY_ADMINS="${process.env.SAML_REGISTRY_ADMINS ?? "admin@example.test"}"\nDEV_MAILBOX="true"\n`,
    { mode: 0o600 },
  );
  console.log("wrote .dev.vars (a dev-only key pair; BETTER_AUTH_URL=" + origin + "; DEV_MAILBOX on)");
} finally {
  rmSync(dir, { recursive: true, force: true });
}

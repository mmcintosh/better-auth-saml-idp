import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig } from "vitest/config";

// A throwaway IdP key pair per run, from better-auth-saml-idp's own keygen: never committed.
function testKeys() {
  const dir = mkdtempSync(join(tmpdir(), "saml-test-keys-"));
  try {
    execFileSync("node", ["node_modules/better-auth-saml-idp/dist/cli/bin.js", "keygen", "--cn", "chardb-saml-idp test", "--bits", "2048", "--key-out", join(dir, "key.pem"), "--cert-out", join(dir, "cert.pem")], { stdio: "pipe" });
    return { key: readFileSync(join(dir, "key.pem"), "utf8"), cert: readFileSync(join(dir, "cert.pem"), "utf8") };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const keys = testKeys();

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          CDB_ADMIN_TOKEN: "chardb-vitest-admin",
          BETTER_AUTH_SECRET: "chardb-vitest-auth-secret-at-least-32-characters",
          BETTER_AUTH_URL: "https://chardb.test",
          SAML_IDP_PRIVATE_KEY: keys.key,
          SAML_IDP_CERT: keys.cert,
          SAML_REGISTRY_ADMINS: "admin@chardb.test",
          DEV_MAILBOX: "true",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 60_000,
  },
});

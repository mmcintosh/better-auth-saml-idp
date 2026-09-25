import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// The first libxml2 schema compile per isolate takes tens of ms, more under load; vite also
// transforms large files on first import. Generous timeout, no retries.
const testTimeout = 60_000;
const globalSetup = ["test/support/global-setup.ts"];

export default defineConfig(async () => {
  const migrations = await readD1Migrations("test/support/d1/migrations");
  return {
    test: {
      projects: [
        { test: { name: "node", testTimeout, globalSetup, include: ["test/**/*.test.ts"], environment: "node" } },
        {
          plugins: [
            cloudflareTest({
              wrangler: { configPath: "./wrangler.jsonc" },
              miniflare: { bindings: { TEST_MIGRATIONS: migrations } },
            }),
          ],
          test: {
            name: "workerd",
            testTimeout,
            globalSetup,
            setupFiles: ["test/support/d1/apply-migrations.ts"],
            include: ["test/**/*.test.ts"],
          },
        },
      ],
    },
  };
});

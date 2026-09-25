// Run from the repo root: npx vitest run --config wasm-validator/vitest.config.ts
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const globalSetup = [here("../test/support/global-setup.ts")];

export default defineConfig({
  root: here("."),
  test: {
    projects: [
      { test: { name: "node", root: here("."), globalSetup, include: ["test/**/*.test.ts"], environment: "node" } },
      {
        plugins: [cloudflareTest({ wrangler: { configPath: here("./wrangler.jsonc") } })],
        test: { name: "workerd", root: here("."), globalSetup, include: ["test/**/*.test.ts"] },
      },
    ],
  },
});

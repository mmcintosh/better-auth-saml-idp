// Run from the repo root: npx vitest run --config wasm-validator/vitest.config.ts
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-plugin";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const globalSetup = [here("../test/support/global-setup.ts")];

export default defineConfig({
  root: here("."),
  test: {
    // @cloudflare/vitest-plugin 1.4.2 can't read Vitest 5's filesystem module cache (fixed in 1.4.3).
    fsModuleCache: false,
    projects: [
      { test: { name: "node", root: here("."), globalSetup, include: ["test/**/*.test.ts"], environment: "node" } },
      {
        plugins: [cloudflareTest({ wrangler: { configPath: here("./wrangler.jsonc") } })],
        test: { name: "workerd", root: here("."), globalSetup, include: ["test/**/*.test.ts"] },
      },
    ],
  },
});

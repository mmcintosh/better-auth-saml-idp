import { defineConfig } from "@playwright/test";
import { CHROMIUM_ARGS } from "./lib/config.mjs";

export default defineConfig({
  testDir: "./browser",
  globalSetup: "./global-setup.mjs",
  timeout: 90_000,
  workers: 1, // one IdP, one D1, shared SP state
  reporter: [["list"]],
  use: {
    browserName: "chromium",
    launchOptions: { args: CHROMIUM_ARGS },
    ignoreHTTPSErrors: true, // throwaway e2e CA (lib/tls.mjs)
    trace: "retain-on-failure",
  },
});

import { writeFileSync } from "node:fs";
import react from "@astrojs/react";
import { chardb } from "@chardb/core/vite";
import { defineConfig } from "astro/config";

// CharDB's Vite plugin loads src/auth.ts here (to generate clients), and the SAML plugin needs its
// settings when it's built: read them from .dev.vars, as Wrangler does (`bun run keys` writes it).
try {
  process.loadEnvFile(".dev.vars");
} catch {}

function localOrigin(raw, fallback, name) {
  const url = new URL(raw ?? fallback);
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) || url.pathname !== "/")
    throw new Error(`${name} must be a loopback HTTP origin`);
  return url;
}
const worker = localOrigin(process.env.CHARDB_DEV_URL, "http://127.0.0.1:8787", "CHARDB_DEV_URL").origin;
const web = localOrigin(process.env.CHARDB_DEV_WEB_URL, "http://127.0.0.1:4321", "CHARDB_DEV_WEB_URL");

export default defineConfig({
  integrations: [
    react(),
    // Astro empties outDir before building; keep the committed placeholder that keeps public/ in git.
    { name: "keep-public-placeholder", hooks: { "astro:build:done": () => writeFileSync("public/.gitkeep", "") } },
  ],
  // A static site, built into the Worker's assets directory (wrangler.toml [assets]): CharDB's
  // Worker serves the pages and handles /api, /sign-in and /demo-sp itself.
  output: "static",
  outDir: "public",
  publicDir: "static",
  server: { host: web.hostname, port: Number(web.port || 4321) },
  vite: {
    plugins: [chardb()],
    server: {
      strictPort: true,
      // One origin in development: everything the Worker serves is passed to it.
      proxy: {
        "/ws": { target: worker.replace(/^http/, "ws"), ws: true, changeOrigin: true },
        "/_chardb": { target: worker, changeOrigin: true, configure: (proxy) => proxy.on("proxyReq", (r) => r.setHeader("origin", worker)) },
        "/api": worker,
        "/health": worker,
        "/sign-in": worker,
        "/dev": worker,
        "/demo-sp": worker,
      },
    },
  },
});

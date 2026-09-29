import react from "@vitejs/plugin-react";
import { chardb } from "@chardb/core/vite";
import { defineConfig } from "vite";

function localOrigin(raw: string | undefined, fallback: string, name: string): string {
  const url = new URL(raw ?? fallback);
  if (
    url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username || url.password || (url.pathname !== "" && url.pathname !== "/") || url.search || url.hash
  ) {
    throw new Error(name + " must be a loopback HTTP origin");
  }
  return url.origin;
}

const workerOrigin = localOrigin(process.env.CHARDB_DEV_URL, "http://127.0.0.1:8787", "CHARDB_DEV_URL");
const workerSocket = workerOrigin.replace(/^http/, "ws");

export default defineConfig({
  publicDir: false,
  plugins: [
    react(),
    chardb(),
  ],
  build: {
    outDir: "public",
    emptyOutDir: true,
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/ws": { target: workerSocket, ws: true, changeOrigin: true },
      "/_chardb": {
        target: workerOrigin,
        changeOrigin: true,
        configure(proxy) {
          proxy.on("proxyReq", request => request.setHeader("origin", workerOrigin));
        },
      },
      "/api": workerOrigin,
      "/health": workerOrigin,
      "/sign-in": workerOrigin,
      "/dev": workerOrigin,
    },
  },
});

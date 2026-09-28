import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Load the plugin from node_modules instead of bundling it: it reads its XSD validator
  // (wasm/xsd.wasm) from its own package directory at runtime.
  serverExternalPackages: ["better-auth-saml-idp"],
  // Don't let `next dev` write AGENTS.md and CLAUDE.md into the example.
  agentRules: false,
};

export default nextConfig;

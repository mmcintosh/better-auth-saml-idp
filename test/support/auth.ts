import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { samlIdp } from "../../src/index";
import type { SamlIdpOptions } from "../../src/types";
import { baseOptions } from "./config";

export const BASE_URL = "https://auth.test";
export const AUTH_BASE = `${BASE_URL}/api/auth`;

/** A Better Auth instance with the plugin, backed by the in-memory adapter. */
export function createTestAuth(overrides: Partial<SamlIdpOptions> = {}) {
  const db = { user: [], session: [], account: [], verification: [] };
  const auth = betterAuth({
    baseURL: BASE_URL,
    secret: "test-secret-that-is-at-least-32-characters-long",
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    telemetry: { enabled: false },
    plugins: [samlIdp(baseOptions(overrides))],
  });
  return { auth, db };
}

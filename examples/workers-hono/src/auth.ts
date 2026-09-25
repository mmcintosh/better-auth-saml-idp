import { AsyncLocalStorage } from "node:async_hooks";
import { betterAuth } from "better-auth";
import { admin } from "better-auth/plugins";
import { withCloudflare } from "better-auth-cloudflare";
import { samlIdp, type ServiceProviderConfig } from "better-auth-saml-idp";
import { drizzle } from "drizzle-orm/d1";
import { schema } from "./schema";

export interface Env {
  DB: D1Database;
  BETTER_AUTH_SECRET: string;
  SAML_IDP_PRIVATE_KEY: string;
  SAML_IDP_CERT: string;
  /**
   * Optional: extra PEM certificate(s), concatenated, published in metadata during a key
   * rotation (see docs/key-rotation.md). They are advertised, never used to sign.
   */
  SAML_IDP_ADDITIONAL_CERTS?: string;
  /** JSON: [{ "id": "...", "entityId": "...", "acsUrls": ["..."] }] */
  SAML_SERVICE_PROVIDERS: string;
  /** Comma-separated emails allowed to manage stored SPs through the registry API (D-027). */
  SAML_REGISTRY_ADMINS?: string;
  /**
   * DEVELOPMENT ONLY. "true" keeps verification links in memory and serves them at
   * /dev/mailbox instead of sending email. Never set this in production.
   */
  DEV_MAILBOX?: string;
}

/** DEV_MAILBOX: the latest verification link per email address (per isolate). */
export const devMailbox = new Map<string, string>();

type SpJson = Pick<
  ServiceProviderConfig,
  | "id"
  | "entityId"
  | "acsUrls"
  | "nameIdFormat"
  | "requireSignedAuthnRequests"
  | "spCertificate"
  | "allowIdpInitiated"
  | "idpInitiatedRelayState"
  | "allowedRelayStates"
  | "signResponse"
  | "signAssertion"
  | "encryption"
  | "attributes"
  | "metadata"
  | "singleLogoutService"
>;

/** Sent to SPs whose JSON entry has no `attributes` (a declarative map; JSON can set its own). */
const DEFAULT_ATTRIBUTES = {
  email: "email",
  name: "name",
  firstName: { field: "name", part: "first" },
  lastName: { field: "name", part: "last" },
} as const;

// Built once per isolate. Better Auth itself is created per request (to pass that request's
// `cf` geolocation), but the SAML plugin holds the parsed keys and the compiled XSDs.
let plugin: { key: string; value: ReturnType<typeof samlIdp> } | undefined;

function samlPlugin(env: Env, origin: string) {
  const key = `${origin}\n${env.SAML_SERVICE_PROVIDERS}\n${env.SAML_IDP_CERT}\n${env.SAML_IDP_ADDITIONAL_CERTS ?? ""}\n${env.SAML_REGISTRY_ADMINS ?? ""}`;
  const admins = new Set((env.SAML_REGISTRY_ADMINS ?? "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean));
  if (plugin?.key === key) return plugin.value;
  const sps = JSON.parse(env.SAML_SERVICE_PROVIDERS || "[]") as SpJson[];
  const value = samlIdp({
    entityId: `${origin}/api/auth/saml2/idp`,
    loginPage: "/sign-in",
    signing: {
      privateKey: env.SAML_IDP_PRIVATE_KEY,
      certificate: env.SAML_IDP_CERT,
      additionalCertificates: pemBlocks(env.SAML_IDP_ADDITIONAL_CERTS),
    },
    serviceProviders: sps.map((sp) => ({ ...sp, attributes: sp.attributes ?? DEFAULT_ATTRIBUTES })),
    // SPs can also be stored in D1 (migration 0003). The API is only mounted for listed admins,
    // who must have a verified email.
    // Single Logout (migration 0004): SPs with a singleLogoutService in their JSON take part.
    singleLogout: { enabled: true },
    registry: {
      enabled: true,
      canManage: admins.size ? ({ user }) => user.emailVerified === true && admins.has(user.email.toLowerCase()) : undefined,
    },
  });
  plugin = { key, value };
  return value;
}

/** The current request's `cf` geolocation, for the shared auth instance (see getAuth). */
export const requestCf = new AsyncLocalStorage<IncomingRequestCfProperties | Record<string, never>>();

function buildAuth(env: Env, origin: string) {
  return betterAuth({
    baseURL: origin,
    secret: env.BETTER_AUTH_SECRET,
    ...withCloudflare(
      {
        autoDetectIpAddress: true,
        geolocationTracking: true,
        // One auth instance serves every request in this isolate; geolocation is looked up per
        // request (better-auth-cloudflare supports a resolver function for exactly this).
        cf: () => requestCf.getStore() ?? {},
        d1: { db: drizzle(env.DB, { schema }), options: { usePlural: true } },
      },
      {
        // The SAML plugin only asserts verified email addresses, so verification is required.
        emailAndPassword: { enabled: true, requireEmailVerification: true },
        emailVerification: {
          sendOnSignUp: true,
          autoSignInAfterVerification: true,
          sendVerificationEmail: async ({ user, url }) => {
            if (env.DEV_MAILBOX === "true") {
              devMailbox.set(user.email, url);
              return;
            }
            // Production: send `url` to `user.email` with your email provider here.
            console.error("[example] email sending is not configured; set up sendVerificationEmail");
          },
        },
        // ADDENDUM-01: single-use state and rate limits in the database, never KV.
        verification: { storeInDatabase: true },
        rateLimit: { enabled: true, storage: "database" },
        advanced: { database: { validateSchema: true } },
        // Plugins go INSIDE withCloudflare's second argument (a `plugins` key next to the
        // spread would replace the Cloudflare plugin and silently drop its storage checks).
        plugins: [admin(), samlPlugin(env, origin)],
      },
    ),
  });
}

let cached: { env: Env; origin: string; auth: ReturnType<typeof buildAuth> } | undefined;

/**
 * Better Auth, built once per isolate (per env + origin) instead of per request. Building it
 * per request roughly doubled warm CPU per SAML request (DECISIONS.md D-017/D-019).
 */
export function getAuth(env: Env, origin: string) {
  if (cached?.env !== env || cached.origin !== origin) cached = { env, origin, auth: buildAuth(env, origin) };
  return cached.auth;
}

/** SP ids that opted in to IdP-initiated SSO, for the home page's app launcher. */
export function idpInitiatedApps(env: Env): string[] {
  try {
    return (JSON.parse(env.SAML_SERVICE_PROVIDERS || "[]") as SpJson[]).filter((sp) => sp.allowIdpInitiated === true).map((sp) => sp.id);
  } catch {
    return [];
  }
}

/** Split concatenated PEM certificates into individual blocks. */
function pemBlocks(text: string | undefined): string[] {
  return (text ?? "").match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
}

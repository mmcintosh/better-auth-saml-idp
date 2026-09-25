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
  /** JSON: [{ "id": "...", "entityId": "...", "acsUrls": ["..."] }] */
  SAML_SERVICE_PROVIDERS: string;
  /**
   * DEVELOPMENT ONLY. "true" keeps verification links in memory and serves them at
   * /dev/mailbox instead of sending email. Never set this in production.
   */
  DEV_MAILBOX?: string;
}

/** DEV_MAILBOX: the latest verification link per email address (per isolate). */
export const devMailbox = new Map<string, string>();

type SpJson = Pick<ServiceProviderConfig, "id" | "entityId" | "acsUrls" | "nameIdFormat">;

// Built once per isolate. Better Auth itself is created per request (to pass that request's
// `cf` geolocation), but the SAML plugin holds the parsed keys and the compiled XSDs.
let plugin: { key: string; value: ReturnType<typeof samlIdp> } | undefined;

function samlPlugin(env: Env, origin: string) {
  const key = `${origin}\n${env.SAML_SERVICE_PROVIDERS}`;
  if (plugin?.key === key) return plugin.value;
  const sps = JSON.parse(env.SAML_SERVICE_PROVIDERS || "[]") as SpJson[];
  const value = samlIdp({
    entityId: `${origin}/api/auth/saml2/idp`,
    loginPage: "/sign-in",
    // The SAML Bindings spec caps RelayState at 80 bytes, but real SPs send more:
    // Cloudflare Access's RelayState exceeds 80 bytes. 1024 is the plugin's hard cap.
    relayStateMaxBytes: 1024,
    signing: { privateKey: env.SAML_IDP_PRIVATE_KEY, certificate: env.SAML_IDP_CERT },
    serviceProviders: sps.map((sp) => ({
      ...sp,
      attributes: (user) => {
        const [firstName, ...rest] = (user.name ?? "").split(" ");
        return { email: user.email, name: user.name, firstName: firstName ?? "", lastName: rest.join(" ") };
      },
    })),
  });
  plugin = { key, value };
  return value;
}

export function createAuth(env: Env, cf: IncomingRequestCfProperties | Record<string, never>, origin: string) {
  return betterAuth({
    baseURL: origin,
    secret: env.BETTER_AUTH_SECRET,
    ...withCloudflare(
      {
        autoDetectIpAddress: true,
        geolocationTracking: true,
        cf,
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

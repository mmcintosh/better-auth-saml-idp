// Better Auth with the SAML IdP plugin, on Postgres (Neon) through Cloudflare Hyperdrive.
// scripts/migrate.ts imports this file with Node's type stripping, so it has no relative imports
// and only erasable TypeScript.
import { betterAuth } from "better-auth";
import { type ServiceProviderConfig, samlIdp } from "better-auth-saml-idp";
import type { Pool } from "pg";

/** The settings Better Auth and the plugin read: secrets and vars on Workers, .dev.vars locally. */
export interface AuthEnv {
  BETTER_AUTH_SECRET: string;
  SAML_IDP_PRIVATE_KEY: string;
  SAML_IDP_CERT: string;
  /** JSON array of service providers (see README.md). */
  SAML_SERVICE_PROVIDERS?: string;
  /** Local development only (scripts/dev-keys.mjs writes it to .dev.vars): print verification links. */
  DEV_PRINT_VERIFICATION_LINKS?: string;
}

/** The SP options that JSON can carry (SAML_SERVICE_PROVIDERS). */
type SpJson = Pick<
  ServiceProviderConfig,
  | "id"
  | "entityId"
  | "acsUrls"
  | "nameIdFormat"
  | "requestSignatures"
  | "spCertificates"
  | "allowIdpInitiated"
  | "idpInitiatedRelayState"
  | "allowedRelayStates"
  | "sign"
  | "encryption"
  | "attributes"
  | "metadata"
>;

/** Sent to SPs whose JSON entry has no `attributes` (a declarative map; JSON can set its own). */
const DEFAULT_ATTRIBUTES = {
  email: "email",
  name: "name",
  firstName: { field: "name", part: "first" },
  lastName: { field: "name", part: "last" },
} as const;

/** What this example's sign-in page delivers: a password, over HTTPS. There's no step-up here. */
const PASSWORD_CLASS = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

function required(env: AuthEnv, name: "BETTER_AUTH_SECRET" | "SAML_IDP_PRIVATE_KEY" | "SAML_IDP_CERT"): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is not set (see examples/workers-neon/README.md)`);
  return value;
}

/**
 * Better Auth on `pool`. On Workers, src/index.ts builds it once per isolate and passes a pool
 * that sends each query to the current request's own pool (a connection can't be used by another
 * request there; Hyperdrive keeps the real connections to Neon warm). `background` receives the
 * work Better Auth and the plugin do after the response (event handlers, the audit log), so a
 * request's pool is closed only once that's done.
 */
export function buildAuth(env: AuthEnv, baseURL: string, pool: Pool, background: (task: Promise<unknown>) => void = (task) => void task.catch(() => {})) {
  const sps = JSON.parse(env.SAML_SERVICE_PROVIDERS || "[]") as SpJson[];
  const local = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(baseURL);
  return betterAuth({
    baseURL,
    secret: required(env, "BETTER_AUTH_SECRET"),
    database: pool,
    advanced: {
      // No schema check at startup: on Workers, a check started by one request and awaited by
      // another can hang when the first request ends. `pnpm db:migrate` sets the schema up.
      database: { validateSchema: false },
      backgroundTasks: { handler: background },
    },
    // The SAML plugin only asserts verified email addresses, so verification is required.
    emailAndPassword: { enabled: true, requireEmailVerification: true },
    emailVerification: {
      sendOnSignUp: true,
      autoSignInAfterVerification: true,
      sendVerificationEmail: async ({ user, url }) => {
        // LOCAL DEVELOPMENT ONLY: print the link. In production, send `url` to `user.email`
        // with your email provider here.
        if (local && env.DEV_PRINT_VERIFICATION_LINKS === "true") {
          console.log(`[example] verify ${user.email}: ${url}`);
          return;
        }
        console.error("[example] email sending is not configured; set up sendVerificationEmail");
      },
    },
    // Single-use state and rate limits in Postgres, shared by every isolate.
    verification: { storeInDatabase: true },
    rateLimit: { storage: "database" },
    plugins: [
      samlIdp({
        entityId: `${baseURL}/api/auth/saml2/idp`,
        loginPage: "/sign-in",
        signing: { privateKey: required(env, "SAML_IDP_PRIVATE_KEY"), certificate: required(env, "SAML_IDP_CERT") },
        // Password sign-in; many SPs (node-saml, for one) request exactly this class.
        authnContextClassRef: PASSWORD_CLASS,
        serviceProviders: sps.map((sp) => ({ ...sp, attributes: sp.attributes ?? DEFAULT_ATTRIBUTES })),
      }),
    ],
  });
}

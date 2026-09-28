// Better Auth with the SAML IdP plugin, on Node (node:sqlite). scripts/migrate.ts imports this
// file with Node's type stripping, so it has no relative imports and only erasable TypeScript.
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { type ServiceProviderConfig, samlIdp } from "better-auth-saml-idp";

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

/**
 * What this example's sign-in page delivers: a password, over HTTPS in production. An SP that asks
 * for another class (MFA) is answered NoAuthnContext by the IdP: this example has no step-up.
 */
const PASSWORD_CLASS = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set (see examples/nextjs/README.md)`);
  return value;
}

function buildAuth() {
  const baseURL = env("BETTER_AUTH_URL").replace(/\/+$/, "");
  const sps = JSON.parse(process.env.SAML_SERVICE_PROVIDERS || "[]") as SpJson[];
  return betterAuth({
    baseURL,
    // BETTER_AUTH_SECRET is read from the environment by Better Auth.
    database: new DatabaseSync(process.env.DATABASE_PATH || "./data.db"),
    // The SAML plugin only asserts verified email addresses, so verification is required.
    emailAndPassword: { enabled: true, requireEmailVerification: true },
    emailVerification: {
      sendOnSignUp: true,
      autoSignInAfterVerification: true,
      sendVerificationEmail: async ({ user, url }) => {
        // DEVELOPMENT ONLY: `next dev` prints the link instead of sending it. In production,
        // send `url` to `user.email` with your email provider here.
        if (process.env.NODE_ENV === "development") {
          console.log(`[example] verify ${user.email}: ${url}`);
          return;
        }
        console.error("[example] email sending is not configured; set up sendVerificationEmail");
      },
    },
    // Single-use state (verification values) in the database, never in secondary storage.
    verification: { storeInDatabase: true },
    plugins: [
      samlIdp({
        entityId: `${baseURL}/api/auth/saml2/idp`,
        loginPage: "/sign-in",
        signing: { privateKey: env("SAML_IDP_PRIVATE_KEY"), certificate: env("SAML_IDP_CERT") },
        // Password sign-in; many SPs (node-saml, for one) request exactly this class.
        authnContextClassRef: PASSWORD_CLASS,
        serviceProviders: sps.map((sp) => ({ ...sp, attributes: sp.attributes ?? DEFAULT_ATTRIBUTES })),
      }),
    ],
  });
}

type Auth = ReturnType<typeof buildAuth>;
const cache = globalThis as typeof globalThis & { __samlIdpExampleAuth?: Auth };

/**
 * Better Auth and the SAML plugin, built once per process on first use: the plugin parses the
 * key and compiles the XSD schemas once. Lazy, so `next build` doesn't need the secrets, and on
 * globalThis, so `next dev` reloads don't open another database handle.
 */
export function getAuth(): Auth {
  cache.__samlIdpExampleAuth ??= buildAuth();
  return cache.__samlIdpExampleAuth;
}

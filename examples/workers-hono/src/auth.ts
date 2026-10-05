import { AsyncLocalStorage } from "node:async_hooks";
import { betterAuth } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { withCloudflare } from "better-auth-cloudflare";
import { samlIdp, type ServiceProviderConfig } from "better-auth-saml-idp";
import { scimProvisioning, type Target } from "better-auth-scim-provisioning";
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
  /**
   * BENCHMARK ONLY. "off" turns Better Auth's rate limit off, so a load test from one machine
   * measures the IdP rather than the per-IP limit (scripts/bench). Never set this in production.
   */
  RATE_LIMIT?: string;
  /** This Worker's public origin, for runs without a request (the Cron Trigger's provisioning run). */
  PUBLIC_ORIGIN?: string;
  // Provisioning (better-auth-scim-provisioning), optional: set a target to turn it on, and apply
  // migration 0011 first. Only listed users are provisioned, so a demo never pushes strangers out.
  /** A SCIM 2.0 app (Cloudflare Access, AWS IAM Identity Center, …): its endpoint and token. */
  SCIM_URL?: string;
  SCIM_TOKEN?: string;
  /** Who goes to the SCIM app: comma-separated emails or "@domain" suffixes. Empty: nobody. */
  SCIM_ALLOWED_EMAILS?: string;
  /** "true": organizations as groups at the SCIM app. */
  SCIM_GROUPS?: string;
  /** Google Workspace: a service account with domain-wide delegation, acting as an admin. */
  GOOGLE_CLIENT_EMAIL?: string;
  GOOGLE_PRIVATE_KEY?: string;
  GOOGLE_ADMIN_EMAIL?: string;
  /** Where new Workspace users go, e.g. "/Provisioned". */
  GOOGLE_ORG_UNIT?: string;
  /** Who goes to Workspace: comma-separated emails or "@domain" suffixes. Empty: nobody. */
  GOOGLE_ALLOWED_EMAILS?: string;
  /** "true": organizations as Google Groups (delegation must also allow the group scope). */
  GOOGLE_GROUPS?: string;
}

/** A matcher for comma-separated emails or "@domain" suffixes; an empty list matches nobody. */
function allowList(list: string | undefined) {
  const allowed = (list ?? "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
  return (email: string) => allowed.some((a) => (a.startsWith("@") ? email.toLowerCase().endsWith(a) : email.toLowerCase() === a));
}

/** The provisioning targets the settings describe; none means provisioning is off. */
export function provisioningTargets(env: Env): Target[] {
  const targets: Target[] = [];
  if (env.SCIM_URL && env.SCIM_TOKEN) {
    const allowed = allowList(env.SCIM_ALLOWED_EMAILS);
    targets.push({ id: "scim", url: env.SCIM_URL, token: env.SCIM_TOKEN, include: (u) => allowed(u.email), groups: env.SCIM_GROUPS === "true" });
  }
  if (env.GOOGLE_CLIENT_EMAIL && env.GOOGLE_PRIVATE_KEY && env.GOOGLE_ADMIN_EMAIL) {
    const allowed = allowList(env.GOOGLE_ALLOWED_EMAILS);
    targets.push({
      id: "google-workspace",
      type: "google-workspace",
      include: (u) => allowed(u.email),
      groups: env.GOOGLE_GROUPS === "true",
      google: { clientEmail: env.GOOGLE_CLIENT_EMAIL, privateKey: env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n"), adminEmail: env.GOOGLE_ADMIN_EMAIL, orgUnitPath: env.GOOGLE_ORG_UNIT || undefined },
    });
  }
  return targets;
}
export const hasProvisioning = (env: Env) => provisioningTargets(env).length > 0;

/** DEV_MAILBOX: the latest verification link per email address (per isolate). */
export const devMailbox = new Map<string, string>();

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
  const admins = registryAdmins(env);
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
      canManage: admins.size ? ({ user }) => isRegistryAdmin(env, user) : undefined,
    },
    // Audit log (migration 0005): sign-ins, denials, logouts and ended sessions, shown on /admin.
    auditLog: { enabled: true, retentionDays: 30 },
    // Tenants (migrations 0008-0010): an organization can get its own IdP identity (entity ID,
    // metadata, SSO/SLO URLs), signing with its own key, sealed in D1 with BETTER_AUTH_SECRET.
    // Admins make tenants on /admin; the organization's owners and admins may then manage its SPs
    // through the registry API (delegation). The entity IDs are pinned by Better Auth's baseURL,
    // this Worker's own origin, never a Host header.
    tenants: { enabled: true, keys: "per-tenant", delegation: {} },
  });
  plugin = { key, value };
  return value;
}

/** The current request's `cf` geolocation, for the shared auth instance (see getAuth). */
export const requestCf = new AsyncLocalStorage<IncomingRequestCfProperties | Record<string, never>>();

/**
 * The current request's `waitUntil`. Better Auth's background tasks (for example the SAML
 * plugin's SP metadata refresh) must use it on Workers: work left running after a response
 * is otherwise cancelled.
 */
export const requestWaitUntil = new AsyncLocalStorage<(p: Promise<unknown>) => void>();

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
        rateLimit: { enabled: env.RATE_LIMIT !== "off", storage: "database" },
        advanced: {
          database: { validateSchema: true },
          backgroundTasks: {
            handler: (p: Promise<unknown>) => {
              const waitUntil = requestWaitUntil.getStore();
              if (waitUntil) waitUntil(p);
              else p.catch(() => {});
            },
          },
        },
        // Plugins go INSIDE withCloudflare's second argument (a `plugins` key next to the
        // spread would replace the Cloudflare plugin and silently drop its storage checks).
        plugins: [
          admin(),
          // Tenants are organizations. Only the registry admins create them in this example, so a
          // public deployment doesn't collect strangers' organizations (tenants are host-made anyway).
          organization({ allowUserToCreateOrganization: (user) => isRegistryAdmin(env, user) }),
          samlPlugin(env, origin),
          // Only with a target: Better Auth checks the schema (validateSchema), so the provisioning
          // tables are needed only once it's turned on.
          ...(hasProvisioning(env) ? [scimProvisioning({ targets: provisioningTargets(env) })] : []),
        ],
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

/** Emails allowed to manage SPs (SAML_REGISTRY_ADMINS, comma-separated). */
function registryAdmins(env: Env): Set<string> {
  return new Set((env.SAML_REGISTRY_ADMINS ?? "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean));
}

/** The registry's canManage rule, shared with the /admin page: a listed, verified email. */
export function isRegistryAdmin(env: Env, user: { email: string; emailVerified?: boolean | null }): boolean {
  return user.emailVerified === true && registryAdmins(env).has(user.email.toLowerCase());
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

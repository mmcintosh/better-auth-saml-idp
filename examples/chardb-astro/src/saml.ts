// The SAML IdP plugin (better-auth-saml-idp) with tenants: an organization can be made its own
// IdP, with its own entity ID, metadata, SSO/SLO URLs and signing key (per-tenant keys, sealed in
// CharDB with BETTER_AUTH_SECRET), and its owners and admins manage its SPs (delegation).
//
// Configuration comes from the Worker's vars and secrets, which nodejs_compat puts in process.env:
//   BETTER_AUTH_URL        this Worker's origin: pins the entity IDs (never a Host header)
//   SAML_IDP_PRIVATE_KEY   the root IdP's signing key (PEM), a secret
//   SAML_IDP_CERT          its certificate (PEM)
//   SAML_REGISTRY_ADMINS   comma-separated emails that manage SPs and tenants (verified only)
// Locally, `bun run keys` writes the first three to .dev.vars.
import { samlIdp } from "better-auth-saml-idp";

const env = process.env;

function required(name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is not set: run \`bun run keys\` for local development, or see the README for production`);
  return value;
}

const admins = new Set(String(env.SAML_REGISTRY_ADMINS ?? "").split(",").map((e: string) => e.trim().toLowerCase()).filter(Boolean));

/** A registry admin: a listed email, verified. */
export const isSamlAdmin = (user: { email: string; emailVerified?: boolean | null }) =>
  user.emailVerified === true && admins.has(user.email.toLowerCase());

export function samlIdpPlugin() {
  const baseURL = required("BETTER_AUTH_URL").replace(/\/+$/, "");
  return samlIdp({
    entityId: `${baseURL}/api/auth/saml2/idp`,
    baseURL,
    signing: { privateKey: required("SAML_IDP_PRIVATE_KEY"), certificate: required("SAML_IDP_CERT") },
    // src/sign-in.ts: signs in by email, then returns to callbackURL.
    loginPage: "/sign-in",
    serviceProviders: [],
    singleLogout: { enabled: true },
    registry: { enabled: true, canManage: ({ user }) => isSamlAdmin(user) },
    auditLog: { enabled: true, retentionDays: 30 },
    tenants: { enabled: true, keys: "per-tenant", delegation: {} },
  });
}

// A host app compiled with exactOptionalPropertyTypes, against the built declarations (dist/):
// `pnpm pack:check` runs `tsc -p tsconfig.strict-host.json`. 1.0.0's declarations failed here
// (samlIdp() wasn't assignable to BetterAuthPlugin), found running the plugin on CharDB.
import { type BetterAuthPlugin, betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { organization } from "better-auth/plugins";
import { samlIdp } from "better-auth-saml-idp";
import { samlIdpClient } from "better-auth-saml-idp/client";

declare const privateKey: string;
declare const certificate: string;
declare const maybeCert: string | undefined;

// Every optional group on, so every conditionally mounted endpoint is in the type.
const plugin: BetterAuthPlugin = samlIdp({
  entityId: "https://auth.example.com/api/auth/saml2/idp",
  signing: { privateKey, certificate, additionalCertificates: maybeCert === undefined ? undefined : [maybeCert] },
  loginPage: "/sign-in",
  serviceProviders: [{ id: "sp", entityId: "https://sp.example.com", acsUrls: ["https://sp.example.com/acs"], nameIdFormat: undefined }],
  singleLogout: { enabled: true },
  auditLog: { enabled: true },
  registry: { enabled: true, canManage: ({ user }) => user.email.endsWith("@example.com") },
  tenants: { enabled: true },
});

export const auth = betterAuth({ baseURL: "https://auth.example.com", plugins: [organization(), plugin] });
export const direct = betterAuth({ plugins: [organization(), samlIdp({ entityId: "e", signing: { privateKey, certificate }, loginPage: "/", serviceProviders: [] })] });
export const client = createAuthClient({ plugins: [samlIdpClient()] });

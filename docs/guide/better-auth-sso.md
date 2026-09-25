# Using with `@better-auth/sso`

[Guide](README.md) › Using with `@better-auth/sso`

`@better-auth/sso` makes Better Auth a SAML **service provider**: it signs users in *from* an identity provider. This plugin makes Better Auth a SAML **identity provider**: it signs users in *to* service providers. They're two halves of SAML, and they work together, which our CI tests on every commit.

## Better Auth to Better Auth

App B (the SP) lets its users sign in with their account on app A (the IdP), over SAML.

**App A (IdP):**

```ts
import { samlIdp } from "better-auth-saml-idp";

samlIdp({
  entityId: "https://a.example.com/api/auth/saml2/idp",
  baseURL: "https://a.example.com/api/auth",
  loginPage: "/sign-in",
  signing: { privateKey: env.SAML_IDP_PRIVATE_KEY, certificate: env.SAML_IDP_CERT },
  serviceProviders: [
    {
      id: "app-b",
      // @better-auth/sso's SP entity ID and ACS URL for this provider:
      entityId: "https://b.example.com/api/auth/sso/saml2/sp/metadata",
      acsUrls: ["https://b.example.com/api/auth/sso/saml2/sp/acs/app-a"],
      attributes: { email: "email", name: "name" },
    },
  ],
});
```

**App B (SP):**

```ts
import { sso } from "@better-auth/sso";

sso({
  defaultSSO: [
    {
      domain: "example.com",
      providerId: "app-a",   // must match the last segment of the ACS URL above
      samlConfig: {
        issuer: "https://b.example.com/api/auth/sso/saml2/sp/metadata",
        entryPoint: "https://a.example.com/api/auth/saml2/idp/sso",
        idpMetadata: { metadata: idpMetadataXml }, // fetched from A's /saml2/idp/metadata
        callbackUrl: "https://b.example.com/dashboard",
        wantAssertionsSigned: true,
      },
    },
  ],
});
```

**Sign in from B:**

```ts
await authClient.signIn.sso({ providerId: "app-a", callbackURL: "/dashboard" });
```

The user goes to A, signs in there (or is already signed in), and comes back to B with a session for the same email. That's exactly what `test/interop/sp-interop.test.ts` does.

Things to line up:
- `acsUrls` on A must be B's ACS URL for this provider: `https://b…/api/auth/sso/saml2/sp/acs/<providerId>`.
- `entityId` on A must be B's `samlConfig.issuer`.
- B should require signed assertions (`wantAssertionsSigned: true`). A signs both the Response and the Assertion by default.
- B's `idpMetadata` comes from A's metadata endpoint. Refresh it when A rotates its key; see [rotation](signing-and-encryption.md#rotation).
- If B also uses `@better-auth/sso`'s IdP-initiated support, see [IdP-initiated SSO](flows.md#idp-initiated-sso) on A (`allowIdpInitiated`), and `saml.allowIdpInitiated` on B.

## One app, both roles: an identity broker

A single Better Auth app can use both plugins. Users sign in with their company's IdP (Okta, Entra ID) through `@better-auth/sso`, and your app then signs them in to SAML-only tools through this plugin:

```
Okta ──SAML──> your app (sso plugin = SP)  ──SAML──> Zoom, HubSpot (saml-idp plugin = IdP)
```

This works because the IdP plugin only needs a Better Auth session. However the user signed in (password, social, or SSO through `@better-auth/sso`), the [sign-in page contract](getting-started.md#5-return-users-from-your-sign-in-page) is the same: send the browser to `callbackURL` afterwards. With `@better-auth/sso`, pass that `callbackURL` to `signIn.sso`.

Keep in mind:
- **Email verification:** the [account policy](users-and-access.md#account-policy) requires verified emails. Users created by `@better-auth/sso` have whatever `emailVerified` your SSO setup gives them. Make sure SSO-provisioned users are verified if your upstream IdP guarantees their addresses.
- **What the assertion claims:** `authnContextClassRef` should describe how users actually sign in. With an upstream IdP, that's what the upstream IdP guarantees.
- **Organizations:** `@better-auth/sso`'s organization provisioning puts users into organizations, and this plugin's [`organization` rule](users-and-access.md#organizations) can then gate SPs on that membership. That's a clean way to give each customer's users access to only their tools.

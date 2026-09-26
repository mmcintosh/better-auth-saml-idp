# Auth0 as a service provider

Auth0 can use a SAML identity provider through an **Enterprise SAML connection**, so users sign in to your Auth0 applications with their Better Auth account. Verified live on 2026-09-26 with a free Auth0 tenant: Auth0's **signed** AuthnRequests were verified with the certificate the plugin learned from Auth0's public metadata (the SP stored in the database registry with only `metadata.url`), and Auth0 received the NameID and first/last name attributes. Both request bindings were verified: HTTP-Redirect (query signature) and HTTP-POST (an enveloped XML signature, checked with the plugin's signature-wrapping defences) (DECISIONS D-035).

## 1. Create the connection in Auth0

**Authentication → Enterprise → SAML → + Create Connection**:

| Field | Value |
|---|---|
| Connection name | e.g. `better-auth` (part of Auth0's URLs; can't be changed) |
| Sign In URL | `https://auth.example.com/api/auth/saml2/idp/sso` |
| X509 Signing Certificate | your IdP certificate as a PEM file |
| User ID Attribute | leave the default (Auth0 uses the NameID) |
| Debug Mode | on while testing (details in Auth0's logs) |
| Sign Request | on, RSA-SHA256, SHA256 |
| Protocol Binding | HTTP-Redirect (or HTTP-POST; the plugin verifies both) |

Click **Save Changes** at the bottom of the page. Only that button saves, and a Sign In URL that didn't save is the most common problem.

Then **enable the connection for an application**: in the connection's **Applications** tab, or in **Applications → your app → Connections**. Otherwise Auth0 answers "the connection is not enabled".

## 2. Register Auth0 on the IdP

Auth0's SP metadata is public:

```bash
npx better-auth-saml-idp sp-from-metadata "https://<tenant>.auth0.com/samlp/metadata?connection=better-auth" --id auth0
```

Or keep its certificates current automatically:

```ts
{
  id: "auth0",
  entityId: "urn:auth0:<tenant>:better-auth",
  acsUrls: ["https://<tenant>.auth0.com/login/callback?connection=better-auth"],
  requireSignedAuthnRequests: true,
  metadata: { url: "https://<tenant>.auth0.com/samlp/metadata?connection=better-auth" },
  attributes: {
    email: "email",
    name: "name",
    given_name: { field: "name", part: "first" },
    family_name: { field: "name", part: "last" },
  },
}
```

## 3. Test

**Authentication → Enterprise → SAML → ⋯ → Try** on the connection. After signing in at your Better Auth sign-in page, Auth0 shows the profile it built, for example `sub: samlp|better-auth|<email>`, `given_name` and `family_name`.

## Notes

- **`ProtocolBinding`:** Auth0 puts its *request* binding in the AuthnRequest's `ProtocolBinding` (for example HTTP-Redirect), which is meant to name the *Response* binding. The plugin treats HTTP-Redirect there as "no preference" and answers over HTTP-POST, as always.
- **Single Logout:** Auth0's metadata includes a `SingleLogoutService`; enable "Sign Out" on the connection to use it.

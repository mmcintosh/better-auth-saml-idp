# Okta as a service provider

Okta can accept sign-ins from an external SAML identity provider, so users sign in to Okta (and everything behind it) with their Better Auth account. Verified live on 2026-09-26 with an Okta Integrator (free) org: Okta's **signed** AuthnRequests were verified, and our assertions were accepted both **plain and encrypted** (AES-256-GCM + RSA-OAEP), with Okta registered in the plugin's database registry (DECISIONS D-034).

## 1. Add the IdP in Okta

In the admin console: **Security → Identity Providers** (direct link: `https://<org>-admin.okta.com/admin/access/identity-providers`) **→ Add identity provider → SAML 2.0 IdP**.

| Field | Value |
|---|---|
| IdP Usage | SSO only |
| IdP username | `idpuser.subjectNameId` (our NameID is the email by default) |
| If no match is found | Create new user (JIT), or redirect to the Okta sign-in page |
| IdP Issuer URI | your `entityId`, e.g. `https://auth.example.com/api/auth/saml2/idp` |
| IdP Single Sign-On URL | `https://auth.example.com/api/auth/saml2/idp/sso` |
| IdP Signature Certificate | your IdP certificate as a file (for example from `npx better-auth-saml-idp inspect`, or the PEM you created with `keygen`) |
| Request Binding | HTTP Redirect |
| Request Signature | on (SHA-256): the plugin verifies it |
| Response Signature Verification | Response or Assertion (the plugin signs both) |

Save. Okta shows its **Assertion Consumer Service URL** and **Audience URI**, and a **Download metadata** link (the metadata needs an admin session, so download it rather than fetching it).

## 2. Register Okta on the IdP

From the downloaded metadata:

```bash
npx better-auth-saml-idp sp-from-metadata metadata.xml --id okta
```

This gives the entity ID (the Audience URI), the ACS URL, `requireSignedAuthnRequests: true` with Okta's signing certificate, and `encryption` with Okta's encryption certificate. Keep `encryption` to send encrypted assertions (Okta decrypts them), or remove it for plain ones. Add attributes Okta's just-in-time provisioning can use:

```ts
attributes: {
  email: "email",
  firstName: { field: "name", part: "first" },
  lastName: { field: "name", part: "last" },
}
```

Add the entry to `serviceProviders`, or store it in the [registry](guide/service-providers.md#registry). On Workers, a JSON variable is limited to about 5 kB; Okta's two certificates push a config over that, so the registry (D1) is the better home.

## 3. Test

Open `https://<org>.okta.com/sso/saml2/<IdP ID>` in a private window. Okta sends a signed AuthnRequest; after signing in at your Better Auth sign-in page, you land in Okta. To send users to this IdP automatically, add an **IdP routing rule** (Security → Identity Providers → Routing Rules).

## Notes

- **First sign-in:** with JIT, Okta creates the user and then asks them to set up its own authenticators (Okta's policy, not the IdP's).
- **Account matching:** `idpuser.subjectNameId` against the Okta username works with the default email NameID. For a persistent NameID, match on email with an attribute instead.
- Okta's System Log (Reports → System Log) shows the reason for any rejected Response.

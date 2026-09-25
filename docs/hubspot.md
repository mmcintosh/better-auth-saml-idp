# Service provider: HubSpot

> **Status: not yet verified against a live HubSpot portal.** HubSpot SSO generally needs a paid HubSpot subscription; check your plan in HubSpot's knowledge base ("Set up single sign-on (SSO)"). The flow below uses only what the plugin already implements and tests. The HubSpot values are placeholders: copy the real ones from **your** portal. The Phase 3 live-login evidence is currently provided by Keycloak, SimpleSAMLphp and the hosted SPs; see [testing-with-sps.md](testing-with-sps.md).

## 1. Get HubSpot's SP values

In HubSpot, open **Settings → Account Defaults → Security → Single sign-on (SSO) → Set up**. HubSpot shows two values specific to your portal. Copy both exactly, including any query string:

| HubSpot label | Plugin field |
|---|---|
| Audience URI (Service Provider Entity ID) | `entityId` |
| Sign on URL, ACS, Recipient, or Redirect | `acsUrls[0]` |

## 2. Register HubSpot on the IdP

```ts
samlIdp({
  // …
  serviceProviders: [
    {
      id: "hubspot",
      entityId: "<Audience URI from HubSpot>",
      acsUrls: ["<ACS URL from HubSpot>"],
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      nameId: (user) => user.email, // must match the HubSpot user's email
      attributes: (user) => ({ email: user.email }),
      // Optional: restrict who may sign in to HubSpot
      authorize: async ({ user }) => user.email.endsWith("@your-company.example"),
    },
  ],
});
```

The ACS URL is compared **exactly**. If HubSpot's ACS URL includes something like `?portalId=…`, include it as shown by HubSpot.

## 3. Give HubSpot the IdP values

| HubSpot field | Value |
|---|---|
| Identity Provider Identifier / Issuer URL | `https://<your-auth-host>/api/auth/saml2/idp` |
| Identity Provider Single Sign-On URL | `https://<your-auth-host>/api/auth/saml2/idp/sso` |
| X.509 certificate | the signing certificate (PEM body, or the `<ds:X509Certificate>` in `/api/auth/saml2/idp/metadata`) |

## 4. Verify before enforcing

Keep a HubSpot super-admin who can still sign in with a password until SSO works. Then:
1. Use HubSpot's **Verify** button: you should see the IdP login page, then return to HubSpot.
2. Decode the SAML Response from your browser's network tab (the `SAMLResponse` form field) and validate it as in [testing-with-sps.md](testing-with-sps.md#external-validator-samltool).
3. Only after that, turn on "Require SSO".

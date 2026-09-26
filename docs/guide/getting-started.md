# Getting started

[Guide](README.md) › Getting started

This page takes you from nothing to a working sign-in at a SAML service provider. It assumes a Better Auth app that users can already sign in to.

## 1. Install

```bash
npm install better-auth-saml-idp
# or: pnpm add / yarn add / bun add
```

Requirements: `better-auth` `>=1.7.5 <1.8.0`, and a real database (replay protection relies on UNIQUE constraints). On Cloudflare Workers, also `better-auth-cloudflare` ≥ 0.4 and the `nodejs_compat` flag; see [Cloudflare Workers](cloudflare-workers.md).

## 2. Create a signing key

The IdP signs every Response with an RSA key. SPs trust its certificate.

```bash
# Node: write both to files (the key with mode 0600), load them from your secret store
npx better-auth-saml-idp keygen --cert-out idp.crt --key-out idp.key

# Workers: the key goes straight into a secret, never to disk
npx better-auth-saml-idp keygen --cert-out idp.crt | npx wrangler secret put SAML_IDP_PRIVATE_KEY
npx wrangler secret put SAML_IDP_CERT < idp.crt
```

`keygen` creates a 3072-bit key and a self-signed certificate valid for 730 days (`--bits`, `--days`, `--cn` change that). It refuses to print a private key to a terminal. A self-signed certificate is normal for SAML: SPs trust the certificate itself, not a CA. Plan its [rotation](../key-rotation.md).

## 3. Add the plugin

```ts title="auth.ts"
import { betterAuth } from "better-auth";
import { samlIdp } from "better-auth-saml-idp";

export const auth = betterAuth({
  // database, emailAndPassword, … as you have them
  plugins: [
    samlIdp({
      entityId: "https://auth.example.com/api/auth/saml2/idp",
      baseURL: "https://auth.example.com/api/auth",
      loginPage: "/sign-in",
      signing: {
        privateKey: process.env.SAML_IDP_PRIVATE_KEY!,
        certificate: process.env.SAML_IDP_CERT!,
      },
      serviceProviders: [], // added in step 6
    }),
  ],
});
```

- `entityId` is the IdP's permanent name. SPs pin it, so pick it once. The URL form above is conventional, but it's only an identifier.
- `baseURL` pins the URLs the IdP puts in its metadata and checks in requests. Always set it in production.
- `loginPage` is your existing sign-in page; see step 5.

Every option is in the [options reference](options.md).

## 4. Create the tables

```bash
npx auth migrate     # Kysely-based adapters
npx auth generate    # Drizzle or Prisma: generates the schema; then run your migration
```

This adds `samlIdpSeenRequest`, plus the registry and Single Logout tables if you enable them. See the [schema](schema.md). On D1, use the example's [migrations](../../examples/workers-hono/migrations/).

## 5. Return users from your sign-in page

When an SP sends a signed-out user to the IdP, the IdP stores the request and redirects to:

```
/sign-in?callbackURL=https%3A%2F%2Fauth.example.com%2Fapi%2Fauth%2Fsaml2%2Fidp%2Fresume%3Frid%3D…
```

After a successful sign-in, **send the browser to `callbackURL`**. The IdP then checks the user and posts the assertion to the SP. With Better Auth's client:

```ts
const callbackURL = new URLSearchParams(location.search).get("callbackURL") ?? "/";
await authClient.signIn.email({ email, password, callbackURL });
```

`callbackURL` is always an absolute URL on your IdP's own origin, and the resume link only works in the browser that started the sign-in. Users who are already signed in skip the page entirely.

Only users with a **verified email** receive assertions (see [Account policy](users-and-access.md#account-policy)). If your app doesn't verify emails yet, that's the first thing to add.

## 6. Register a service provider

Every SP needs three things from you: its **entity ID**, its **ACS URL** (Assertion Consumer Service, where the IdP posts the Response), and which **attributes** it expects. Give the SP your metadata URL (or the values in it):

```
https://auth.example.com/api/auth/saml2/idp/metadata
```

Then add the SP:

```ts
serviceProviders: [
  {
    id: "hubspot",
    entityId: "https://api.hubspot.com/login-api/v1/saml/login?portalId=1234",
    acsUrls: ["https://api.hubspot.com/login-api/v1/saml/acs?portalId=1234"],
    attributes: { email: "email", firstName: { field: "name", part: "first" } },
  },
],
```

Or build the entry from the SP's metadata:

```bash
npx better-auth-saml-idp sp-from-metadata https://sp.example.com/saml/metadata --id my-sp
```

SPs can also be added at runtime with the [registry](service-providers.md#registry). Step-by-step guides: [Cloudflare Access](../sp-cloudflare-access.md), [Okta](../sp-okta.md), [HubSpot](../hubspot.md), [AWS IAM Identity Center](../sp-aws-iam-identity-center.md), and [testing with other SPs](../testing-with-sps.md).

## 7. Check it

```bash
npx better-auth-saml-idp inspect https://auth.example.com   # what SPs see: metadata, certificates, expiry
npx better-auth-saml-idp smoke https://auth.example.com --sp <the SP's entity ID>   # 15 security checks
```

Then sign in from the SP. If something goes wrong, the error page shows a code; look it up in the [error reference](errors.md), or paste the SAML message from the browser's network tab into `npx better-auth-saml-idp decode`.

## Next

- [Sign-in flows](flows.md): what happens on each request, IdP-initiated SSO, ForceAuthn and IsPassive
- [Users and access](users-and-access.md): account policy, NameIDs, attributes, organizations, `authorize`
- [Signing, encryption and keys](signing-and-encryption.md)
- [Single Logout](single-logout.md)
- [Security](security.md)

# Example: SAML IdP on Cloudflare Workers (Hono + D1 + Drizzle)

This is a minimal Better Auth server that acts as a **SAML 2.0 Identity Provider**, using `better-auth-saml-idp`. It follows every host requirement in the plugin's [security guide](../../docs/security.md):
- `samlIdp()` sits **inside** `withCloudflare`'s second argument
- verification values and rate limits are stored in the database (D1), never in KV
- `validateSchema` is on

> **`better-auth-cloudflare` ≥ 0.4 is required.** Until 0.4 is on npm, this example uses a build of upstream `main` from `../../vendor/`, which contains the 0.4 storage check. Switch to `"better-auth-cloudflare": "^0.4.0"` once it's released.

## Run it locally

```sh
pnpm install                 # from the repo root (pnpm workspace)
cd examples/workers-hono
pnpm keys                    # writes .dev.vars: a throwaway IdP key pair + BETTER_AUTH_SECRET
pnpm db:migrate:local        # creates the tables in local D1
pnpm dev --var DEV_MAILBOX:true   # http://localhost:8787
```

- IdP metadata: `http://localhost:8787/api/auth/saml2/idp/metadata`
- Entity ID: `http://localhost:8787/api/auth/saml2/idp`
- SSO URL: `http://localhost:8787/api/auth/saml2/idp/sso` (Redirect and POST)

## Email verification

The plugin only signs assertions for **verified** email addresses, so the example requires verification (`requireEmailVerification`, then auto sign-in after verifying):
- **In production:** implement `sendVerificationEmail` in `src/auth.ts` with your email provider, for example Cloudflare Email Service.
- **In development:** `DEV_MAILBOX=true` keeps the link in memory and serves it at `/dev/mailbox?email=…`. Never set it in production.

## Register service providers

SPs come from the `SAML_SERVICE_PROVIDERS` variable, a JSON array, so adding one doesn't need a code change:

```jsonc
[
  { "id": "cf-access", "entityId": "https://TEAM.cloudflareaccess.com/cdn-cgi/access/callback",
    "acsUrls": ["https://TEAM.cloudflareaccess.com/cdn-cgi/access/callback"] }
]
```

- **Locally:** `pnpm dev --var 'SAML_SERVICE_PROVIDERS:[...]'`, or put it in `.dev.vars`.
- **Deployed:** set it in `wrangler.jsonc` → `vars`, or with the dashboard.

Every SP gets NameID = the user's email, plus the attributes `email`, `name`, `firstName` and `lastName` (see `src/auth.ts`).

## Deploy

```sh
npx wrangler d1 create saml-idp-example       # paste database_id into wrangler.jsonc
pnpm db:migrate:remote
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 730 -subj "/CN=my-idp" -keyout idp.key -out idp.crt
npx wrangler secret put SAML_IDP_PRIVATE_KEY < idp.key
npx wrangler secret put SAML_IDP_CERT < idp.crt
openssl rand -base64 32 | npx wrangler secret put BETTER_AUTH_SECRET
rm idp.key                                     # keep a secure backup of the key; never commit it
pnpm deploy
```

After deploying, the entity ID becomes `https://<your-worker>.workers.dev/api/auth/saml2/idp`. Register SPs with that value.

Two things to know:
- **Workers Paid is recommended.** The first SAML request in each new isolate compiles the XSD schemas, about 40–55 ms of CPU, which is over the Free plan's 10 ms limit for that one request.
- **Don't add KV for sessions** and don't enable `session.cookieCache`. See [docs/security.md](../../docs/security.md).

## Guides for real service providers

- [Cloudflare Access](../../docs/sp-cloudflare-access.md)
- [AWS IAM Identity Center](../../docs/sp-aws-iam-identity-center.md)
- [HubSpot](../../docs/hubspot.md), not yet verified live
- [Testing with other SPs and validators](../../docs/testing-with-sps.md)

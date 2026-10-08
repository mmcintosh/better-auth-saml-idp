# Example: SAML IdP on Cloudflare Workers (Hono + D1 + Drizzle)

This is a minimal Better Auth server that acts as a **SAML 2.0 Identity Provider**, using `better-auth-saml-idp`. It follows every host requirement in the plugin's [security guide](../../docs/security.md):
- `samlIdp()` sits **inside** `withCloudflare`'s second argument
- verification values and rate limits are stored in the database (D1), never in KV
- `validateSchema` is on

> **`better-auth-cloudflare`:** this example uses a build of upstream `main` from `../../vendor/` (the coming 0.4, which checks storage routing at startup). With npm's 0.3.1 it also works, because the settings above keep verification values and rate limits out of KV ([#72](https://github.com/zpg6/better-auth-cloudflare/issues/72)). Switch to `"better-auth-cloudflare": "^0.4.0"` once it's released.

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

## Two-step sign-in

Signed-in users can turn on two-step sign-in (an authenticator-app code, Better Auth's `twoFactor` plugin; migration `0012_two_factor.sql`) on the home page. Turning it on signs them out everywhere, so every later session has passed the code. The SAML plugin then reports the stronger sign-in to service providers (`authnContext`, D-047): `PasswordProtectedTransport` for a password, Microsoft's `http://schemas.microsoft.com/claims/multipleauthn` for a password plus a code. A Microsoft 365 domain federated to this IdP with `federatedIdpMfaBehavior` set to `acceptIfMfaDoneByFederatedIdp` then accepts that as MFA and doesn't ask again. A session an admin opened by impersonating a user counts as password only.

## Register service providers

SPs come from the `SAML_SERVICE_PROVIDERS` variable, a JSON array, so adding one doesn't need a code change:

```jsonc
[
  { "id": "cf-access", "entityId": "https://TEAM.cloudflareaccess.com/cdn-cgi/access/callback",
    "acsUrls": ["https://TEAM.cloudflareaccess.com/cdn-cgi/access/callback"] }
]
```

Each entry takes any JSON-representable SP option, including `attributes` as a declarative map (for example `"attributes": { "email": "email", "role": "role" }`). Without one, the example sends `email`, `name`, `firstName` and `lastName`. Check a config with `npx better-auth-saml-idp check-config`.

- **Locally:** `pnpm dev --var 'SAML_SERVICE_PROVIDERS:[...]'`, or put it in `.dev.vars`.
- **Deployed:** set it in `wrangler.jsonc` → `vars`, or with the dashboard.

Every SP gets NameID = the user's email, plus the attributes `email`, `name`, `firstName` and `lastName` (see `src/auth.ts`).

Optional per-SP keys passed through: `nameIdFormat`, `requestSignatures`, `spCertificates`, and for IdP-initiated SSO `allowIdpInitiated`, `idpInitiatedRelayState` and `allowedRelayStates`. SPs with `"allowIdpInitiated": true` are listed under **Apps** on the home page, each linking to `/api/auth/saml2/idp/init?sp=<id>`.

## Admin pages

The example's pages share one layout, with a sidebar to move between them. The pages are built only on the plugins' public APIs: copy them into your own app (`src/admin.ts`, `src/ui/`). The plugins themselves ship no UI, like `@better-auth/sso`.

| Page | What's on it |
|---|---|
| **My apps** (`/`) | For everyone signed in: the apps they can open from here (IdP-initiated SSO), and the tenants' metadata |
| **Overview** (`/admin`) | Counts, this IdP's details for SP setup forms (entity ID, SSO and SLO URLs, metadata, with copy buttons; the metadata and certificate as downloads, with the certificate's expiry), and recent activity |
| **Service providers** (`/admin/sps`) | SPs from code and from the database registry, with status, issues and warnings; add one from its metadata XML (reviewed as JSON before saving); edit, enable or disable, delete; test sign-in |
| **Tenants** (`/admin/tenants`) | Create a tenant (an organization and its own IdP), enable or disable it, rotate its signing key (see [Tenants](#tenants)) |
| **Activity** (`/admin/activity`) | The audit log: sign-ins, refusals, logouts, ended sessions, with each user's email |
| **Users and apps** (`/admin/provisioning`) | With [provisioning](#provisioning-optional) on: each user's account at each app, the queue, groups, and actions (see below) |

The styles and code are same-origin files (`/assets/app.css`, `/assets/app.js`), so the pages' Content Security Policy allows no inline code at all. Stored values (SP configurations, names, audit details) are rendered as text, never markup. The design has light and dark themes.

Only emails listed in `SAML_REGISTRY_ADMINS` (comma-separated, a variable) with a verified address can open it or use the registry API:

```jsonc
"vars": { "SAML_REGISTRY_ADMINS": "you@example.com" }
```

## Provisioning (optional)

With [better-auth-scim-provisioning](https://www.npmjs.com/package/better-auth-scim-provisioning), the same app also keeps accounts in step at the apps it signs people in to: created before the first sign-in, updated, deactivated when someone is banned or deleted, and organizations as groups. See [sign-in and provisioning together](../../docs/guide/provisioning.md).

It's off until you configure a target:

1. Apply migration `0011_scim_provisioning.sql` (`pnpm db:migrate:remote`). It's needed only once provisioning is on: Better Auth checks the schema (`validateSchema`), so the provisioning plugin is added only with a target.
2. Set a target, and **who may be provisioned there** (comma-separated emails or `@domain` suffixes; empty means nobody, so a demo never pushes strangers' accounts out):

| Target | Settings |
|---|---|
| A SCIM 2.0 app (Cloudflare Access, AWS IAM Identity Center, …) | `SCIM_URL`, `SCIM_TOKEN` (secrets); `SCIM_ALLOWED_EMAILS`; `SCIM_GROUPS="true"` for organizations as groups |
| Google Workspace | `GOOGLE_CLIENT_EMAIL`, `GOOGLE_PRIVATE_KEY`, `GOOGLE_ADMIN_EMAIL` (secrets); `GOOGLE_ALLOWED_EMAILS`; `GOOGLE_ORG_UNIT` (e.g. `/Provisioned`); `GOOGLE_GROUPS="true"` for Google Groups |

3. For retries, add a Cron Trigger and this Worker's public origin, so the scheduled run can deliver what's due:

```jsonc
"triggers": { "crons": ["* * * * *"] },
"vars": { "PUBLIC_ORIGIN": "https://<your-worker>.workers.dev" }
```

**Users and apps** (`/admin/provisioning`) then shows each user's account at each app (provisioned, pending, deactivated, or not provisioned), any queued or failed delivery with its error, the groups, and the queue. From there an admin can add a test user, rename, change email, ban and unban, set a password (so a test user can sign in through the IdP), re-sync, delete, run the queue, and reconcile everyone a page at a time. The admin can't ban or delete their own account there.

To try it locally without a real app, point `SCIM_URL` at any local SCIM server on `http://127.0.0.1` (http is allowed for loopback addresses only).

## Tenants

The example is a multi-tenant IdP ([guide](../../docs/guide/multi-tenant.md)): an organization can be made a **tenant**, which is its own IdP with its own entity ID, metadata, SSO and SLO URLs, and signing key. The root IdP above is unchanged. In `src/auth.ts`:

```ts
organization({ allowUserToCreateOrganization: (user) => isRegistryAdmin(env, user) }),
samlIdp({ /* … */ tenants: { enabled: true, keys: "per-tenant", delegation: {} } }),
```

- **Making one:** on `/admin`, **New tenant** creates an organization (you become its owner) and its tenant. The slug is the tenant key, in its URLs: `/api/auth/saml2/idp/metadata/<key>`, `/sso/<key>`, `/slo/<key>`. It never changes, because SPs pin it. Enabled tenants are listed on the home page.
- **Its SPs:** stored SPs with `"tenant": "<organization id>"` in their JSON. They sign in through the tenant's URLs and get assertions from the tenant's entity ID.
- **Its key:** each tenant gets its own RSA 3072 key when it's made, stored in D1 encrypted with `BETTER_AUTH_SECRET`. Rotate it on `/admin` in three steps, as for the root key: rotate (publish a next key), activate (24 hours later, once SPs have fetched it; or forced, for a leaked key), retire.
- **Delegation:** the organization's owners and admins may manage the tenant's SPs through the registry API. In this example only registry admins can create organizations, so a public deployment doesn't collect strangers' organizations.
- **CPU:** generating a key (creating a tenant, or rotating without uploading a key) takes a few hundred milliseconds of CPU or more: fine on Workers Paid, over the Free plan's limit.
- **Upgrading a deployment that already had stored SPs:** apply the migrations (0008 to 0010), deploy, then press **Backfill SP lookup keys** on `/admin` once. Until then those SPs aren't found.

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

- [Cloudflare Access](../../docs/sp-cloudflare-access.md), [Okta](../../docs/sp-okta.md), [Auth0](../../docs/sp-auth0.md), [Salesforce](../../docs/sp-salesforce.md) and [AWS IAM Identity Center](../../docs/sp-aws-iam-identity-center.md), verified live
- [HubSpot](../../docs/hubspot.md), not yet verified live
- [Testing with other SPs and validators](../../docs/testing-with-sps.md)

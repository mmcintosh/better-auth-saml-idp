# Example: SAML IdP on Next.js (App Router, Node, SQLite)

A minimal Next.js app that runs Better Auth as a **SAML 2.0 Identity Provider** with `better-auth-saml-idp`, on Node with `node:sqlite` (no native modules). It shows:
- `samlIdp()` next to email and password sign-in, built once per process (`src/lib/auth.ts`);
- Better Auth's Next.js handler on the Node runtime (`src/app/api/auth/[...all]/route.ts`);
- a sign-in page that honours the plugin's login-page contract (`src/app/sign-in/page.tsx`);
- a home page with who is signed in and a link to the IdP metadata.

For Cloudflare Workers, see the [Workers + Hono example](../workers-hono/README.md). The [guide](../../docs/guide/README.md) explains every option.

## Run it locally

Requires Node 22.18+ (the migration script uses Node's type stripping) and pnpm.

```sh
pnpm install              # from the repo root (a pnpm workspace; also builds the plugin)
cd examples/nextjs
pnpm keys                 # writes .env.local: a throwaway IdP key pair, BETTER_AUTH_SECRET, a test SP
pnpm db:migrate           # creates the tables in ./data.db
pnpm dev                  # http://localhost:3000
```

- IdP metadata: `http://localhost:3000/api/auth/saml2/idp/metadata`
- Entity ID: `http://localhost:3000/api/auth/saml2/idp`
- SSO URL: `http://localhost:3000/api/auth/saml2/idp/sso` (Redirect and POST)

`pnpm keys` runs the plugin's CLI (`better-auth-saml-idp keygen`) and never prints the private key. It refuses to replace an existing `.env.local` without `--force`. `.env.local` and `data.db` are gitignored. `next start` loads `.env.local` too: don't build or start a production deployment from a directory where you ran `pnpm keys`, or it runs with the throwaway key and secret. Delete `.env.local` there, or deploy from a clean checkout with the values in your host's secret store.

### Environment

| Variable | What it is |
|---|---|
| `BETTER_AUTH_URL` | The site's origin, for example `http://localhost:3000`. The entity ID and every SAML URL derive from it. |
| `BETTER_AUTH_SECRET` | Better Auth's secret (32+ random bytes). |
| `SAML_IDP_PRIVATE_KEY`, `SAML_IDP_CERT` | The IdP's signing key and certificate, as PEM. In production, create them once (`npx better-auth-saml-idp keygen --cert-out idp.crt --key-out idp.key`) and keep them in your secret store. |
| `SAML_SERVICE_PROVIDERS` | The SPs, as a JSON array (below). |
| `DATABASE_PATH` | Optional: the SQLite file, `./data.db` by default. |

### Database

`pnpm db:migrate` runs `scripts/migrate.ts`, which passes the app's own Better Auth options to `getMigrations` from `better-auth/db/migration`. That creates Better Auth's tables and the plugin's (`samlIdpSeenRequest`, the replay-protection table). Run it again after upgrading or changing plugins; it only adds what's missing. On the first run, Better Auth's startup schema check logs the missing tables just before the script creates them.

Better Auth's CLI (`npx auth migrate`) does the same if you export an `auth` instance from a config file it can load. The script is used here because the app builds Better Auth lazily (below).

Better Auth and the plugin are built on first use, once per process (`getAuth()`), so `next build` doesn't need the secrets and the plugin parses the key and compiles its XSD schemas once. `next.config.ts` lists `better-auth-saml-idp` in `serverExternalPackages`: the plugin reads its validator (`wasm/xsd.wasm`) from its package directory at runtime, so it must not be bundled.

## Email verification

The plugin only signs assertions for **verified** email addresses (the [account policy](../../docs/guide/users-and-access.md#account-policy)), so the example requires verification, then signs the user in when they follow the link (`autoSignInAfterVerification`):
- **In development** (`next dev`), `sendVerificationEmail` prints the link in the terminal: `[example] verify you@example.com: http://localhost:3000/api/auth/verify-email?token=…`. Open it in the same browser. If you signed up from an SP's sign-in, the link carries on to that SP.
- **In production**, nothing is sent until you implement `sendVerificationEmail` in `src/lib/auth.ts` with your email provider. The link is never logged outside development.

## The sign-in page

When an SP sends a signed-out user, the plugin redirects to `/sign-in?callbackURL=<its /saml2/idp/resume link>`. The page ([contract](../../docs/guide/flows.md#sp-initiated-sso)):
- after signing in, goes to `callbackURL` only if it's on this origin (anything else goes to `/`);
- with `prompt=login` (the SP sent `ForceAuthn`), asks for credentials even when the user is signed in;
- when the user is already signed in and there's no `prompt=login`, continues to `callbackURL` straight away.

The IdP states `PasswordProtectedTransport` as the authentication class (`authnContextClassRef`), which many SPs request by default. That's only true over HTTPS: deploy behind TLS. An SP that asks for another class (for example MFA) gets `NoAuthnContext` from the IdP straight away, without the sign-in page: this example has no step-up, like the Workers example. For step-up, declare [`authnContext.levels`](../../docs/guide/flows.md#requestedauthncontext); the IdP then sends users to the page with `acr_values`, which it must honour.

## Register service providers

SPs come from `SAML_SERVICE_PROVIDERS`, a JSON array in `.env.local` (or your host's environment). `pnpm keys` adds a test SP that doesn't exist, for the scripts below:

```sh
SAML_SERVICE_PROVIDERS='[{"id":"test-sp","entityId":"http://localhost:4000/saml/metadata","acsUrls":["http://localhost:4000/saml/acs"]}]'
```

Add your SP's entry next to it and restart the server. Each entry takes any JSON-representable SP option, including `attributes` as a declarative map (for example `"attributes": { "email": "email" }`). Without one, the example sends `email`, `name`, `firstName` and `lastName`; the NameID is the email. To build an entry from an SP's metadata:

```sh
npx better-auth-saml-idp sp-from-metadata https://sp.example.com/saml/metadata --id my-sp
```

Give the SP the IdP's metadata URL, or its entity ID, SSO URL and certificate. Step-by-step guides: [Cloudflare Access](../../docs/sp-cloudflare-access.md), [Okta](../../docs/sp-okta.md), [Auth0](../../docs/sp-auth0.md), [Salesforce](../../docs/sp-salesforce.md), [HubSpot](../../docs/hubspot.md), [AWS IAM Identity Center](../../docs/sp-aws-iam-identity-center.md), and [testing with other SPs](../../docs/testing-with-sps.md).

## Test it

With the server running (`pnpm dev`, or `pnpm build && pnpm start`), from `examples/nextjs`:

```sh
npx better-auth-saml-idp inspect http://localhost:3000 --allow-http     # the metadata SPs see
npx better-auth-saml-idp smoke http://localhost:3000 --allow-http \
  --sp http://localhost:4000/saml/metadata --acs http://localhost:4000/saml/acs   # 15 security checks
pnpm smoke     # CI's checks: metadata, the redirect to /sign-in?callbackURL=…, inspect and smoke
pnpm sso       # a full sign-in to the test SP, validated by @node-saml/node-saml
```

`pnpm sso` signs up a new user, then signs in and completes SP-initiated SSO. As a **test shortcut**, it marks the user's email verified directly in `data.db` instead of following the verification link, so it must run next to the server's database.

To try SSO by hand, build a request with `npx better-auth-saml-idp request http://localhost:3000 --allow-http --sp http://localhost:4000/saml/metadata --acs http://localhost:4000/saml/acs`, open the URL, sign in, and read the Response in the browser's network tab (the post to port 4000 fails, since nothing listens there). `npx better-auth-saml-idp decode` explains it.

## Deploy

Any Node host that keeps a writable disk works as is (a VM, a container with a volume). Set the variables above, run `pnpm db:migrate`, then `pnpm build && pnpm start`. With several instances or a serverless host, use a shared database instead of SQLite: pass Better Auth another [database](../../docs/guide/databases.md) in `src/lib/auth.ts`. The replay protection relies on UNIQUE constraints, so it needs a real database.

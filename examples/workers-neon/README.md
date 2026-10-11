# Example: Cloudflare Workers + Postgres on Neon (Hyperdrive)

A SAML IdP on Cloudflare Workers with Better Auth on **Postgres**, here [Neon](https://neon.tech), reached through [Hyperdrive](https://developers.cloudflare.com/hyperdrive/). It has a sign-in page and SPs configured from JSON, and nothing else. The [Workers + Hono example](../workers-hono/README.md) is the full demo on D1 (admin page, tenants, two-step sign-in, provisioning).

Verified live on 2026-10-11 (DECISIONS.md D-078): the plugin's `smoke` checks, a full SP-initiated sign-in validated by node-saml, a session deleted in Neon refused on the very next request, and 30 parallel requests, all on a deployed Worker. CI runs the same scripts against a local Postgres.

## Why Postgres instead of D1

D1 is simpler and is enough for the plugin. Choose Postgres when you need:
- **transactions**, for example Better Auth's own SCIM server (`@better-auth/scim`), which doesn't run on D1;
- **more data** than a D1 database holds, or reporting and backups with ordinary Postgres tools;
- **a database branch per preview or test run** (Neon branches).

## How it's built

- **[src/auth.ts](src/auth.ts)**: Better Auth on a `pg` pool, with email and password sign-in (verified emails only: the plugin asserts nothing else), and the plugin. Single-use values and rate limits are in Postgres.
- **[src/index.ts](src/index.ts)**: the Worker (Hono). Two things matter on Workers:
  - **Connections belong to one request.** Each request gets its own `pg` pool (at most 5 connections; Workers allow 6 per request), closed after the response once Better Auth's background work is done. Hyperdrive keeps the real connections to Neon open, so this is cheap.
  - **Better Auth is built once per isolate**, and reaches the current request's pool through `AsyncLocalStorage`. Building it per request also works, but costs about 25 ms of CPU on every request (measured: the metadata endpoint at 30 ms instead of 3).
- **No schema check at startup** (`validateSchema: false`): on Workers, a check started by one request and awaited by another can hang. `pnpm db:migrate` sets the schema up instead.
- **Smart Placement** (`placement` in wrangler.jsonc): Better Auth makes several queries per request, so the Worker should run near the database.

## Deploy

You need a Cloudflare account with Workers Paid (the first SAML request in an isolate compiles the XML schema validator, over the Free plan's CPU limit) and a Neon project.

1. **The database.** In Neon, take the **direct** connection string (not the pooled one: Hyperdrive pools). Create the tables, from this directory:

   ```sh
   pnpm keys                                   # .dev.vars: the settings the options need
   DATABASE_URL="postgres://…?sslmode=verify-full" pnpm db:migrate
   ```

   Run it again after upgrading Better Auth or the plugin. It's safe to repeat.

2. **Hyperdrive, with its query cache off.** Hyperdrive caches reads by default, and Better Auth's session lookup is a read: a revoked session would stay valid until the cache expires.

   ```sh
   npx wrangler hyperdrive create saml-idp --connection-string "postgres://…" --caching-disabled
   ```

   Paste its id into `wrangler.jsonc` (`hyperdrive[0].id`).

3. **Secrets and SPs.** Make the IdP's key pair once and keep it safe; rotating it means updating every SP.

   ```sh
   npx better-auth-saml-idp keygen --cn "my-idp" --cert-out idp.crt --key-out idp.key
   npx wrangler secret put SAML_IDP_PRIVATE_KEY < idp.key
   npx wrangler secret put SAML_IDP_CERT < idp.crt
   openssl rand -base64 32 | npx wrangler secret put BETTER_AUTH_SECRET
   rm idp.key                                  # after storing it somewhere safe
   ```

   Set `SAML_SERVICE_PROVIDERS` in `wrangler.jsonc` to a JSON array of SPs (`{ "id", "entityId", "acsUrls" }`, and any other option JSON can carry; see `SpJson` in src/auth.ts).

4. **Email.** Sign-up sends a verification link, and the plugin asserts only verified emails. Put your email provider in `sendVerificationEmail` (src/auth.ts) before real users sign up.

5. `pnpm deploy`. The IdP's entity ID is `https://<your-worker>/api/auth/saml2/idp`; its metadata is at `…/saml2/idp/metadata`. Check it:

   ```sh
   SMOKE_SP=<an SP's entityId> SMOKE_ACS=<its ACS URL> pnpm smoke https://<your-worker>
   ```

## Run it locally

With Postgres on `localhost:5432` (for example `docker run -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:17`):

```sh
pnpm -C ../.. build                      # the plugin's dist/, which this example imports
pnpm keys                                # .dev.vars with a throwaway key pair and a test SP
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres pnpm db:migrate
pnpm dev                                 # http://localhost:8787
```

`wrangler dev` connects to `localConnectionString` in wrangler.jsonc instead of Hyperdrive; `CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE` overrides it. Verification links are printed to the console (only with `DEV_PRINT_VERIFICATION_LINKS` from .dev.vars, and only on localhost).

Then, against the running Worker:

```sh
pnpm smoke                                                     # metadata, redirect, security checks
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres pnpm sso   # a full sign-in
```

`pnpm sso` marks its test user's email verified directly in the database (a test shortcut), so it needs `DATABASE_URL` too.

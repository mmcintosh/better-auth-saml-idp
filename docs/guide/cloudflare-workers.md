# Cloudflare Workers

[Guide](README.md) › Cloudflare Workers

The plugin runs on Workers with D1 through [`better-auth-cloudflare`](https://github.com/zpg6/better-auth-cloudflare). The [Workers + Hono example](../../examples/workers-hono/README.md) is a complete, deployable IdP; it's the live demo at `better-auth-saml-idp-example.mmcintosh-f61.workers.dev`, which serves Cloudflare Access sign-ins.

## Requirements

- `better-auth-cloudflare` ≥ 0.4 (Better Auth 1.7 support), and the `nodejs_compat` compatibility flag.
- **Workers Paid.** The first SAML request in an isolate compiles the XSD validator (WebAssembly). Measured: warm SSO about 16 ms CPU; cold 56 to 162 ms, which is over the Free plan's 10 ms. See [DECISIONS D-017](../../DECISIONS.md).
- D1 through Drizzle, with `validateSchema`.

## Put the plugin inside `withCloudflare`

```ts
betterAuth({
  ...withCloudflare(
    { d1: { db: drizzle(env.DB, { schema }), options: { usePlural: true } }, cf },
    {
      verification: { storeInDatabase: true },
      rateLimit: { storage: "database" },
      plugins: [samlIdp({ /* … */ })],   // ← here, in withCloudflare's second argument
    },
  ),
});
```

A `plugins: [...]` written **next to** `...withCloudflare(...)` replaces the Cloudflare plugin, which silently disables its storage validation, IP detection and geolocation.

## Background tasks: wire `waitUntil`

Work a Worker leaves running after the response can be cancelled. The plugin refreshes SP metadata in the background (and other Better Auth features use background tasks too), so give Better Auth the request's `waitUntil`:

```ts
import { AsyncLocalStorage } from "node:async_hooks";
const requestWaitUntil = new AsyncLocalStorage<(p: Promise<unknown>) => void>();

// in your Better Auth options
advanced: {
  backgroundTasks: {
    handler: (p) => {
      const waitUntil = requestWaitUntil.getStore();
      if (waitUntil) waitUntil(p);
      else p.catch(() => {});
    },
  },
},

// in the handler
app.all("/api/auth/*", (c) => requestWaitUntil.run((p) => c.executionCtx.waitUntil(p), () => auth.handler(c.req.raw)));
```

If a refresh does get cancelled, the plugin notices after 30 seconds and starts a new one, so it recovers either way; `waitUntil` just makes it reliable.

## Build Better Auth once per isolate

Parsing the key and compiling the validator are one-time costs per isolate, so don't build a new Better Auth instance per request. The example builds it once and passes each request's `cf` through `AsyncLocalStorage` (`withCloudflare` accepts a function for `cf`). See `examples/workers-hono/src/auth.ts`.

## Secrets and configuration

| Name | Kind | What |
|---|---|---|
| `BETTER_AUTH_SECRET` | secret | Better Auth's secret (also keys persistent NameIDs and SessionIndexes; changing it changes them). |
| `SAML_IDP_PRIVATE_KEY` | secret | The IdP's signing key (`keygen … \| wrangler secret put`). |
| `SAML_IDP_CERT` | secret or var | Its certificate. |
| `SAML_IDP_ADDITIONAL_CERTS` | secret or var | Concatenated PEMs published for rotation. |
| `SAML_SERVICE_PROVIDERS` | var | A JSON array of SPs, any JSON-representable SP option (attribute maps, `metadata`, `encryption`, `singleLogoutService`, `organization`…). |
| `SAML_REGISTRY_ADMINS` | var | Comma-separated emails that may use the registry API. |

Check a JSON configuration with `npx better-auth-saml-idp check-config`. Key rotation with `wrangler secret` is in [docs/key-rotation.md](../key-rotation.md#workers-deployments-examplesworkers-hono).

## D1 migrations

`examples/workers-hono/migrations/`:

| File | Adds |
|---|---|
| `0001_init.sql` | Better Auth's tables and the replay table |
| `0002_seen_request_key.sql` | The replay table's UNIQUE `key` (drop and recreate if upgrading from a pre-release) |
| `0003_service_providers.sql` | The registry table (`registry.enabled`) |
| `0004_session_participants.sql` | The Single Logout table (`singleLogout.enabled`) |
| `0005_audit_events.sql` | The audit-log table (`auditLog.enabled`) |

```bash
npx wrangler d1 migrations apply <db> --remote
```

## Don't use KV for sessions

Workers KV is eventually consistent, and Better Auth reads sessions from secondary storage before the database. A session revoked in D1 can live on in KV for a minute or more, at any location. An IdP must be able to revoke, so keep sessions in D1 and leave `session.cookieCache` off. If you use KV for other things, set `verification: { storeInDatabase: true }` so single-use values stay atomic. See [docs/security.md](../security.md).

## Checking a deployment

```bash
npx better-auth-saml-idp inspect https://<worker>.workers.dev
npx better-auth-saml-idp smoke https://<worker>.workers.dev --sp <SP entity ID>
npx wrangler tail <worker> --format pretty   # the plugin logs as [saml-idp]
```

# Cloudflare Workers

[Guide](README.md) › Cloudflare Workers

The plugin runs on Workers with D1 through [`better-auth-cloudflare`](https://github.com/zpg6/better-auth-cloudflare). The [Workers + Hono example](../../examples/workers-hono/README.md) is a complete, deployable IdP; it's the live demo at `better-auth-saml-idp-example.mmcintosh-f61.workers.dev`, which serves Cloudflare Access sign-ins.

## Requirements

- `better-auth-cloudflare` and the `nodejs_compat` compatibility flag. The plugin doesn't depend on `better-auth-cloudflare` itself; any version that supports Better Auth 1.7 works.
- With **0.3.1** (npm's current release) and Better Auth ≥ 1.7.3, keep single-use values out of KV: `verification: { storeInDatabase: true }` and `rateLimit: { storage: "database" }`. 0.3.1's KV storage has no atomic consume, and Better Auth 1.7 relies on one ([better-auth-cloudflare #72](https://github.com/zpg6/better-auth-cloudflare/issues/72)). The example does this. 0.4 checks it at startup.
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

Work a Worker leaves running after the response can be cancelled. The plugin does three things in the background: it runs your [event handlers](observability.md), writes the [audit log](observability.md), and refreshes SP metadata (and other Better Auth features use background tasks too). Without `waitUntil`, the first two are **lost** whenever the response goes out first, which for a sign-in is almost always. So give Better Auth the request's `waitUntil`:

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

Or, where you can't wrap the request (a framework that builds Better Auth for you, such as [CharDB](../../examples/chardb/README.md)), use the `waitUntil` that `cloudflare:workers` exports: `handler: (p) => waitUntil(p)`. Import it only in code that runs in the Worker; the CharDB example passes it in from its Worker entry, because CLI tools load its auth file outside the Worker.

A cancelled metadata refresh recovers by itself (the plugin starts a new one after 30 seconds). Events and audit rows don't: a dropped one is gone.

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
| `0006_api_decision_4_option_names.sql` | Rewrites stored SPs saved with the option names from before 1.0 (D-040) |
| `0007_participants_user_ended.sql` | `user_id` and `ended_at` on the Single Logout table (`events.onSessionEnded`) |
| `0008_tenants.sql` | The tenant table and tenant columns (`tenants.enabled`; see [Multi-tenant IdP](multi-tenant.md#database)) |
| `0009_tenant_keys.sql` | The tenant signing-key table (`tenants.keys: "per-tenant"`; see [Per-tenant signing keys](multi-tenant.md#per-tenant-signing-keys)) |

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

# better-auth-saml-idp

A [Better Auth](https://www.better-auth.com) plugin that turns your Better Auth server into a **SAML 2.0 Identity Provider**. It signs users in to SAML service providers such as HubSpot with SP-initiated SSO. It runs on **Cloudflare Workers** and **Node 20+**, with no Java and no native binaries.

> **Unofficial community plugin.** This project isn't affiliated with or endorsed by Better Auth.

> Status: pre-release. Phases 0–2 are done: runtime, plugin skeleton and SP-initiated SSO. Design decisions and evidence are in `DECISIONS.md`.

> [!WARNING]
> **Cloudflare Workers users: put `samlIdp()` inside `withCloudflare`'s second argument.** If you write `plugins: [...]` next to `...withCloudflare(...)`, your array **replaces** the Cloudflare plugin. That silently disables its storage validation, IP detection and geolocation. You also need `better-auth-cloudflare` **≥ 0.4**.

## Requirements

- `better-auth` `>=1.7.5 <1.8.0`
- A real database adapter (D1/Drizzle, Postgres, MySQL, SQLite…). Replay protection depends on primary-key enforcement.
- `verification.storeInDatabase: true` whenever secondary storage (for example KV) is configured
- On Workers: `better-auth-cloudflare` ≥ 0.4 and the `nodejs_compat` flag

## Cloudflare Workers (D1 + Drizzle)

```ts
import { betterAuth } from "better-auth";
import { withCloudflare } from "better-auth-cloudflare";
import { drizzle } from "drizzle-orm/d1";
import { samlIdp } from "better-auth-saml-idp";

export const createAuth = (env: Env, cf: IncomingRequestCfProperties) =>
  betterAuth({
    ...withCloudflare(
      { d1: { db: drizzle(env.DB, { schema }), options: { usePlural: true } }, cf },
      {
        verification: { storeInDatabase: true },
        rateLimit: { storage: "database" },
        plugins: [
          samlIdp({
            entityId: "https://auth.example.com/api/auth/saml2/idp",
            loginPage: "/sign-in",
            signing: { privateKey: env.SAML_IDP_PRIVATE_KEY, certificate: env.SAML_IDP_CERT },
            serviceProviders: [
              {
                id: "hubspot",
                entityId: "<from HubSpot's SSO settings>",
                acsUrls: ["<from HubSpot's SSO settings>"],
                attributes: (user) => ({ email: user.email }),
              },
            ],
          }),
        ],
      },
    ),
  });
```

Add the plugin's table to your Drizzle schema. Field maps use Drizzle **property keys**, not column names:

```ts
export const samlIdpSeenRequests = sqliteTable(
  "saml_idp_seen_requests",
  {
    id: text("id").primaryKey(),
    spId: text("sp_id").notNull(),
    requestId: text("request_id").notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [
    uniqueIndex("saml_idp_seen_requests_sp_request_uq").on(t.spId, t.requestId),
    index("saml_idp_seen_requests_expires_idx").on(t.expiresAt),
  ],
);
```

Expired rows are cleaned up as new requests arrive. If an IdP gets little traffic, you can also delete rows with `expires_at < now` on a cron.

## Endpoints

All endpoints are relative to your Better Auth base path, e.g. `/api/auth`.

| Method | Path | |
|---|---|---|
| GET | `/saml2/idp/metadata` | IdP metadata, to give to the SP |
| GET, POST | `/saml2/idp/sso` | Receives AuthnRequests (HTTP-Redirect and HTTP-POST bindings) |
| GET | `/saml2/idp/resume?rid=` | Where the login page returns the user (`callbackURL`) |

The login page gets `?callbackURL=<absolute resume URL>`. After a successful sign-in, send the browser there.

## Security

See [docs/security.md](docs/security.md) for the threat model, host configuration requirements (don't use KV for sessions; leave `cookieCache` off) and known limitations.

## Development

```sh
pnpm test          # Node (node:sqlite) + workerd (D1/Drizzle, validateSchema on)
pnpm test:wasm     # the libxml2 WASM validator, Node + workerd
pnpm typecheck
scripts/use-better-auth.sh latest-1.7   # run the suite against another Better Auth version
```

## License

MIT © Mark McIntosh. Third-party components (libxml2 in `wasm/xsd.wasm`, and the OASIS/W3C schemas) are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

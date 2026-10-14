# better-auth-saml-idp

Turn your [Better Auth](https://www.better-auth.com) server into a **SAML 2.0 Identity Provider**, and sign your users in to Microsoft 365, Google Workspace, Okta, Salesforce, AWS and other SAML 2.0 service providers (HTTP-Redirect and HTTP-POST bindings). Runs on **Cloudflare Workers** and **Node 22+**, with no Java and no native binaries.

[![CI](https://github.com/mmcintosh/better-auth-saml-idp/actions/workflows/ci.yml/badge.svg)](https://github.com/mmcintosh/better-auth-saml-idp/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/better-auth-saml-idp)](https://www.npmjs.com/package/better-auth-saml-idp)
[![Better Auth](https://img.shields.io/badge/better--auth-%E2%89%A51.7.5%20%3C1.8-black)](https://www.better-auth.com)
[![Runs on](https://img.shields.io/badge/runs%20on-Workers%20%7C%20Node%2022%2B%20%7C%20Bun%20%7C%20Deno-f38020)](docs/guide/README.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

📖 **[Read the guide](docs/guide/README.md)**: getting started, every option, every error code, security controls, schema, Single Logout, `@better-auth/sso` interop, Cloudflare Workers, the CLI and troubleshooting.

**Try it:**

- **Example IdP (Workers + Hono + D1)**: [better-auth-saml-idp-example.mmcintosh-f61.workers.dev](https://better-auth-saml-idp-example.mmcintosh-f61.workers.dev/), which signs users in to Microsoft 365, AWS IAM Identity Center, Cloudflare Access, Okta, Auth0 and Salesforce, verified live
- **Feature comparison with eleven SAML IdPs**: [mmcintosh.github.io/better-auth-saml-idp/comparison](https://mmcintosh.github.io/better-auth-saml-idp/comparison/)

> **Unofficial community plugin.** This project isn't affiliated with or endorsed by Better Auth. Status: **stable, 1.x** on npm (`npm install better-auth-saml-idp`), following semantic versioning: the npm badge above shows the current version, and the [CHANGELOG](CHANGELOG.md) what changed.

If it's useful to you, a ⭐ on [GitHub](https://github.com/mmcintosh/better-auth-saml-idp) helps others find it.

## ✨ Features

- 🔐 **SAML 2.0 IdP**: SP-initiated SSO over HTTP-Redirect and HTTP-POST, and IdP-initiated SSO as an opt-in per SP.
- ✍️ **Signing done right**: Response and Assertion signed with RSA-SHA256 (SHA-1 only by opt-in), a per-SP signing choice, optional signed metadata, and [zero-downtime key rotation](docs/key-rotation.md).
- 🔒 **Encrypted assertions**: AES-256-GCM with RSA-OAEP per SP, signed before encryption.
- 🛡️ **Hardened input**: every message is checked against the OASIS XSDs by a libxml2 WebAssembly build that also runs on Workers. DOCTYPEs are refused, DEFLATE output is capped, and duplicate or encoded parameters are rejected.
- ✅ **Signed AuthnRequests** over Redirect *and* POST, with defences against XML signature wrapping. Each defence was mutation-checked when written, and is fuzzed on every CI run.
- 🔁 **Replay protection** you can check: a database unique key, tested under concurrency across separate instances.
- 🗄️ **Your database**: proven in CI on PostgreSQL, MySQL, MongoDB, SQLite and Cloudflare D1, through Kysely, Drizzle and Prisma, and experimentally on [CharDB](https://github.com/zpg6/chardb) (Durable Objects) ([Databases](docs/guide/databases.md)).
- 🎲 **Fuzz-tested**: property-based tests throw hostile input at every inbound parser (AuthnRequest, LogoutRequest, LogoutResponse, SP metadata, raw XML) and the signature verifier, and hostile user data at issuance ([design notes](DECISIONS.md)).
- 📦 **Supply chain**: SHA-pinned actions, CodeQL, dependency audits, OpenSSF Scorecard, the [OpenSSF Best Practices](https://www.bestpractices.dev/projects/15268) passing badge, and a release workflow that publishes with npm provenance and an SBOM ([SECURITY.md](SECURITY.md)).
- 👤 **Strict identity**: only verified emails get assertions; impersonated and anonymous sessions are refused; the user and session are re-read right before signing. The NameID can come from a user field (an employee number), but only from fields users can't change themselves.
- 🪜 **Step-up authentication**: declare your levels (password, MFA…) and what each session achieved; when an SP asks for more, the user is sent back to sign in with `acr_values`, as Keycloak does with levels of authentication ([guide](docs/guide/flows.md#requestedauthncontext)).
- 🚦 **Your access rules**: a per-SP `authorize` hook that can deny with a reason or send the user to sign in again (for example when their MFA is too old).
- 🚪 **Single Logout**: SP- and IdP-initiated, propagated through the browser to every SP that received an assertion in the session. When a session ends without it (an admin disables a user, a factor changes), `onSessionEnded` names the SPs still signed in, so you can act on them ([guide](docs/guide/single-logout.md#when-the-session-ends-without-the-browser)).
- 🗂️ **SP registry**: add, change, disable and remove SPs at runtime through an admin-gated API that logs every change with the acting user, or configure them in code. The example includes [reference admin pages](examples/workers-hono/README.md#admin-pages) to copy.
- 🔄 **Metadata refresh**: SP certificates stay current from their metadata URL, while the entity ID and ACS URLs stay pinned.
- 🏢 **Better Auth native**: organization-scoped SPs and org attributes (organization plugin), optionally an [IdP identity per organization](docs/guide/multi-tenant.md) (its own entity ID, metadata and URLs), registry permissions through the admin plugin's access control, a typed client plugin, and tables generated by `npx auth generate`. With `@better-auth/sso` in the same app, it's an [identity broker](docs/guide/better-auth-sso.md#one-app-both-roles-an-identity-broker): users sign in with their company's IdP and reach your SAML-only tools.
- 🎟️ **Assertion exchange for OAuth tokens**: opt an SP in, and an agent holding one of its assertions can trade it for tokens at an OAuth authorization server on the same Better Auth instance, once each (RFC 8693, draft ID-JAG §4.5, the flow MCP's Enterprise-Managed Authorization uses). The plugin vouches for its own assertions: signature, issuer and tenant, the mapped client, single use across instances, and the user as they are now ([guide](docs/guide/token-exchange.md)).
- 📈 **Observability**: `onAssertionIssued`, `onAssertionExchanged`, `onDenied`, `onLogout` and `onSessionEnded` callbacks for audit trails and SIEM, and an optional audit-log table with retention ([guide](docs/guide/observability.md)).
- 🧩 **Attribute mapping**: a declarative map (fields, constants, lists, first/last name) or a function.
- 🧰 **CLI**: `npx better-auth-saml-idp` inspects, decodes and verifies messages, smoke-tests, validates config and generates keys.
- ☁️ **Runs where your app runs**: a Better Auth plugin, not a separate server. The whole suite runs on Node and Cloudflare Workers (D1); the published package is smoke-tested on Bun and Deno in CI. [Benchmarked on Workers and D1](docs/benchmark.md): about 260 ms and 20 ms of CPU per sign-in. Examples: [Workers + Hono](examples/workers-hono/README.md), [Next.js](examples/nextjs/README.md), and [CharDB](examples/chardb/README.md) with a React or an [Astro](examples/chardb-astro/README.md) front end (experimental).


## 📚 Table of Contents

> The full documentation is the **[guide](docs/guide/README.md)**. This README is the overview.

- [Quick Start](#-quick-start)
- [Tested and verified](#-tested-and-verified)
- [Installation](#-installation)
- [Requirements](#requirements)
- [Setup (Cloudflare Workers + D1)](#-setup-cloudflare-workers--d1)
  - [1. Create a signing key](#1-create-a-signing-key)
  - [2. Add the tables to your schema](#2-add-the-tables-to-your-schema)
  - [3. Configure Better Auth](#3-configure-better-auth)
  - [4. Return users from your sign-in page](#4-return-users-from-your-sign-in-page)
  - [5. Register a service provider](#5-register-a-service-provider)
  - [6. Check it](#6-check-it)
- [Configuration Options](#-configuration-options)
- [Usage](#-usage)
  - [Endpoints](#endpoints)
  - [Attributes](#attributes)
  - [Signing and encryption](#signing-and-encryption)
  - [IdP-initiated SSO](#idp-initiated-sso)
  - [Single Logout](#single-logout)
  - [Organizations and permissions](#organizations-and-permissions)
  - [Client plugin](#client-plugin)
  - [Managing SPs at runtime (registry)](#managing-sps-at-runtime-registry)
  - [Keeping SP certificates current](#keeping-sp-certificates-current)
  - [Registering an SP from its metadata](#registering-an-sp-from-its-metadata)
  - [Exchanging assertions for OAuth tokens](#exchanging-assertions-for-oauth-tokens)
- [Command-line tool](#-command-line-tool)
- [How it compares](#-how-it-compares)
- [What's next](#-whats-next)
- [Security](#-security)
- [Development](#-development)
- [License](#license)
- [Contributing](#contributing)

## ⚡ Quick Start

```bash
npm install better-auth-saml-idp
npx better-auth-saml-idp keygen --cert-out idp.crt --key-out idp.key   # signing key (mode 0600) and certificate
```

Add the plugin to your Better Auth config, with the key and certificate loaded from your secret store:

```ts
import { betterAuth } from "better-auth";
import { samlIdp } from "better-auth-saml-idp";

export const auth = betterAuth({
  // database, emailAndPassword, … as you have them
  plugins: [
    samlIdp({
      entityId: "https://auth.example.com/api/auth/saml2/idp",
      baseURL: "https://auth.example.com",
      loginPage: "/sign-in", // your sign-in page; it sends users back to callbackURL
      signing: {
        privateKey: process.env.SAML_IDP_PRIVATE_KEY!,
        certificate: process.env.SAML_IDP_CERT!,
      },
      serviceProviders: [], // filled in below
    }),
  ],
});
```

```bash
npx auth migrate   # create the tables (Drizzle or Prisma: npx auth generate, then your migration)

# Check what SPs will see, turn an SP's metadata into a serviceProviders entry, then run the smoke test:
npx better-auth-saml-idp inspect https://auth.example.com
npx better-auth-saml-idp sp-from-metadata https://sp.example.com/saml/metadata --id my-app
npx better-auth-saml-idp smoke https://auth.example.com --sp <the SP's entity ID>
```

The [Getting started guide](docs/guide/getting-started.md) walks through each step. On Cloudflare Workers, follow [Setup (Cloudflare Workers + D1)](#-setup-cloudflare-workers--d1) instead: the key goes straight into a Worker secret.

The [Workers + Hono example](examples/workers-hono/README.md) is a complete, deployable IdP with a sign-in page, D1 migrations and SPs configured from JSON. The [Next.js example](examples/nextjs/README.md) is the same on Node: App Router, `node:sqlite`, and a sign-in page that honours `callbackURL` and `prompt=login`. The [Workers + Neon example](examples/workers-neon/README.md) runs on Postgres through Hyperdrive instead of D1.

## ✅ Tested and verified

**CLI:**

- [x] `inspect`: what SPs see in your metadata: certificates, expiry, schema, signature
- [x] `decode`: explain and verify a captured SAMLRequest/SAMLResponse, and decrypt it with `--key`
- [x] `request`: build a test AuthnRequest, signed or unsigned, for either binding
- [x] `smoke`: 15 security checks against a deployed IdP
- [x] `sp-from-metadata`: a `serviceProviders` entry from SP metadata
- [x] `check-config`: run the plugin's validation on your options
- [x] `keygen`: signing key and certificate, piped straight into your secret store

**Verified with** (live tests are run by hand; each has its date and evidence in [DECISIONS.md](DECISIONS.md)):

- [x] Cloudflare Access: live, with signed requests, encrypted assertions, metadata refresh and key rotation
- [x] Okta: live (Integrator org as SP), signed requests verified, plain and encrypted assertions, SP stored in the D1 registry ([guide](docs/sp-okta.md))
- [x] Auth0: live (Enterprise SAML connection), signed requests over both Redirect and **POST (XML signature)** verified with a certificate learned from Auth0's metadata URL, encrypted assertions, first/last name attributes ([guide](docs/sp-auth0.md))
- [x] Salesforce: live (Developer Edition), signed requests required and verified (its ~300-character request IDs found a real bug, fixed), the NameID matched to the Federation ID, **Single Logout both ways**, SP stored in the D1 registry ([guide](docs/sp-salesforce.md))
- [x] Keycloak 26.8 and SimpleSAMLphp 2.5: real Chromium over HTTPS, in CI
- [x] node-saml, samlify and `@better-auth/sso`: in CI, on Node and workerd, including an **identity broker** (`@better-auth/sso` upstream and this plugin downstream in one Better Auth, [guide](docs/guide/better-auth-sso.md#one-app-both-roles-an-identity-broker))
- [x] SAMLtool: Response validation
- [x] AWS IAM Identity Center: live (multi-Region instance), the access portal and the AWS console in an assigned permission set, SP stored in the D1 registry ([guide](docs/sp-aws-iam-identity-center.md))
- [x] Google Workspace: live (an SSO profile assigned to one organizational unit), sign-in to Google through the IdP, with the users created and suspended by [better-auth-scim-provisioning](https://www.npmjs.com/package/better-auth-scim-provisioning) ([guide](docs/sp-google-workspace.md))
- [x] Microsoft 365 (Entra ID domain federation): live (a spare domain federated with Graph PowerShell), sign-in to My Apps through the IdP with a persistent NameID matched to `onPremisesImmutableId`, and the IdP's MFA class (`multipleauthn`) sent. In a test tenant: Microsoft took it as MFA (per-user MFA and Conditional Access), asked for its own MFA after a password-only sign-in, and signing out at Microsoft ended the IdP session. A user added after federating (Graph `POST /users` with `onPremisesImmutableId`, no password) signed in on the first try ([guide](docs/sp-microsoft-365.md))
- [ ] HubSpot: guide written ([HubSpot](docs/hubspot.md)), not yet run live

**Databases, in CI:**

- [x] PostgreSQL 17, MySQL 8.4 and MongoDB 8.2 (replica set): the database-dependent behaviours (replay protection under concurrency, single use, registry, logout participants, memberships, the sweep, the audit log)
- [x] SQLite (Node) and Cloudflare D1 via Drizzle (workerd): the whole suite
- [x] Drizzle on PostgreSQL and MySQL, and Prisma on PostgreSQL: the adapter matrix, in CI
- [x] CharDB 0.1 (Durable Objects), experimental: the [example](examples/chardb/README.md)'s flow (tenants, per-tenant keys, replay protection) in workerd, weekly in CI; not the whole suite

## 📦 Installation

```bash
npm install better-auth-saml-idp
# or
pnpm add better-auth-saml-idp
```

### Requirements

- `better-auth` and `@better-auth/core` `>=1.7.5 <1.8.0` (peer dependencies)
- A real database adapter (D1/Drizzle, Postgres, MySQL, SQLite…). Replay protection depends on UNIQUE constraints.
- `verification.storeInDatabase: true` whenever secondary storage (for example KV) is configured
- On Workers: `better-auth-cloudflare` and the `nodejs_compat` flag. With Better Auth ≥ 1.7.3, set `verification: { storeInDatabase: true }` and `rateLimit: { storage: "database" }`: with KV configured, `better-auth-cloudflare` 0.4.0 fails every request without them, naming the fix, and 0.3.1 silently breaks single-use values ([better-auth-cloudflare #72](https://github.com/zpg6/better-auth-cloudflare/issues/72)).

## ⛅ Setup (Cloudflare Workers + D1)

### 1. Create a signing key

```bash
npx better-auth-saml-idp keygen --cert-out idp.crt | npx wrangler secret put SAML_IDP_PRIVATE_KEY
npx wrangler secret put SAML_IDP_CERT < idp.crt
```

`keygen` never prints a private key to a terminal. It writes the key to a pipe, as here, or to `--key-out` with mode 0600.

### 2. Add the tables to your schema

The plugin's tables, with the UNIQUE constraints replay protection depends on, come from Better Auth's CLI: `npx auth generate` writes them into your Drizzle schema for whatever options you enable. On D1, the example's [migrations](examples/workers-hono/migrations/) create every table, in order. Each table, column and index is listed in [Schema](docs/guide/schema.md).

### 3. Configure Better Auth

> [!WARNING]
> **Cloudflare Workers: put `samlIdp()` inside `withCloudflare`'s second argument.** A `plugins: [...]` next to `...withCloudflare(...)` **replaces** the Cloudflare plugin, which silently disables its storage validation, IP detection and geolocation.

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
            baseURL: "https://auth.example.com", // pin the IdP's own URLs (same value as Better Auth's baseURL)
            loginPage: "/sign-in",
            // What your sign-in guarantees; matched against SPs' RequestedAuthnContext.
            authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            signing: { privateKey: env.SAML_IDP_PRIVATE_KEY, certificate: env.SAML_IDP_CERT },
            serviceProviders: [
              {
                id: "my-app",
                entityId: "<the SP's entity ID>",
                acsUrls: ["<the SP's ACS URL>"],
                attributes: { email: "email" },
              },
            ],
          }),
        ],
      },
    ),
  });
```

**Defaults to know about:**
- Only users with a **verified email** receive assertions, and admin-impersonation sessions and anonymous users are refused (`accountPolicy`).
- The NameID follows each SP's `nameIdFormat`: the email for `emailAddress`, an opaque per-SP ID for `persistent`, and a one-time ID for `transient`.
- Requests the IdP can't satisfy get a **signed SAML error Response**: IsPassive without a session, an unsatisfiable RequestedAuthnContext, or a Subject mismatch.

### 4. Return users from your sign-in page

Unauthenticated users are sent to `loginPage?callbackURL=<absolute resume URL>`. After a successful sign-in, send the browser to that `callbackURL`, and the IdP finishes the SAML exchange.

### 5. Register a service provider

Give the SP your metadata URL, `https://auth.example.com/api/auth/saml2/idp/metadata`. Take its entity ID and ACS URL, or its metadata, and add an entry to `serviceProviders`, or store it at runtime with the [registry](#managing-sps-at-runtime-registry). Step-by-step guides: [Microsoft 365](docs/sp-microsoft-365.md) · [Google Workspace](docs/sp-google-workspace.md) · [Okta](docs/sp-okta.md) · [Auth0](docs/sp-auth0.md) · [Salesforce](docs/sp-salesforce.md) · [AWS IAM Identity Center](docs/sp-aws-iam-identity-center.md) · [Cloudflare Access](docs/sp-cloudflare-access.md) · [HubSpot](docs/hubspot.md) (not yet verified live) · [testing with other SPs](docs/testing-with-sps.md).

To also create, update and switch off the accounts at those apps, pair it with [better-auth-scim-provisioning](https://www.npmjs.com/package/better-auth-scim-provisioning): see [Sign-in and provisioning](docs/guide/provisioning.md). Verified live together with Cloudflare Access, Google Workspace and AWS IAM Identity Center.

### 6. Check it

```bash
npx better-auth-saml-idp inspect https://auth.example.com
npx better-auth-saml-idp smoke https://auth.example.com --sp <SP entity ID>
```

## 🔧 Configuration Options

**`samlIdp({ ... })`**

| Option | Type | Default | Description |
|---|---|---|---|
| `entityId` | string | (required) | The IdP entity ID, usually `https://<host>/<basePath>/saml2/idp` |
| `baseURL` | string | Better Auth's `baseURL`, else request host | Pins the IdP's own URLs (metadata, Destination check, resume links). Same value and rule as Better Auth's `baseURL` (`basePath` is added to a bare origin). **Pin one of the two** |
| `loginPage` | string | (required) | Path or absolute URL of your sign-in page; it receives `callbackURL` |
| `signing.privateKey` / `.certificate` | PEM | (required) | RSA ≥ 2048 key and its certificate. Or `signing: { managed: true }`: the plugin makes, stores and rotates the key ([details](docs/guide/signing-and-encryption.md#a-key-the-plugin-manages)) |
| `signing.additionalCertificates` | PEM[] | `[]` | Published but not used to sign (rotation) |
| `signing.signatureAlgorithm` / `.digestAlgorithm` | string | `rsa-sha256` / `sha256` | SHA-1 also needs `allowInsecureSha1` |
| `signing.sign` | `"both"` / `"response"` / `"assertion"` | `"both"` | What to sign: the Response, the Assertion, or both. Each SP can override |
| `serviceProviders` | array | (required) | See the next table |
| `registry` | object | off | `{ enabled, canManage?, permissions?, cacheSeconds?, authorize? }` [database registry](#managing-sps-at-runtime-registry) |
| `tenants` | object | off | An IdP identity per organization: its own entity ID, metadata and URLs ([multi-tenant guide](docs/guide/multi-tenant.md)) |
| `singleLogout` | object | off | `{ enabled: true }` [Single Logout](#single-logout) |
| `tokenExchange` | object | off | `{ enabled: true }` lets stored SPs carry `tokenExchange`; an SP in code with it turns exchange on by itself ([Exchanging assertions](#exchanging-assertions-for-oauth-tokens)) |
| `events` | object | none | `{ onAssertionIssued?, onAssertionExchanged?, onDenied?, onLogout?, onSessionEnded? }` background callbacks ([Observability](docs/guide/observability.md)); `onSessionEnded` also turns on session tracking |
| `auditLog` | object | off | `{ enabled, retentionDays? }` records events in the `samlIdpAuditEvent` table |
| `signMetadata` | boolean | `false` | Sign the metadata document |
| `sessionNotOnOrAfter` | `false` / `"idp-session"` / `{ maxSeconds }` | `false` | Tell SPs when to end their session; each SP can override it ([Single Logout](docs/guide/single-logout.md#when-the-session-ends-without-the-browser)) |
| `authnContextClassRef` | string | `…:unspecified` | What your sign-in guarantees |
| `authnContext` | object | none | Step-up levels instead: `{ levels, current }`; an SP asking for more sends the user to sign in again. `current` gets the user, session, SP and request ([guide](docs/guide/flows.md#requestedauthncontext)) |
| `accountPolicy` | object | strict | `requireEmailVerified: true`, `allowImpersonatedSessions: false`, `allowAnonymousUsers: false` |
| `assertionLifetimeSeconds` | number | `300` | Assertion validity window |
| `clockSkewSeconds` | number | `60` | Tolerance for `NotBefore` and `IssueInstant` |
| `pendingRequestTtlSeconds` | number | `600` | How long a request waits for the user to sign in |
| `relayStateMaxBytes` | number | `4096` | 80 is the spec; real SPs send more (Cloudflare Access over 1000) |
| `schema` | object | none | Rename tables and columns, as with other Better Auth plugins |
| `schemaValidator` | object | libxml2 WASM | Replace the XSD validator |

**Each service provider**

| Option | Type | Default | Description |
|---|---|---|---|
| `id` | string | (required) | Your name for the SP (logs, `/init?sp=`, registry) |
| `entityId` | string | (required) | Matched exactly against the AuthnRequest `Issuer` |
| `acsUrls` | string[] | (required) | Allow-list; a requested ACS URL must match exactly |
| `nameIdFormat` | string | `emailAddress` | Or `persistent`, `transient`, `unspecified`, or a full NameID format URN; the short names stand for the standard URNs |
| `nameId` | function or `{ field }` | per format | Custom NameID value; `{ field }` works for stored SPs too, and only takes fields users can't set |
| `attributes` | map or function | none | [Attributes](#attributes) |
| `authorize` | function | allow | Decide per user and SP (gets `organizations` and the re-read session); `true`, or `{ allow: false, reason?, reauthenticate? }` to deny or send the user to sign in again |
| `organization` | object | none | `{ slug \| id, roles? }`: [members only](#organizations-and-permissions) |
| `tenant` | string | none | The tenant this SP belongs to, with `tenants` on ([multi-tenant guide](docs/guide/multi-tenant.md)) |
| `requestSignatures` | `"require"` / `"verify-if-signed"` / `"ignore"` | `"verify-if-signed"` with certificates, else `"ignore"` | Signatures on the SP's requests (Redirect or POST) |
| `spCertificates` | PEM or PEM[] | none | The SP's signing certificates (several during its rotation) |
| `metadata` | object | none | `{ url, refreshSeconds?, signingCertificates? }` [refresh certificates](#keeping-sp-certificates-current) |
| `encryption` | object | none | `{ certificate, dataAlgorithm?, keyAlgorithm?, allowInsecureCbc? }` [encrypt assertions](#signing-and-encryption) |
| `singleLogoutService` | object | none | `{ url, binding?, responseUrl? }` where the SP takes logout messages ([Single Logout](#single-logout)) |
| `sessionNotOnOrAfter` | as the server option | server option | Per-SP override |
| `sign` | as `signing.sign` | global | Per-SP signing choice |
| `allowIdpInitiated` | boolean | `false` | [IdP-initiated SSO](#idp-initiated-sso) |
| `idpInitiatedRelayState` / `allowedRelayStates` | string / string[] | none | RelayState for IdP-initiated SSO (exact-match allow-list) |
| `tokenExchange` | object | none | `{ clientId }`: this OAuth client may exchange this SP's assertions for tokens, once each ([Exchanging assertions](#exchanging-assertions-for-oauth-tokens)) |

Run `npx better-auth-saml-idp check-config config.json` to validate options and see every warning.

## 🚀 Usage

### Endpoints

All paths are relative to your Better Auth base path, for example `/api/auth`.

| Method | Path | |
|---|---|---|
| GET | `/saml2/idp/metadata` | IdP metadata, to give to the SP |
| GET, POST | `/saml2/idp/sso` | Receives AuthnRequests (HTTP-Redirect and HTTP-POST) |
| GET | `/saml2/idp/resume?rid=` | Where the sign-in page returns the user (`callbackURL`) |
| GET | `/saml2/idp/init?sp=<id>` | IdP-initiated SSO, for SPs with `allowIdpInitiated` |
| GET, POST | `/saml2/idp/slo` | [Single Logout](#single-logout): SPs' LogoutRequests and LogoutResponses (both bindings) |
| GET | `/saml2/idp/logout?returnTo=` | IdP-initiated logout: every SP, then back to `returnTo` |
| GET, POST | `/saml-idp/service-providers/*` | [Registry API](#managing-sps-at-runtime-registry), only with `registry.canManage` or `registry.permissions` |

### Attributes

Each SP's `attributes` is a function `(user) => ({ ... })` or a declarative map, which also works from JSON:

```ts
attributes: {
  email: "email",                                 // a user field
  role: "role",                                   // additional fields too (e.g. the admin plugin's)
  groups: { field: "teams", split: "," },         // one field → several values
  firstName: { field: "name", part: "first" },    // "Ada King Lovelace" → "Ada"
  lastName: { field: "name", part: "last" },      //                     → "King Lovelace"
  org: { value: "Acme" },                         // a constant
}
```

Missing, null and empty values are left out, dates become ISO 8601, and arrays become several values. A field the user doesn't have is logged once, so a typo shows up in the logs.

### Signing and encryption

- **Signing.** Response and Assertion are both signed by default. Each SP can choose with `sign: "response"` or `"assertion"`. `signMetadata: true` signs the metadata document.
- **Encryption per SP.** `encryption: { certificate }` sends `<saml:EncryptedAssertion>`, using AES-256-GCM with RSA-OAEP, signed before encryption and wrapped in a signed Response.
  - `dataAlgorithm` also takes `aes128-gcm`, or `aes256-cbc` together with `allowInsecureCbc: true`.
  - `keyAlgorithm: "rsa-oaep-sha256"` is available, but node-saml and samlify can't decrypt it.
  - RSA PKCS#1 v1.5 isn't offered.
  - Verified live with Cloudflare Access ([guide](docs/sp-cloudflare-access.md#5-encrypt-assertions-optional)).
- **Signed requests.** With the SP's `spCertificates` (or its `metadata.url`), a signed request must verify and an unsigned one is still accepted (`"verify-if-signed"`). Set `requestSignatures: "require"` to refuse unsigned ones. Without certificates, signatures aren't checked (`"ignore"`).
  - Redirect-binding signatures are verified over the exact query octets.
  - POST-binding signatures are enveloped XML signatures, accepted only when they cover the request's own unique ID with allow-listed algorithms and one of the SP's configured certificates ([design notes](DECISIONS.md)).

### IdP-initiated SSO

Off by default. Turn it on per SP to put "launch this app" links in your own UI:

```ts
{
  id: "my-app",
  entityId: "…",
  acsUrls: ["…"],
  allowIdpInitiated: true,
  idpInitiatedRelayState: "https://app.example.com/",         // optional: where the SP should land the user
  allowedRelayStates: ["https://app.example.com/reports"],    // optional: caller RelayStates accepted, exact match
}
```

Link to `/api/auth/saml2/idp/init?sp=my-app`.
- **No session:** the user signs in first.
- **SP support:** the Response has no `InResponseTo`, so the SP must accept unsolicited Responses. Cloudflare Access doesn't.
- **RelayState:** a caller's value is used only if it's on `allowedRelayStates`. Anything else is replaced, so a launcher link can't become an open redirect at the SP.

Read the [security notes](docs/security.md#idp-initiated-sso) before you enable it.

### Single Logout

```ts
samlIdp({
  // ...
  singleLogout: { enabled: true }, // adds the saml_idp_session_participants table (D1 migrations 0004, 0007, 0014)
  serviceProviders: [
    { id: "app", entityId: "…", acsUrls: ["…"], spCertificates: "…",
      singleLogoutService: { url: "https://app.example.com/saml/slo" } }, // binding: "redirect" (default) or "post"
  ],
});
```

**What happens:**
- The IdP remembers which SPs received an assertion in each session.
- When one SP sends a LogoutRequest to `/saml2/idp/slo`:
  1. The IdP ends its own session first, so it's over even if a later step breaks. That's the session the request's `SessionIndex` names, found on the server when the request comes without its cookie: Microsoft 365 sends it from a hidden iframe, where browsers never send the cookie.
  2. It sends a signed LogoutRequest through the browser to each other SP that has a `singleLogoutService`.
  3. It answers the originating SP with a signed LogoutResponse: `Success`, or `PartialLogout` if an SP failed or couldn't be reached.
- `/saml2/idp/logout?returnTo=/` does the same from your own "sign out everywhere" button. `returnTo` must be a same-origin path or a trusted origin.

**Authentication:**
- An SP with certificates must sign its LogoutRequests (Redirect or POST, with the same hardened checks as AuthnRequests).
- An SP without certificates ends a session only with its `SessionIndex`. That value is different for every SP and every session (a keyed MAC), so one SP's value can't end the session in another SP's name. Any other request ends nothing.
- An SP that requires signed AuthnRequests, or gets its certificates from `metadata.url`, must also sign its logout messages. If its certificates aren't available, they're refused.
- LogoutRequests are replay-protected.
- A cross-site drive-by to `/logout` gets a confirmation page.

Front-channel logout is best effort by nature: if an SP never sends the browser back, the chain stops there. The IdP session is already over by then.

### Organizations and permissions

With Better Auth's **organization plugin**:

```ts
{ id: "zoom", entityId: "…", acsUrls: ["…"],
  organization: { id: "org_8f3…", roles: ["admin", "member"] }, // members only (with one of these roles)
  attributes: {
    email: "email",
    groups: { organization: "slugs" },                           // this SP's organization only
    roles: { organization: "roles" },                            // roles in it
  } }
```

Users can create organizations by default and name them anything, so match rules by `id`, not `slug`. For an SP without an `organization` rule, limit organization attributes with `only` ([details](docs/guide/users-and-access.md#organizations)).

`authorize({ user, organizations, serviceProvider })` receives the memberships for custom rules. An SP with an `organization` rule is refused if the organization plugin isn't installed.

With the **admin plugin**, registry access can use Better Auth's access control instead of, or as well as, `canManage`:

```ts
import { createAccessControl } from "better-auth/plugins/access";
import { adminAc, defaultStatements, userAc } from "better-auth/plugins/admin/access";
import { samlIdpStatements } from "better-auth-saml-idp";

const ac = createAccessControl({ ...defaultStatements, ...samlIdpStatements });
const roles = {
  admin: ac.newRole({ ...adminAc.statements, samlServiceProvider: ["list", "read", "create", "update", "delete"] }),
  auditor: ac.newRole({ samlServiceProvider: ["list", "read"] }),
  user: ac.newRole({ ...userAc.statements }),
};
// admin({ ac, roles }), then samlIdp({ registry: { enabled: true, permissions: true } })
```

### Client plugin

```ts
import { samlIdpClient } from "better-auth-saml-idp/client";
const authClient = createAuthClient({ plugins: [samlIdpClient()] });

await authClient.samlIdp.serviceProviders.create({ serviceProvider: { id: "my-app", entityId: "…", acsUrls: ["…"] } });
authClient.samlIdp.signOutEverywhere({ returnTo: "/" }); // Single Logout, every SP
authClient.samlIdp.launch("my-app");                     // IdP-initiated SSO
```

Tables: `npx auth generate` (Better Auth's CLI) generates the plugin's tables, with their UNIQUE constraints, for whatever you enable.

### Managing SPs at runtime (registry)

```ts
samlIdp({
  // ...
  registry: {
    enabled: true,                                  // adds the saml_idp_service_providers table
    canManage: ({ user }) => user.role === "admin", // mounts the API (as does permissions: true); omit both to manage rows yourself
  },
});
```

| Method | Path | |
|---|---|---|
| GET | `/saml-idp/service-providers` | List SPs, code and stored, each a `ServiceProviderRecord` with any issues and warnings |
| GET | `/saml-idp/service-providers/get?id=` | One SP, code or stored |
| POST | `/saml-idp/service-providers/create` | `{ serviceProvider, enabled? }` |
| POST | `/saml-idp/service-providers/update` | `{ id, serviceProvider, enabled? }`: full replacement; the id can't change |
| POST | `/saml-idp/service-providers/delete` | `{ id }` |

**How stored SPs behave:**
- They're plain JSON: the same options as in code, minus functions.
- They're validated on every write *and* every read, so a row edited by hand into an invalid config is ignored and reported.
- SPs defined in code always win.
- Each isolate caches lookups for `cacheSeconds` (default 60), including misses.

**Who can use the API:**
- A signed-in user whose session is re-read from the database and that `canManage` approves (and, with `permissions: true`, the admin plugin's access control). A demoted admin loses access at once, even with Better Auth's cookie cache on.
- Impersonated sessions are refused.
- Origin checks apply, and every change is logged with the acting user.

### Keeping SP certificates current

```ts
{ id: "cf-access", entityId: "https://TEAM.cloudflareaccess.com/cdn-cgi/access/callback",
  acsUrls: ["https://TEAM.cloudflareaccess.com/cdn-cgi/access/callback"],
  requestSignatures: "require",
  metadata: { url: "https://TEAM.cloudflareaccess.com/cdn-cgi/access/saml-metadata" } }
```

The SP's signing certificates, plus its encryption certificate when `encryption` is on, are refreshed from its metadata, daily by default.
- **Only certificates are taken.** The entity ID must match, and ACS URLs always come from your config, so a compromised metadata URL can't redirect assertions.
- **Failures are safe.** Certificates you configure stay trusted, and a failed fetch keeps the last good copy.
- **Pinning.** Pin the metadata's own signature with `metadata.signingCertificates` when the SP signs it.
- **Verified live** with Cloudflare Access, with no certificates configured.

### Registering an SP from its metadata

```ts
const { serviceProvider, warnings } = await serviceProviderFromMetadata(metadataXml, {
  id: "cf-access",
  attributes: { email: "email" },
});
```

The result gives you the entity ID, HTTP-POST ACS URLs (default first), NameID format and signing certificates, plus `requestSignatures: "require"` if the SP asks for it. The document is XSD-validated first, but its own signature is **not** checked, so review the result before you pin it. The CLI equivalent is `sp-from-metadata`.

### Exchanging assertions for OAuth tokens

An agent that signed a person in through this IdP holds a SAML assertion. With assertion exchange, it can trade that assertion at your OAuth token endpoint for tokens (RFC 8693 with a SAML 2.0 subject token; [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) §4.5). The token endpoint is an authorization server plugin (an ID-JAG issuer) on the same Better Auth instance; this plugin answers the one question only the IdP can: *did I issue this assertion, to the SP this client stands for, and has it not been exchanged before?*

```ts
{ id: "agent", entityId: "https://agent.example.com/saml", acsUrls: ["https://agent.example.com/saml/acs"],
  tokenExchange: { clientId: "agent-oauth-client" } }
```

- Each assertion to that SP is recorded at sign-in (Better Auth's verification table; no new table) and can be exchanged **once**, by that client, before it expires.
- The token endpoint calls `getSamlIdpExchange(ctx).verifyIssuedAssertion(ctx, assertionXml, { clientId })`. It checks the signature (XSW-hardened, the identity's own key), the issuer and tenant, the exact shape, the time window, the SP's client, single use, and the user, session and membership as they are now, without any outbound request. Failures throw `AssertionExchangeError` with a code.
- Every exchange emits `assertion.exchanged`. Tenant administrators can't set or change `tokenExchange`. SPs without it are unaffected.

See [Exchanging assertions for OAuth tokens](docs/guide/token-exchange.md).

## 🧰 Command-line tool

```bash
npx better-auth-saml-idp inspect https://auth.example.com
npx better-auth-saml-idp decode "<URL or SAMLResponse=… copied from the browser>" --idp https://auth.example.com --sp <SP entity ID>
npx better-auth-saml-idp smoke https://auth.example.com --sp <SP entity ID>
```

| Command | What it does |
|---|---|
| `inspect <idp-url>` | What SPs see in your metadata: entity ID, SSO URLs, certificates and expiry, schema validity, and the metadata signature (`--cert` pins it) |
| `decode [input]` | Explains a captured SAMLRequest or SAMLResponse: a URL, form body, base64 or XML, as an argument, a file or `-` for stdin. It verifies signatures with the same code as the IdP and checks time windows, Audience, Recipient and InResponseTo. `--key` decrypts |
| `request <idp-url> --sp <id>` | Builds an AuthnRequest URL, or an HTML form with `--binding post`. `--passive`, `--force-authn`, `--name-id-format`, `--authn-context`, `--relay-state`, `--sign-key` |
| `smoke <idp-url> --sp <id>` | 15 security checks against a deployed IdP. It needs no user, and the only rows it leaves are short-lived ones |
| `sp-from-metadata <file\|url>` | A `serviceProviders` entry as JSON on stdout |
| `check-config <file>` | The plugin's validation on a `.json` config (PEMs as `"file:./idp.crt"`) or a `.js`/`.mjs` module |
| `keygen --cert-out idp.crt` | RSA key and self-signed certificate. The key goes to `--key-out` (mode 0600) or to a pipe, never a terminal |

Every command takes `--json`. Exit codes are 0 for OK, 1 when a check failed, and 2 for a usage error. The CLI never needs your IdP's private key.

## 📊 How it compares

A feature-by-feature comparison with Shibboleth, SimpleSAMLphp, Keycloak, Zitadel, authentik, Logto, Ory Polis, Entra ID, Okta, Google Workspace and Auth0, with sources: **[interactive comparison](https://mmcintosh.github.io/better-auth-saml-idp/comparison/)** (or [docs/comparison.md](docs/comparison.md)).

[![Feature comparison with Shibboleth, SimpleSAMLphp, Keycloak, Zitadel, authentik, Logto, Ory Polis, Entra ID, Okta, Google Workspace and Auth0](docs/assets/comparison.png)](https://mmcintosh.github.io/better-auth-saml-idp/comparison/)

<!-- roadmap:start (generated by scripts/comparison/gen.py) -->
## 🧭 What's next

The 1.x line covers everything on the [roadmap](https://mmcintosh.github.io/better-auth-saml-idp/comparison/#roadmap) derived from a feature comparison with eleven other SAML identity providers (checked 2026-09-25).

**Not planned:**

- 🚫 **Artifact binding**: Of the products compared, only Keycloak supports it fully (Shibboleth and SimpleSAMLphp for responses); no target SP needs it.
- 🚫 **Admin UI in the plugin**: Better Auth plugins are headless; hosts build their own UI on the registry API, and the example has a reference page to copy.

What shipped in each release is in the [CHANGELOG](CHANGELOG.md).
<!-- roadmap:end -->

## 🔒 Security

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/mmcintosh/better-auth-saml-idp/badge)](https://scorecard.dev/viewer/?uri=github.com/mmcintosh/better-auth-saml-idp)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15268/badge)](https://www.bestpractices.dev/projects/15268)
[![Socket](https://socket.dev/api/badge/npm/package/better-auth-saml-idp)](https://socket.dev/npm/package/better-auth-saml-idp)
[![CodeQL](https://github.com/mmcintosh/better-auth-saml-idp/actions/workflows/codeql.yml/badge.svg)](https://github.com/mmcintosh/better-auth-saml-idp/actions/workflows/codeql.yml)

- [docs/security.md](docs/security.md) has the threat model, host requirements (don't use KV for sessions; leave `cookieCache` off) and known limitations.
- [docs/key-rotation.md](docs/key-rotation.md) describes the zero-downtime rotation procedure.
- [DECISIONS.md](DECISIONS.md) has every security-relevant design decision, with its tests and mutation proofs.

Please report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes, not in public issues. It also covers the supply chain:
- actions pinned by SHA;
- CodeQL, runtime dependency audits, OSV-Scanner and OpenSSF Scorecard;
- npm provenance and a CycloneDX SBOM with every release.

Versioning, Better Auth compatibility and support windows are in [Versioning and support](docs/guide/versioning.md).

## 🧪 Development

```bash
pnpm test          # Node (node:sqlite) + workerd (D1/Drizzle, validateSchema on)
pnpm test:wasm     # the libxml2 WASM validator, Node + workerd
pnpm e2e           # Playwright + Chromium: Keycloak, SimpleSAMLphp (Docker) and a node-saml SP
pnpm lint          # Biome (recommended + security rules)
pnpm typecheck
pnpm pack:check    # dist build, publint, Are the Types Wrong
scripts/use-better-auth.sh latest-1.7   # run the suite against another Better Auth version
```

CI runs all of these, plus a gitleaks scan of the whole history, on Node 24 with Better Auth 1.7.5 and the latest 1.7.x, and on Node 22 with 1.7.5. It also builds and starts the [Next.js example](examples/nextjs/README.md) and signs in through it. [CONTRIBUTING.md](CONTRIBUTING.md) has the rest: the adapter matrix, fuzzing, e2e, conventions and releasing.

## License

MIT © Mark McIntosh. Third-party components (libxml2 in `wasm/xsd.wasm`, and the OASIS/W3C schemas) are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Contributing

Contributions are welcome: bug reports, [SP interop reports](https://github.com/mmcintosh/better-auth-saml-idp/issues/new?template=sp-interop.yml) (especially "it works with X"), fixes and features. For anything significant, please open an issue first. See [CONTRIBUTING.md](CONTRIBUTING.md): security-sensitive changes come with tests that fail without the change, as in [DECISIONS.md](DECISIONS.md).

# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-09-28

The first stable release, on npm's `latest` tag. It's 1.0.0-rc.2 with the changes below; the full feature list is under 1.0.0-rc.1 and 1.0.0-rc.2 in the [CHANGELOG](https://github.com/mmcintosh/better-auth-saml-idp/blob/main/CHANGELOG.md). From here on, [Versioning and support](https://github.com/mmcintosh/better-auth-saml-idp/blob/main/docs/guide/versioning.md) applies. better-auth-cloudflare 0.4 isn't needed: with 0.3.1, keep verification and rate limits in the database, as the Workers guide says. Support for 0.4 comes in a 1.x minor release.

### Changed

- Dependencies: the xml-crypto range now starts at 6.3.2.

### Documentation

- **AWS IAM Identity Center verified live** (D-054): a multi-Region instance accepted our assertion, with the access portal and the AWS console in an assigned permission set. The [guide](docs/sp-aws-iam-identity-center.md) now covers the several ACS URLs AWS publishes (one per Region, on `signin.aws` and `sso.signin.aws`), registering AWS from its metadata on the admin page, and what AWS doesn't do (signed requests, Single Logout).

## [1.0.0-rc.2] - 2026-09-28

### Added

- **Multi-tenant IdP, phase 1** (`tenants: { enabled: true }`, off by default; [guide](docs/guide/multi-tenant.md), D-052): an IdP identity per Better Auth organization, next to the root IdP.
  - A tenant has its own entity ID (its metadata URL), metadata, and SSO and SLO URLs at `/saml2/idp/{metadata,sso,slo}/<tenantKey>`. In this phase every tenant signs with the root `signing` key.
  - The host's administrators create tenants through the registry API (`authClient.samlIdp.tenants.*`, `samlTenant` in `samlIdpStatements`); nothing is created automatically. `tenantKey` is the organization id unless another is chosen (not another organization's id), and never changes.
  - A tenant is bound to the organization it was made for, by id and creation time: once that organization is gone, even deleted straight from the database, or its id is given to a new organization (serial ids on SQLite and D1), the tenant answers nothing. Deleting the organization through Better Auth also disables its tenant. A deleted tenant's key is retired and never used again, since SPs set up for it still trust its entity ID (D-053).
  - SPs join a tenant with `tenant` (in code or stored). They're found only through their tenant's URLs, and only the organization's members may sign in to them (`organization` may only add `roles`). Entity IDs are unique per tenant, so one SP (AWS, Google) can be in several.
  - Persistent NameIDs of tenant SPs differ per tenant; the root's are unchanged.
  - Single Logout reaches every tenant's SPs in the session, each from its own tenant's identity.
  - `tenantId` in events (every refusal that names a tenant's SP included), the audit log (a new column), `ServiceProviderInfo`, and registry records (with tenants on).
  - Startup errors: tenants without the organization plugin, `registry.enabled` or a pinned `baseURL`; `tenants.delegation` (it needs per-tenant keys, which come in phase 2).
  - Database: the `samlIdpTenant` and `samlIdpRetiredTenantKey` tables and `tenantId`/`lookupKey` on `samlIdpServiceProvider`, only with tenants on. A registry that already has rows needs a one-time step: [the guide](docs/guide/multi-tenant.md#database) and `auth.api.samlIdpBackfillServiceProviderKeys()`, which pages through the table and reports rows it couldn't write (`failed`). On MongoDB, `backfillMongoServiceProviderKeys(db)` instead, before turning tenants on. D1: the example's migration `0008_tenants.sql`.
  - New error codes for the tenant API: `INVALID_TENANT`, `TENANT_EXISTS`, `TENANT_NOT_FOUND`, `TENANT_HAS_SERVICE_PROVIDERS`, `TENANT_KEY_RETIRED`.
  - With `tenants` unset, schema, routes and every response are unchanged (pinned by snapshots recorded before the change). Additive only: `serviceProviderInfo.tenantId` (`null`) in `authorize`, the `samlTenant` resource in `samlIdpStatements`, the five error codes and the `backfillMongoServiceProviderKeys` export.
- **Next.js example** ([`examples/nextjs`](examples/nextjs/README.md)): App Router on the Node runtime with `node:sqlite`, a sign-in page that honours `callbackURL` and `prompt=login`, and a migration script. CI builds it, starts it with `next start`, runs the CLI's `inspect` and `smoke` checks against it and completes a sign-in with node-saml as the SP.

## [1.0.0-rc.1] - 2026-09-28

The first release. Release candidates are published to npm under the `next` tag (`npm install better-auth-saml-idp@next`). 1.0.0 follows as `latest` once `better-auth-cloudflare` 0.4 is on npm, since Workers users on its current 0.3.1 need two settings (see [Cloudflare Workers](docs/guide/cloudflare-workers.md)).

### Added

- **SAML 2.0 IdP plugin for Better Auth.**
  - SP-initiated SSO: AuthnRequests over HTTP-Redirect and HTTP-POST; Responses over HTTP-POST (a request for the HTTP-Redirect `ProtocolBinding`, as Auth0 sends, is answered over POST).
  - IdP-initiated SSO, opt-in per SP. RelayState comes only from an allow-list, and a cross-site launch without a user click gets a confirmation page.
  - IdP metadata at `/saml2/idp/metadata`, optionally signed (`signMetadata`).
- **Signing:** Response and Assertion signed with RSA-SHA256 by default (`signing.sign: "both" | "response" | "assertion"`, per SP too). SHA-1 needs an explicit opt-in. Extra certificates are published for [key rotation](docs/key-rotation.md).
- **Encrypted assertions per SP:** AES-256-GCM with RSA-OAEP, signed before encryption.
- **Signed requests per SP** (`requestSignatures: "require" | "verify-if-signed" | "ignore"`; the default follows whether the SP has certificates). HTTP-Redirect query signatures, and enveloped XML signatures over HTTP-POST with signature-wrapping defences. `spCertificates` takes one PEM or several, for the SP's key rotation.
- **SP metadata:** `serviceProviderFromMetadata()` builds an SP entry from its metadata XML. A metadata URL keeps an SP's signing and encryption certificates current; the entity ID and ACS URLs stay pinned, and the metadata signature can be pinned (`metadata.signingCertificates`).
- **Users and access:**
  - Account policy: a verified email is required; impersonated sessions and anonymous users are refused. The user and session are re-read right before signing.
  - NameID per format (emailAddress, persistent, transient), or from a user field for any SP (`nameId: { field }`). Only fields users can't set themselves are accepted.
  - Declarative attribute maps (field, constant, split list, first/last name, organization data), so SPs can be configured in JSON.
  - `authorize` per SP: `true`, or `{ allow: false, reason?, reauthenticate? }`. The reason goes to the `denied` event; `reauthenticate` sends the user back to sign in (`prompt=login`) and asks again, with `NoPassive` for passive requests and no loops.
  - Organization plugin: organization-scoped SPs and organization attributes.
- **Step-up authentication** (`authnContext: { levels, current }`): an SP's RequestedAuthnContext (exact, minimum, better, maximum) is judged against the class this session achieved. When more is needed, the user is sent to sign in again (`prompt=login`, `acr_values`), as Keycloak does with levels of authentication.
- **Protocol:** ForceAuthn, IsPassive, RequestedAuthnContext (or step-up, above), and signed SAML error Responses for requests the IdP can't satisfy. Request IDs up to 1024 characters (Salesforce's are about 300).
- **Single Logout:** SP- and IdP-initiated, front-channel propagation to every SP in the session, `PartialLogout` reporting, and authenticated LogoutRequests (signature, or the per-session SessionIndex). `sessionNotOnOrAfter` (global and per SP) tells SPs when to end their own session.
- **Personal data:** a deleted user's session-participant rows (with their NameIDs) are removed with the user.
- **Sessions that end without Single Logout** (an admin revoke or disable, a factor change, `/sign-out`, expiry): `events.onSessionEnded` names the SPs that weren't told, even when the delete runs outside a request, and the server-only `auth.api.samlIdpListSessionParticipants` lists a user's SP sessions.
- **Database-backed SP registry** with an admin-gated API (`authClient.samlIdp.serviceProviders.*`): add, change, disable and remove SPs without a redeploy (`update` with only `{ id, enabled }` flips the switch without re-validating). Every call returns the same `ServiceProviderRecord`, with issues and warnings. Permissions through a function (`canManage`) or admin-plugin access control (`samlIdpStatements`).
- **Observability:** `events.onAssertionIssued`, `onDenied`, `onLogout` and `onSessionEnded`, which run in the background and can't affect the flow, and an optional audit-log table with retention.
- **Client plugin** (`better-auth-saml-idp/client`): `authClient.samlIdp.signOutEverywhere()`, `launch()` and the registry calls.
- **Configuration:** `baseURL` takes the same value as Better Auth's. Invalid options and key material are refused at startup with every issue listed (`SamlIdpConfigError`); SP certificates are parsed at startup too.
- **Command-line tool** (`npx better-auth-saml-idp`): `inspect`, `decode` (signature verification and decryption), `request`, `smoke`, `sp-from-metadata`, `check-config` and `keygen`.
- **Cloudflare Workers:** runs on Workers with D1 through `better-auth-cloudflare`, with the XSD validator as WebAssembly. A Workers + Hono example includes D1 migrations and a reference admin page (`/admin`).
- **Public types:** an explicit list, including `SamlIdpOptions`, `ServiceProviderConfig`, `StoredServiceProviderConfig`, `ServiceProviderInfo`, `ServiceProviderRecord`, `AuthorizeResult`, `SignedParts`, `RequestSignaturePolicy`, `NameIdSource`, `SessionLimit`, the event types and `SamlIdpErrorCode`.
- **Verified with:**
  - live: Cloudflare Access, Okta, Auth0 and Salesforce (including Single Logout);
  - in CI: Keycloak 26.7, SimpleSAMLphp 2.5 and a node-saml POST-binding SP in real Chromium over HTTPS; `@better-auth/sso`, node-saml and samlify on Node and workerd, including an identity broker (`@better-auth/sso` upstream and this plugin downstream in one Better Auth).
- **The guide** (`docs/guide/`) with complete references for options, errors, security controls and schema. Links are checked in CI.
- **Project:** [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), issue forms, [versioning and support](docs/guide/versioning.md), and a release workflow with npm trusted publishing, staged publishing (approved by a maintainer with 2FA), provenance and a CycloneDX SBOM.

### Security

- **Inbound validation:** every message is validated against the OASIS XSDs (a WebAssembly build of libxml2 that runs on Workers), DOCTYPE is refused, and DEFLATE, size and nesting limits apply. Duplicate and percent-encoded parameters are rejected.
- **Replay protection:** single-use pending requests, and AuthnRequest IDs rejected on reuse by a database unique key.
- **Independent security reviews,** every finding fixed with a regression test (DECISIONS.md D-029, D-030, D-039), plus property-based fuzzing (fast-check) of the signature verifier and every inbound parser.
- **Supply chain:** every GitHub Action pinned by SHA, least-privilege tokens, CodeQL, a blocking runtime dependency audit, dependency review, OSV-Scanner, OpenSSF Scorecard, a secret scan over the full history, and a reproducible-build check of `wasm/xsd.wasm`.

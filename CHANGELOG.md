# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Project

- **Clean-up** ([D-083](DECISIONS.md#d-083-clean-up-after-170-internal-references-out-of-the-code-and-docs-2026-10-16)): references to internal documents that aren't in the repository (review finding IDs, `ADDENDUM-01`, `SPEC`, design sections, project phases) are gone from the source, the published type declarations, the docs, the examples and the workflows, and the pre-1.0 multi-tenant design document is removed; the [multi-tenant guide](docs/guide/multi-tenant.md) documents what was built.
- Development only: Prisma 7.10.1 brings deepmerge-ts 8 and mysql2 3.24, so the two `pnpm.overrides` that lifted them (GHSA-ggr8-5vv4-36mx, GHSA-3f6p-5ww8-9rcr, GHSA-rgwj-5xj2-c3m3) are gone, and `pnpm audit` stays clean without them. @cloudflare/vitest-plugin 1.4.3 reads Vitest 5's filesystem module cache, so both Vitest configs no longer turn it off.
- Development only: the development setup and the examples run Better Auth 1.7.12 (was 1.7.10). The CharDB examples run the plugin's 1.7.0 (was 1.6.0, now deprecated). The plugin's code is unchanged: none of 1.7.11's and 1.7.12's fixes touch what it uses, and the supported range (`>=1.7.8 <1.8.0`) already includes them.
- Development only: vite 8.3.4 (was 8.3.1), a dependency of Vitest, for three launch-editor advisories published 2026-10-20 (GHSA-587h-7wmj-h5pm, GHSA-r825-w8mm-5pxw, GHSA-698v-4r3x-3vcv). It is now a direct development dependency, so the lockfile holds one copy that Dependabot keeps current. Nothing the package ships uses it.
- Development only: `better-call` and `@better-fetch/fetch`, which Better Auth pins to exact versions, are exempt from pnpm's one-day minimum release age like Better Auth itself, so CI and the canary can install a new Better Auth release on its first day ([D-084](DECISIONS.md#d-084-better-call-and-better-fetch-exempt-from-the-one-day-wait-2026-10-20)).
- Development only: `examples-audit` (the examples' dependencies) is no longer a required check, so an advisory there is reported without blocking pull requests ([D-085](DECISIONS.md#d-085-examples-audit-is-no-longer-a-required-check-2026-10-21)).

## [1.7.0] - 2026-10-16

Better Auth 1.7.8 is now the minimum, which keeps installs off Better Auth versions with known security advisories, and Next.js apps that bundle the plugin get a clear error instead of failing every SAML request; everyone on 1.6.x should upgrade, along with Better Auth.

### Changed

- **Better Auth 1.7.8 is now the minimum** (the peer range is `>=1.7.8 <1.8.0`, was `>=1.7.5`). 1.7.7 fixed three Better Auth security advisories: a critical Magic Link account takeover ([GHSA-965c-763c-88jm](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm)), an OAuth Proxy sign-in as another user (GHSA-r4xp-prcw-77qf), and rate limits exceeded under concurrency on Drizzle and Postgres (GHSA-44jh-23m7-hpcf). 1.7.8 stopped `@better-auth/sso` accepting a reused SAML assertion under `generateId: "uuid"`. The plugin's own code isn't affected by any of them, but the Better Auth it runs in is, and npm refuses to install the plugin next to an older one. Upgrade Better Auth (and its `@better-auth/*` packages) to 1.7.8 or later; 1.7.10 is the latest. This is a minor release under a new rule in the [versioning policy](docs/guide/versioning.md#better-auth-compatibility): the floor may rise for security within a Better Auth minor (D-081).

### Fixed

- **Next.js: a clear error when the plugin is bundled.** A Next.js app (Turbopack, the default) that bundles the plugin answered 500 to every SAML request with a `TypeError` ("The \"path\" argument must be of type string … Received an instance of URL"): the bundler rewrites the path to the plugin's XSD validator (`wasm/xsd.wasm`) into a web path the server can't read. The error now says what to do, and [getting started](docs/guide/getting-started.md#1-install) and [troubleshooting](docs/guide/troubleshooting.md) say it up front: add `serverExternalPackages: ["better-auth-saml-idp"]` to `next.config`. The Next.js example already did; a copy of it built without the setting, installed from the packed tarball, reproduced the failure and now shows the message.

### Documentation

- **A shorter README** (about 170 lines, was 607), with a diagram of the sign-in at the top and a screenshot of a real Microsoft 365 sign-in handing the user to the example IdP. The README is now the overview: what it is, the features, the Quick Start, requirements, and a table of the service providers it's verified with and what was verified. The reference sections (the option tables, endpoints, attributes, signing, Single Logout, organizations, the registry, the CLI) live in the [guide](docs/guide/README.md), which already had them, with a table of where to find what. The guide's endpoint list gains the managed key's `/saml-idp/signing-keys` routes, and [getting started](docs/guide/getting-started.md) the defaults the README listed (verified email, NameID per format, signed error Responses). The release checklist asks for README changes only where the README's own sections change.
- **The [comparison](https://mmcintosh.github.io/better-auth-saml-idp/comparison/) rechecked on 2026-10-15**, with a new README image. This plugin's column is at 1.7: the managed key's rotation through the API makes key rotation a full yes, and Single Logout and MFA name Microsoft 365, verified live. Keycloak 26.8.1, Zitadel 4.19.5, authentik 2026.8.4, Logto 1.45 and SimpleSAMLphp 2.5.3.1 are the versions compared; Logto 1.44 added requiring signed AuthnRequests. The roadmap lists the managed key, Microsoft 365 and assertion exchange as done.
- The [Cloudflare Access guide](docs/sp-cloudflare-access.md) gives the RelayState default as 4096, as it has been since 1.1.1; it still said 1024.
- docs/security.md no longer calls `better-auth-cloudflare` 0.4 unreleased. [CONTRIBUTING](CONTRIBUTING.md#releasing-maintainers) says when releases are cut (every week or two, and at once for a security fix), and `pnpm release` now requires the sentence that opens each release, saying why it exists and who should upgrade.

### Examples

- The examples (Next.js, Workers + D1, Workers + Neon, and the experimental CharDB examples) and the development setup run Better Auth 1.7.10. CI tests 1.7.8, the lowest supported version, alongside the latest 1.7.x.
- **The CharDB examples** run the plugin's current release (1.6.0, was 1.2.0) and Better Auth 1.7.10 (was 1.7.6, below the new minimum), with CharDB's generated migration `v3` for the plugin's newer index (`samlIdpSessionParticipant_sessionIndex_idx`). A CharDB deployment of the example applies it on upgrade.
- **The Workers example** uses better-auth-scim-provisioning 1.3.0 and better-auth-cloudflare 0.4.1.

### Project

- The upstream canary also tests Better Auth's `beta` tag, where Better Auth publishes its prereleases (1.8.0-beta.0 on 2026-10-15). It had tested only `latest` and `next`, and `next` still points at 0.8.7-beta.5, so it would never have tried 1.8 before its release. A prerelease tag is skipped once `latest` has caught up with it.
- **Up to date before the release** ([D-082](DECISIONS.md#d-082-up-to-date-before-170-vitest-5-and-two-overrides-gone-2026-10-15)): Vitest 5 (its hold lifted, now that @cloudflare/vitest-plugin supports it); the `@better-auth/utils` override removed (it held the tests on 0.4.2 while every supported Better Auth requires 0.5.0) and the `sharp` override removed (no longer needed); xml-crypto 6.4.0 in the lockfile, which new installs already get (the published range stays `^6.3.3`; the plugin uses none of what it deprecates); patch and minor updates for development and the examples. The upstream watch reports Better Auth's `beta` prereleases too, and the decision log's index lists every decision again (it stopped at D-062).

## [1.6.0] - 2026-10-14

A signing key the plugin makes, stores and rotates itself, so a deployment needs no key made by hand, and Microsoft 365 users provisioned straight from Better Auth.

### Added

- **A signing key the plugin makes and keeps: `signing: { managed: true }`** ([guide](docs/guide/signing-and-encryption.md#a-key-the-plugin-manages), D-080). Instead of a PEM key and certificate in the options, the plugin generates the IdP's key the first time it's needed (RSA 3072, a two-year certificate) and stores it encrypted in `samlIdpTenantKey`, under Better Auth's secret or `signing.keyEncryptionSecret`. Concurrent first requests end up with one key. It's rotated in the same three steps as tenants' keys, through `/saml-idp/signing-keys`, `/rotate`, `/activate` and `/retire` (with `signing.minPublishedSeconds`, default 24 hours, before a next key can sign). These need a host manager, on the new `samlSigningKey` statement with `permissions`. Every step, and the first generation, is a `signing-key.changed` event (`events.onSigningKeyChanged`). A stored key that can't be used refuses sign-ins and metadata; nothing else ever signs instead. Tenants on the shared key sign with the managed key. A deployment can now start with no key made by hand, which a one-click install needs. Keys given as PEM work as before. **Switching an existing deployment:** without `signing.initialKey` (the current key, stored as the first one) the plugin makes a new key and SPs that trust the old certificate refuse its signatures ([how to switch](docs/guide/signing-and-encryption.md#switching-an-existing-deployment)). **Set `signing.keyEncryptionSecret`:** with Better Auth's secret, rotating it without keeping the old version makes the stored key unreadable and stops the IdP signing ([recovering](docs/guide/signing-and-encryption.md#recovering-a-managed-key)).
- **Error codes** `INVALID_SIGNING_KEY`, `SIGNING_KEY_EXISTS`, `SIGNING_KEY_NOT_FOUND` and `SIGNING_KEY_TOO_NEW`, for the managed key's routes.

### Changed

- **Types:** `SamlIdpOptions["signing"]` is now `SigningConfig | ManagedSigningConfig` (narrow on `managed`), `SamlIdpEvent` includes `SigningKeyChangedEvent`, and `samlIdpStatements` includes `samlSigningKey`. Code that switches exhaustively over events or statements gets a new case.

### Documentation

- **Microsoft 365: adding users after federating** ([guide](docs/sp-microsoft-365.md#3-link-each-user-to-their-better-auth-account), D-079). A user created on the federated domain with Graph `POST /users`, `onPremisesImmutableId` set to their Better Auth id and no password, signed in at My Apps through the IdP on the first try. The guide had said this works without showing how. It now has the request, and a row in the Graph API table.
- **Microsoft 365: provisioning, who may sign in, and two Graph surprises** ([guide](docs/sp-microsoft-365.md)). Step 3 points to [better-auth-scim-provisioning](https://www.npmjs.com/package/better-auth-scim-provisioning) 1.3.0's Entra ID target, which creates users with `onPremisesImmutableId` set and no password. Step 2 says how to let in only some users. "When something goes wrong" covers a deleted user blocking a new one with the same immutableId (the recycle bin, and how to restore), and a new user not yet found by id.

## [1.5.1] - 2026-10-12

A README for newcomers on any runtime, npm keywords for the verified SPs, and the Workers example on better-auth-cloudflare 0.4.0.

### Documentation

- **A README for newcomers on any runtime.** The Quick Start now works on Node as well as Workers (install, a key, a minimal config, the tables, then the CLI checks), and the Workers-only warning moved into the Workers setup. The examples use a generic SP instead of HubSpot, which isn't verified live yet. Setup step 2 starts from Better Auth's CLI and the example's migrations, with the hand-written tables in [Schema](docs/guide/schema.md). The verification lists sit after the Quick Start, and the roadmap became a short "What's next" (the full roadmap is on the comparison page). Fixed: Keycloak 26.8 (not 26.7) in CI, the CI matrix sentence, the better-auth-cloudflare settings (0.4.0, released 2026-10-12, requires them with KV; the README had said 0.4 wouldn't need them), and the guide links in step 5 (Okta, Auth0 and Salesforce added). The options tables gained `tenants` and the per-SP `tenant`.
- **npm keywords** name the verified SPs (Microsoft 365, Entra ID, Google Workspace, Okta, Salesforce) instead of HubSpot.

### Examples

- **The Workers example uses better-auth-cloudflare 0.4.0 from npm** (released 2026-10-12) instead of a vendored build of its main branch; 0.4.0 is that build plus the release commit. Its `verification.storeInDatabase` and `rateLimit.storage: "database"` settings stay: with KV configured, 0.4.0 fails every request without them, naming the fix. The plugin itself doesn't depend on better-auth-cloudflare.
- **Workers + Neon example** ([examples/workers-neon](examples/workers-neon/README.md), D-078): the plugin on Cloudflare Workers with Postgres on Neon through Hyperdrive, its query cache off. Better Auth is built once per isolate and each request gets its own `pg` pool (connections can't cross requests on Workers); building it per request cost about 25 ms of CPU on every request. Verified live (smoke checks, a full sign-in, a session deleted in Neon refused on the next request), and CI runs the same scripts under `wrangler dev` against Postgres.

## [1.5.0] - 2026-10-11

Signing out at Microsoft 365 now ends the IdP session, and authnContext.current() also gets the SP and its request.

### Added

- **`authnContext.current()` also gets the SP and its request** (`serviceProvider`, `requested`; D-077), so it can answer per SP. For example, an SP that asks for exactly `PasswordProtectedTransport` can get that class from an MFA session, instead of a sign-in round that can't help and then `NoAuthnContext`. Callbacks that ignore the new fields behave as before.

### Changed

- **The registry's overlap warning** (the same entity ID and ACS URL in two tenants) no longer says tenants share one signing key when `tenants.keys` is `"per-tenant"`. It now says each copy of the SP must trust only its own tenant's certificate (D-077).

### Fixed

- **Signing out at Microsoft 365 now ends the IdP session** (D-076). Microsoft sends its LogoutRequest from a hidden iframe on its sign-out page, and browsers never send the session cookie to a cross-site iframe, so the IdP found no session, answered `Success`, and the next Microsoft sign-in went through without asking. A LogoutRequest without the session's cookie (or with another session's) now ends the session its SessionIndex was issued for, found on the server. This browser's own session and cookie are left alone. The SessionIndex is unguessable and given only to that SP for that one session; whoever holds it can end that one session and nothing else.
  - **Database:** `sessionIndex` on `samlIdpSessionParticipant` gains an index, so the lookup isn't a table scan. D1: the example's migration `0014`. Without it, logout still works, more slowly on large tables. On **MySQL or SQL Server**, Better Auth's `migrate` won't index an existing `text` column: change it first (MySQL: `ALTER TABLE samlIdpSessionParticipant MODIFY sessionIndex varchar(255) NOT NULL;`, using your table and column names).

### Documentation

- **Microsoft 365 guide, from a second live test** (D-076, D-077): Microsoft relying on your IdP's MFA is verified with per-user MFA and with Conditional Access (security defaults off), and a password-only sign-in gets Microsoft's own MFA. New: sign-out, one Microsoft tenant per IdP entity ID (use a tenant of your IdP for a second one), the Graph API (`az rest`) route beside PowerShell, why the federation starts on `rejectMfaByFederatedIdp`, and what `AADSTS51004` usually means in a test.

### Examples

- **The Workers example's provisioning is on better-auth-scim-provisioning 1.0** (#73), with migration `0015` for its new columns (group links' `kind` and `subjectId`, links' `adopted`). A deployment that ran provisioning on 0.3 applies `0015` before deploying. Checked locally on D1 against a SCIM server: a user and an organization's group delivered, and the new columns written.
- **Passkeys in the Workers example** (Better Auth's `passkey` plugin, migration `0013`): add them on the home page, then "Sign in with a passkey", using the browser's own WebAuthn JSON helpers with no client library.
- **The sign-in level now comes from how the session was signed in**, not from the user's two-step setting. A session field (`auth_method`), set when the session is created, records password, authenticator code, backup code, passkey or impersonation, and the MFA class is sent only for the code and passkey ones. The Microsoft 365 guide's MFA snippet follows it.

## [1.4.0] - 2026-10-09

The audit log records the sign-in level sent to each service provider, and a new guide covers Microsoft 365 (Entra ID domain federation), verified live.

### Added

- **The `assertion.issued` event records the sign-in level sent** (`authnContextClassRef`, #65, D-075): the class `authnContext.current()` reported, or `authnContextClassRef` when step-up isn't configured. It's in the audit log's details too, so the log shows, for example, whether Microsoft 365 was told the user did MFA.

### Documentation

- **Microsoft 365 guide** ([docs/sp-microsoft-365.md](docs/sp-microsoft-365.md), D-075): Entra ID domain federation, verified live. It covers adding Microsoft by configuration (its metadata isn't schema-valid), linking users through `onPremisesImmutableId`, federating with Graph PowerShell, sending the `multipleauthn` class for MFA done at the IdP, and the security-defaults catch.

### Examples

- **Two-step sign-in in the Workers example** (#64): authenticator-app codes (Better Auth's `twoFactor`, migration `0012`), reported to SPs through `authnContext`. A password is `PasswordProtectedTransport`, a password plus a code is Microsoft's `multipleauthn`, which a Microsoft 365 domain federated with `acceptIfMfaDoneByFederatedIdp` is set to accept as MFA (Microsoft relying on it isn't verified yet; see the guide).
- **A QR code for two-step sign-in setup** in the Workers example, drawn by the Worker (`uqr`), so the key never goes to a third-party QR service.

## [1.3.0] - 2026-10-08

samlify is no longer a dependency: the plugin writes its metadata itself, byte for byte the same, so a user installs 6 packages instead of 13 and the bundled code roughly halves. No API or behaviour changes.

### Changed

- **samlify is no longer a dependency** (D-074). It was only used to build the IdP's metadata document, which the plugin now writes itself, byte for byte the same (tested against samlify's output for every option that changes it). A user now installs 6 packages instead of 13: gone are samlify, `node-rsa`, `@authenio/xml-encryption`, `xpath` 0.0.34, `xml`, `xml-escape`, `asn1`, `safer-buffer` and `escape-html`. The plugin's bundled code roughly halves (minified 993 KB → 523 KB, gzip 269 KB → 143 KB). No API or behaviour changes.

## [1.2.1] - 2026-10-08

Documentation release: no code changes. The package's README and docs catch up with 1.2.0's assertion exchange, the security notes gain a Hyperdrive warning, and two Workers-guide statements are corrected.

### Examples

- The CharDB examples run on React 19 (react, react-dom and their types together; `JSX.Element` becomes `ReactElement`, since React 19's types have no global `JSX`). Dependabot now proposes React's packages as one update, and leaves Vitest's next major alone until the Workers test plugin supports it.

### Project

- OSV-Scanner and Scorecard report no open vulnerabilities. The CharDB examples force `source-map-js` 1.2.2 (GHSA-68fv-2mgg-jv7q). `osv-scanner.toml` files record, with reasons and a re-check date, the advisories that have no update: npm's bundled dependencies in the release job (`.github/npm-cli`), and `http-cache-semantics` through Astro in the CharDB Astro example. None reach the published package.
- Every dependency install in CI goes through Socket Firewall, which blocks confirmed malware before it downloads (the release job included). pnpm 10.34.6 won't resolve a version less than a day old (`minimumReleaseAge`, Better Auth exempt), and Dependabot waits 3 days (D-073). The README shows Socket's package badge.
- `main` requires a pull request and 19 passing checks (the CI, CodeQL and dependency jobs) before anything merges, with no bypass (D-072).
- Next.js example scripts: `dev-keys.mjs` never replaces a `.env.local` that appeared after its check, and `sso.mjs` decodes HTML entities in one pass.

### Documentation

- Assertion exchange (1.2.0) in the README (features, options, a usage section), the security page, the errors page (each `AssertionExchangeError` code and whether it uses the assertion up), the schema page, and the threat model.
- The README shows the OpenSSF Best Practices badge (passing, project 15268). Its answers are kept in `.bestpractices.json`, which the badge site reads to pre-fill them.
- Each release now checks the docs against the changelog: a step in CONTRIBUTING.md's release list, and a checklist in the release pull request `pnpm release` opens.
- Cloudflare Workers guide and security notes: turn off Hyperdrive's query cache for an auth database (`--caching-disabled`): it kept a revoked session valid for 62.5 s. Also: `validateSchema: false` when Better Auth is built per request; `cf` as a function needs better-auth-cloudflare 0.4 (0.3.1 stores no geolocation then); and 0.4's storage check fires when Better Auth initializes, on the first request, not at deploy time.

## [1.2.0] - 2026-10-06

Adds assertion exchange: an SP can let one OAuth client trade its assertions for tokens, once each (draft ID-JAG §4.5, MCP's Enterprise-Managed Authorization). Nothing changes for SPs that don't opt in.

### Added

- **Assertion exchange** (D-071): an SP can let one OAuth client exchange its assertions for tokens, once each. This is RFC 8693 token exchange with a SAML 2.0 subject token, the flow in draft-ietf-oauth-identity-assertion-authz-grant §4.5 that MCP's Enterprise-Managed Authorization uses. Set `tokenExchange: { clientId }` on the SP; stored SPs also need the new server option `tokenExchange: { enabled: true }`. Each assertion to such an SP is recorded at sign-in. An authorization server on the same Better Auth instance (an ID-JAG issuer) checks it with `getSamlIdpExchange(ctx).verifyIssuedAssertion(ctx, assertionXml, { clientId })`. That checks the signature (XSW-hardened, the identity's own key), the issuer and tenant, the validity window, the SP's client, single use across instances, and the user, session and membership as they are now. Failures throw `AssertionExchangeError` with a code. A new `assertion.exchanged` event (`events.onAssertionExchanged`, audit log) records each exchange. A tenant's administrator can't set or change `tokenExchange`. Nothing changes for SPs that don't opt in. See [Exchanging assertions for OAuth tokens](docs/guide/token-exchange.md).

### Project

- The workerd tests run on `@cloudflare/vitest-plugin` 1.3.6, which replaces `@cloudflare/vitest-pool-workers` (0.22.0, last published 2026-09-18). It brings the current miniflare and wrangler, so the development-only `undici` override is gone. Vitest 5 waits for the plugin to support it.
- `sharp` 0.35.5 is forced (GHSA-wq5f-xc86-pv6w, high), at the root and in the CharDB examples. It comes with Miniflare, so it affects development and the examples only; nothing in the published package uses it.
- The release job stages with npm 12.2.0 (was 11.20.0).

## [1.1.4] - 2026-10-06

Requires xml-crypto 6.3.3, which fixes several canonicalization cases in signed XML; upgrade to pick it up if your lockfile still has 6.3.2. No API changes.

### Changed

- **xml-crypto 6.3.3 or later.** It fixes several canonicalization cases in signed XML (inherited namespace context, namespace values, processing instructions). Fresh installs already got it through `^6.3.2`; the minimum now makes sure. Every test, including the SP interop suite, passes on it.

### Project

- A weekly **Upstream watch** issue lists what Dependabot doesn't cover: Better Auth against the peer range, the vendored builds of unreleased upstream code, and updates held back on purpose (`upstream-watch.yml`).
- The adapter matrix runs **Prisma 7** (7.10, with `@prisma/adapter-pg` and the `prisma-client` generator, as `npx auth generate` writes it for Prisma 7) instead of Prisma 6. Prisma 7's CLI pins mysql2 3.15.3 (GHSA-3f6p-5ww8-9rcr, GHSA-rgwj-5xj2-c3m3), so a development-only override lifts it to 3.24.5. The Databases guide now says Prisma 7.
- The Upstream watch also lists each pnpm override with whether the package that needs it still does.

### Examples

- The CharDB examples run on CharDB's main branch (`e6cf5c9`) and better-auth-saml-idp 1.1.3. CharDB now keeps Better Auth's background work alive itself, so the examples' `src/background.ts` workaround is gone, and a replayed request no longer logs an uncaught SQLite error. Checked on a database created with the previous build: sessions, tenants, keys, SPs, used request IDs and audit rows carry over.

## [1.1.3] - 2026-10-05

Fixes from an external review of 1.1.2: nothing critical or high, but upgrade if you log client IPs, use tenant key rotation, or pass RelayState with line breaks. No API changes.

### Fixed

From an external review of 1.1.2 (nothing critical or high; D-065):
- **Events and the audit log read the client IP the way Better Auth does.** They took the left-most `X-Forwarded-For` entry without checking it, which any client can set. Now a valid IP only, and a multi-value header only through `advanced.ipAddress.trustedProxies`.
- **A retried tenant key activation finishes the activation.** Cut short after the active key moved to "previous", a retry retired the tenant's own old key and published the shared root certificate for that tenant.
- **`/saml2/idp/init` answers an unknown SP id and one that hasn't opted in alike** (`IDP_INITIATED_NOT_ALLOWED`), so SP ids and tenant keys can't be listed from outside. A missing `sp` is still `UNKNOWN_SERVICE_PROVIDER`.
- **RelayState goes back to the SP exactly as it came.** The form escaped it as XML, which dropped some characters and rewrote line endings. A RelayState with control characters, which a browser's form submission would change, is now refused (`INVALID_SAML_REQUEST`).
- **SP metadata up to 1 MiB is accepted, as documented.** The validator capped it at 128 KiB; protocol messages are still held to 128 KiB (`libxml2Validator({ maxMetadataBytes })`).

### Documentation

- The getting-started sign-in snippet only follows a `callbackURL` on the IdP's own origin. As written, a signed-in user opening `/sign-in?callbackURL=javascript:…` would have run it, and another site's URL redirected there.
- Corrected where the docs said something the code doesn't do: the replay key, the minimum better-auth-cloudflare version, when the registry API is mounted, ProtocolBinding, Redirect-bound XML signatures, InvalidNameIDPolicy's status, tenant metadata's certificate, the flow diagram's order, ForceAuthn's meaning, and resume links.
- A guide to using this plugin with better-auth-scim-provisioning, so your app both signs people in to its apps and keeps their accounts in step there (`docs/guide/provisioning.md`).
- A benchmark of sign-ins on Workers and D1, with the scripts to rerun it (`docs/benchmark.md`, `scripts/bench`). The Workers example gains a benchmark-only `RATE_LIMIT=off`.

### Project

- Releases are one merge: `pnpm release patch|minor|major` opens the release PR, and merging it tags the version and starts the release run (`tag-release.yml`). Publishing still waits for the two approvals.

### Examples

- The Workers example can also provision (better-auth-scim-provisioning, optional): set a SCIM app or Google Workspace target, apply migration 0011, and a **Users and apps** page shows each user's account at each app, the queue and the groups, with actions (add a test user, ban, re-sync, reconcile, …). A Cron Trigger, if added, delivers retries.
- The Workers example's pages are redesigned: one layout with a sidebar (the IdP's sections for admins, your apps for everyone), separate Overview, Service providers, Tenants and Activity pages, a matching sign-in page, light and dark themes, and user emails in the activity log. The styles and code are same-origin files, so the pages' CSP allows no inline code at all.

## [1.1.2] - 2026-10-04

A fix for Google Workspace, and any SP that names its NameID format: with `nameIdFormat` set to a short name as the README documents (`emailAddress`, `persistent`, `transient`), those sign-ins failed with `InvalidNameIDPolicy`. Upgrade if you set `nameIdFormat`; nothing else changes.

### Fixed

- **`nameIdFormat` short names now work.** The README documents `emailAddress`, `persistent` and `transient`, but they were compared as given against the URN an SP asks for, so an SP configured that way was refused with `InvalidNameIDPolicy` whenever it named a format. Google Workspace always does, so every Workspace sign-in failed. The short names (and `unspecified`) now stand for the standard URNs. A full URN is kept as it is; any other value is kept too, with a startup warning.
- A SAML error Response sent to an SP (`InvalidNameIDPolicy`, `NoAuthnContext`, `NoPassive`, …) is logged as a warning with its reason, not at debug level. SPs usually show only "couldn't sign you in", so this line is often the only way to see why.

### Documentation

- A guide for Google Workspace as a service provider, verified live: sign-in to Google through the IdP, with an SSO profile assigned to one organizational unit.
- The README lists CharDB (Durable Objects, experimental) with the other databases, as the databases guide does.
- The observability guide said a denial for a known SP is stored in the audit log. Only denials for a signed-in user are; the others go to `onDenied`, and SAML error Responses to the log.

## [1.1.1] - 2026-10-02

A fix for Cloudflare Access: every sign-in through it failed on 1.1.0 and earlier. Upgrade if you use Cloudflare Access; nothing else changes.

### Fixed

- **Cloudflare Access sign-ins failed with `RELAY_STATE_TOO_LONG`.** Cloudflare Access now sends a RelayState of over 1000 bytes (1069, up from about 200 when it was first tested), past the 1024-byte cap. The default and maximum `relayStateMaxBytes` is now 4096 (D-062). Found in a live test of a new deployment.

### Documentation

- **The CharDB example with an Astro front end** (`examples/chardb-astro`, experimental): the same Worker (CI checks the files are identical), with Astro pages at real URLs, a static sidebar and React islands. Both CharDB examples now keep `public/.gitkeep` through a web build, and CI builds their web apps.
- **Cloudflare Workers guide: without `waitUntil`, events and audit rows are lost,** not only SP metadata refreshes delayed. Found building the CharDB example, whose framework builds Better Auth without it; the guide now also shows `waitUntil` from `cloudflare:workers` for such hosts.
- **A CharDB example (experimental):** `examples/chardb`, a `chardb init` app that is also a multi-tenant IdP (tenants with per-tenant keys and delegation), with all the plugin's tables in CharDB's Catalog through CharDB's own migrations. A UI for organizations and invitations, tenants and their keys, SPs, and the audit log, with a built-in demo SP to try sign-ins in the browser; a workerd test of the whole flow runs weekly in CI. Experimental because CharDB is 0.1, and outside the versioning promises; built with CharDB from a Better Auth 1.7 branch (`vendor/`) until CharDB publishes one.
- **The Workers example is a multi-tenant IdP:** Better Auth's organization plugin (migration `0010_organizations.sql`) and `tenants: { enabled: true, keys: "per-tenant", delegation: {} }`. `/admin` gains a Tenants section (create an organization and its tenant, enable or disable it, rotate, activate and retire its key) and a button for the one-time SP backfill after upgrading; the home page lists tenants with their metadata. Only registry admins create organizations there.

## [1.1.0] - 2026-09-29

Multi-tenancy phases 2 and 3: a signing key per tenant, and delegated administration of a tenant's SPs by its organization's owners and admins. Both are opt-in; with neither set, nothing changes. Reviewed twice before release (D-060, D-061).

### Added

- **Multi-tenant IdP, phase 2: a signing key per tenant** (`tenants: { enabled: true, keys: "per-tenant" }`; [guide](docs/guide/multi-tenant.md#per-tenant-signing-keys), D-058). Opt-in: with `keys: "shared"` (the default) nothing changes.
  - Each tenant signs its assertions, logout messages and metadata with its own key, and its metadata publishes that certificate. A new tenant gets one at creation (RSA 3072, a two-year self-signed certificate).
  - A tenant made before keeps the shared key until its first own key is rotated in, so its SPs see an ordinary rotation. Once a tenant has had its own key, nothing else ever signs for it: a key that can't be loaded refuses (`INTERNAL_ERROR`, metadata 500) and never falls back.
  - Rotation per tenant through the registry API: `/saml-idp/tenants/keys` (list), `/keys/rotate` (a next key, generated or uploaded), `/keys/activate` (after `minPublishedSeconds`, default 24 hours; `force` for a leaked key) and `/keys/retire` (erases the old private key).
  - Keys are stored in the new `samlIdpTenantKey` table, sealed with Better Auth's (versioned) secret or `tenants.keyEncryptionSecret`, and bound to their tenant and key id, so a key copied into another row is refused. D1: the example's migration `0009_tenant_keys.sql`.
  - New error codes: `INVALID_TENANT_SIGNING_KEY`, `TENANT_SIGNING_KEY_EXISTS`, `TENANT_SIGNING_KEY_NOT_FOUND`, `TENANT_SIGNING_KEY_TOO_NEW`. Tenant records gain `signing` and `keys` with per-tenant keys.
- **Multi-tenant IdP, phase 3: delegated administration** (`tenants.delegation`, with per-tenant keys only; [guide](docs/guide/multi-tenant.md#delegated-administration), D-059). An organization's owners and admins manage their own tenant's SPs through the registry API.
  - Membership is read from the database on every request, so a demotion takes effect at once; only enabled tenants count; impersonated sessions are refused.
  - Scope: list is filtered in the query; get, update and delete of another tenant's SP, or the root's, answer 404; create only in their own tenants.
  - Limits: attributes and NameID only from `userFields` (default `email`, `name`, `id`); no `metadata.url` unless `allowMetadataUrl`; no warnings naming another tenant's SP.
  - Tenants and their keys stay with the host's managers. A tenant's administrator can read its own tenant record and certificates.
  - With delegation alone (no `canManage`, no `permissions`), the registry API is mounted for tenants' administrators only.
- **Audit log API:** `GET /saml-idp/audit` (with `auditLog.enabled`): newest first, paged with `before`, filtered by tenant in the query; a tenant's administrator sees only its own.
- **Registry changes in the audit log:** a `service-provider.changed` event (`events.onServiceProviderChanged`) for each create, update, enable, disable and delete, with the acting user and `delegated`.
- **Review 7 of phases 2 and 3, before release** (D-060):
  - **R7-5 (High):** delegation now applies only to tenants that sign with their own key. A tenant still on the shared key would have let its administrator get assertions for another identity's SPs signed with that key (design §5.1).
  - **R7-4 (High):** a delegated SP can't use `only` in organization attributes, which would have told a tenant's administrator its members' memberships in other organizations.
  - **R7-1:** retired tenant keys beyond the five newest are deleted, and key reads are newest first, so many rotations can't push the active key out of a bounded read (which would have refused every sign-in).
  - **R7-2:** tenant records carry `warnings` for certificates that expire within 30 days, or have, and loading such a key logs it.
  - **R7-3:** listing tenants reads only their key rows (filtered in the query).
  - **R7-6:** a delegated create or update naming another organization gets the same 403 whether or not it is a tenant.
- **Tenant changes in the audit log** (review 6 I-2): a `tenant.changed` event (`events.onTenantChanged`, and the audit log) when an administrator creates, enables, disables or deletes a tenant, or rotates, activates or retires one of its keys, with who did it.

### Fixed

- **More than 100 values in one lookup on D1** (review 8 R8-1, D-061). D1 allows 100 bound parameters per statement. With per-tenant keys, the tenant list failed with 100 or more tenants. For a user in 100 or more organizations, sign-in to an SP with organization attributes, and delegated registry requests, failed too; that one was in 1.0 already. Both now read in batches.
- **Tenant certificates' common name is at most 64 characters** (R8-2), as RFC 5280 requires; with a long tenant key it could reach 80. The CLI's `keygen` applies the same cap.
- **A refused key rotation no longer generates a key first** (R8-3).

### Changed

- **Trailing slashes are trimmed with a loop everywhere** (base URLs, the CLI's metadata URL): the last `/\/+$/` uses, which CodeQL flags as quadratic on many slashes, now share the loop `samlIdpClient()` already used (D-037). The inputs are configuration, not requests, so this is tidiness rather than a fix.
- **Development only:** undici is pinned to 7.29.1 under the Workers test pool (GHSA-3wwx-pv8p-q78v); nothing in the published package uses it.

## [1.0.2] - 2026-09-29

### Fixed

- **`samlIdpClient()` under TypeScript 5 with `exactOptionalPropertyTypes`.** 1.0.1 fixed the strict-host types under TypeScript 7, which the package is built and checked with. Under TypeScript 5.9, `createAuthClient({ plugins: [samlIdpClient()] })` still failed: `getActions` declared `better-auth/client`'s `BetterFetch`, which TypeScript 5 doesn't treat as the core one `BetterAuthClientPlugin` uses. Its parameters now come from `BetterAuthClientPlugin` itself. `pnpm pack:check` compiles the strict host with TypeScript 5.9 as well as 7; 1.0.1's declarations fail it under 5.9 (D-057). Nothing changed at runtime.

## [1.0.1] - 2026-09-29

Two fixes found by running the plugin, with multi-tenancy on, in a [CharDB](https://github.com/zpg6/chardb) app (Better Auth on Durable Objects). Everything else passed there: the tables and their UNIQUE keys came through CharDB's migrations, and every `smoke` check passed at the root and at a tenant (D-056).

### Fixed

- **Types under `exactOptionalPropertyTypes`.** In a host compiled with that option, `samlIdp()` wasn't assignable to `BetterAuthPlugin` (in `betterAuth({ plugins })` too), nor `samlIdpClient()` in `createAuthClient`, and optional options refused an explicit `undefined`. Nothing changed at runtime. The package is now built with the option, optional fields accept `undefined`, and `pnpm pack:check` compiles a strict host against the built declarations (`test/types/strict-host.ts`; 1.0.0's fail it with 5 errors).
- **The CLI and tenants.** `inspect`, `smoke`, `request` and `decode --idp` now accept a tenant's metadata URL (`…/saml2/idp/metadata/<tenantKey>`); 1.0.0 treated it as a base URL. `smoke` runs every check at the tenant's SSO URL.

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

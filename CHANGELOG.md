# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

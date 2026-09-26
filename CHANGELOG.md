# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

The first npm release (1.0.0) waits for `better-auth-cloudflare` 0.4, which Workers users need.

### Security

- **Hardening (D-037):** the pre-parse attribute scan in `parseXmlStrict` could take quadratic time on unterminated markup: 2.5 s for 64 KiB. It is now linear, and element nesting is capped at 100. This was not reachable in the default configuration, because libxml2 schema validation rejects such input first. It protects hosts that replace `schemaValidator`, and the CLI.

### Added

- **Observability** ([guide](docs/guide/observability.md)): `events.onAssertionIssued`, `onDenied` and `onLogout` callbacks, which run in the background and can't affect the flow, and an optional `auditLog` table (`samlIdpAuditEvent`, D1 migration `0005`) with retention.
- **Supply chain:**
  - every GitHub Action pinned by SHA, least-privilege tokens;
  - CodeQL (security-extended); a runtime dependency audit that blocks; dependency review on PRs; OSV-Scanner; OpenSSF Scorecard; Dependabot;
  - a release workflow publishing with npm provenance, with a CycloneDX SBOM.
- **Project files:** [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), issue forms (bug, SP interop, feature), a PR template, and [Versioning and support](docs/guide/versioning.md).
- **Property-based fuzzing** (fast-check) of the signature verifier (XSW, mutation, byte flips) and of every inbound parser, plus an issuance round-trip over hostile user data. `FUZZ_RUNS` sets the depth.

- **SAML 2.0 IdP plugin for Better Auth** with SP-initiated SSO.
  - AuthnRequests over the HTTP-Redirect and HTTP-POST bindings.
  - Responses over HTTP-POST.
  - IdP metadata at `/saml2/idp/metadata`.
- **Signing**
  - Response and Assertion are signed with RSA-SHA256 by default. SHA-1 needs an explicit opt-in.
  - Per-SP `signResponse` / `signAssertion`.
  - Optional signed metadata (`signMetadata`).
  - Extra certificates published for key rotation ([docs/key-rotation.md](docs/key-rotation.md)).
- **Inbound validation**
  - Every message is validated against the OASIS XSDs with a WebAssembly build of libxml2 that runs on Workers.
  - DOCTYPE is refused. DEFLATE and size limits apply. Duplicate and percent-encoded parameters are rejected.
- **Signed AuthnRequests** over HTTP-Redirect, which can be required per SP. SPs may have several certificates.
- **Replay protection**
  - Single-use pending requests (`consumeVerificationValue`).
  - AuthnRequest-ID replay is rejected by a database unique key.
- **Account policy:** users need a verified email; impersonated sessions and anonymous users are refused. The user and session are re-read right before signing.
- **Protocol:** NameID per format (emailAddress, persistent, transient), ForceAuthn, IsPassive, and RequestedAuthnContext (exact match). Requests the IdP can't satisfy get signed SAML error Responses.
- **`serviceProviderFromMetadata()`** builds a service-provider entry from the SP's metadata XML.
- **Cloudflare Workers support** through `better-auth-cloudflare` (D1/Drizzle, `validateSchema`). There is a Workers + Hono example.
- **Interop tests**
  - `@better-auth/sso`, node-saml and samlify.
  - Keycloak 26.4, SimpleSAMLphp 2.5 and a node-saml POST-binding SP in real Chromium over HTTPS.
  - Verified live with Cloudflare Access.
- **Interop:** Okta and Auth0 verified live as SPs (signed requests, encrypted assertions with Okta, metadata-sourced certificates with Auth0). `ProtocolBinding="HTTP-Redirect"` (sent by Auth0) is answered over HTTP-POST instead of being refused.
- **The guide** (`docs/guide/`): getting started, service providers, flows, users and access, signing and encryption, Single Logout, `@better-auth/sso` interop, Cloudflare Workers, CLI, troubleshooting; and complete references for options, errors, security controls and schema. Links are checked in CI.
- **Better Auth integration:** organization-scoped SPs and organization attributes (organization plugin), registry permissions through admin-plugin access control (`samlIdpStatements`), a typed client plugin with `signOutEverywhere()` / `launch()`, and tables verified with `npx auth generate`.
- **Single Logout:** SP- and IdP-initiated, front-channel propagation to every SP in the session, `PartialLogout` reporting, and an authenticated LogoutRequest (signature, or the per-session SessionIndex).
- **Database-backed SP registry** with an admin-gated management API: add, change, disable and remove SPs without a redeploy.
- **SP certificates are parsed at startup**, so a malformed `spCertificate` is a configuration error instead of a sign-in failure.
- **SP metadata URL with refresh:** an SP's signing and encryption certificates are kept current from its metadata. Entity ID and ACS URLs stay pinned, and the metadata signature can be pinned too.
- **Signed AuthnRequests over HTTP-POST:** enveloped XML signatures verified with signature-wrapping defences. The Redirect binding keeps its query signatures.
- **Declarative attribute mapping per SP:** `attributes` can be a map (field, constant, split list, first/last name) instead of a function, so SPs can be configured in JSON.
- **Command-line tool** (`npx better-auth-saml-idp`) with seven commands: `inspect`, `decode` (signature verification and decryption), `request`, `smoke`, `sp-from-metadata`, `check-config` and `keygen`.
- **Encrypted assertions per SP:** AES-256-GCM with RSA-OAEP, signed before encryption.
- **IdP-initiated SSO**, opt-in per SP. RelayState comes only from an allow-list, and a cross-site redirect without a user click gets a confirmation page.
- **Package:** ESM build with type declarations, checked with publint and Are the Types Wrong.

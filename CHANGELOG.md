# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

The first npm release (1.0.0) waits for `better-auth-cloudflare` 0.4, which Workers users need.

### Added

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
- **Command-line tool** (`npx better-auth-saml-idp`) with seven commands: `inspect`, `decode` (signature verification and decryption), `request`, `smoke`, `sp-from-metadata`, `check-config` and `keygen`.
- **Encrypted assertions per SP:** AES-256-GCM with RSA-OAEP, signed before encryption.
- **IdP-initiated SSO**, opt-in per SP. RelayState comes only from an allow-list, and a cross-site redirect without a user click gets a confirmation page.
- **Package:** ESM build with type declarations, checked with publint and Are the Types Wrong.

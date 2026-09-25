# Security

This page covers what `better-auth-saml-idp` defends against, what it relies on from the host, and how to configure the host so that those defences hold.

> [!WARNING]
> **On Cloudflare Workers, put `samlIdp()` inside `withCloudflare`'s second argument.** If you write `plugins: [...]` *next to* `...withCloudflare(...)`, your array **replaces** the Cloudflare plugin. That silently turns off its storage validation, IP detection and geolocation hooks. See [Host configuration](#host-configuration).

## Host configuration

This plugin issues signed assertions, so an SP will trust anything it signs. Configure the host so that single-use values really are single-use and revoked sessions really are revoked.

```ts
betterAuth({
  ...withCloudflare(
    { d1: { db, options: { usePlural: true } }, cf },
    {
      verification: { storeInDatabase: true },   // required
      rateLimit: { storage: "database" },         // keep rate limiting on
      plugins: [samlIdp({ /* … */ })],            // INSIDE withCloudflare
    },
  ),
});
```

- **Minimum versions:** `better-auth` ≥ 1.7.5 and < 1.8, and `better-auth-cloudflare` **≥ 0.4**.
  - `better-auth-cloudflare` 0.3.1 combined with `better-auth` ≥ 1.7.3 silently breaks every verification consume (better-auth-cloudflare #72).
  - 0.4 turns that misconfiguration into a startup error. The plugin's own tests assert that it fails loudly.
- **Keep single-use state in the database.** `verification.storeInDatabase: true` routes consumes through the database's lock-guarded `DELETE … RETURNING`.
  - Workers KV can't do atomic get-and-delete, compare-and-swap or counters, so KV must never hold single-use state.
- **Don't use KV secondary storage for sessions, and leave `session.cookieCache` disabled.**
  - Better Auth checks secondary storage *before* the database, so a revoked session can stay valid for KV's propagation window, often 60 seconds or more (better-auth-cloudflare #61).
  - The plugin re-checks the user and session against the database before signing (below), but a stale session can still *reach* the resume endpoint.
- **Pin the IdP's base URL**, via `samlIdp({ baseURL })` or Better Auth's `baseURL`. Otherwise the SSO URL in metadata, the `Destination` check and the resume links follow the request's `Host` header. That's bounded and never cached publicly, but it's still steerable.
- **Verify email addresses.** The plugin refuses to assert unverified emails (see the account policy below), so the host needs a working verification flow.
- **Use a real database adapter.**
  - Replay protection relies on the database enforcing a UNIQUE constraint (the `key` column).
  - Better Auth's in-memory adapter doesn't enforce keys. It's fine for development, but it doesn't provide replay protection.

## What the plugin enforces

| Threat | Defence | Tested in |
|---|---|---|
| Assertion sent to an attacker | An ACS URL must match the SP's allow-list **exactly**. When the request names none, the first registered URL is used. Unregistered URLs are never used or echoed. | `security.test.ts`, `sp-registry.test.ts` |
| Unknown or spoofed SP | The `Issuer` must match a configured `entityId` exactly. | `security.test.ts` |
| Replayed AuthnRequest | `(spId, requestId)` is inserted into `samlIdpSeenRequest`. A duplicate primary key, and in the documented schema a composite `UNIQUE`, rejects a replay. There's no read-then-write. | `security.test.ts` (sequential, concurrent, cross-instance) |
| Replayed or raced resume link | The pending request is a Better Auth verification value, consumed once through `consumeVerificationValue`. It expires (default 10 minutes) and is bound to the starting browser by a signed cookie. | `security.test.ts` (10 concurrent resumes, one and five instances) |
| Someone signs up as `ceo@victim.example` and gets it asserted | **Account policy**, checked on the fresh DB user right before signing: an unverified email → `EMAIL_NOT_VERIFIED`; an admin-impersonation session or an anonymous user → `SESSION_NOT_ALLOWED`. All three are on by default; relax them with `accountPolicy` only if you understand the consequences. | `review-findings.test.ts` #1 |
| Revoked or banned user still holding a session | Right before signing, the user is re-read from the database (missing or banned → refused). Where sessions live in the database, the session row is re-read too (missing or expired → refused). | `security.test.ts` (banned; stale-cache session; deleted user) |
| Forged AuthnRequest from an SP that must sign | HTTP-Redirect signatures are verified over the raw query octets with the SP's certificate. The query is parsed by the plugin itself: names are decoded before matching (`Relay%53tate` is RelayState), duplicates are rejected, and the octets cover exactly the parameters used. SHA-1 is refused unless you opt in. Signed POST-binding requests aren't supported in v1 and are rejected. | `security.test.ts` |
| XML attacks on the parser | The size is capped, including the inflated size of DEFLATE data. DOCTYPE and ENTITY are rejected before parsing. The request is checked against the OASIS XSDs with libxml2 2.15 in WASM (no network, no file access), then parsed strictly and checked for structure: one `Issuer`, `Version` 2.0, a fresh `IssueInstant`, our `Destination`. | `validator.test.ts`, `security.test.ts`, `wasm-validator/test/` |
| Weak crypto | RSA-SHA256 / SHA-256 by default. SHA-1 needs `allowInsecureSha1: true` and logs a warning. RSA keys under 2048 bits, expired certs and mismatched key/cert pairs are rejected at startup. | `options.test.ts` |
| Assertion contents (NameID, attributes) readable by the browser, extensions, proxies or logs between IdP and SP | Per-SP `encryption`: the signed assertion is encrypted into an `EncryptedAssertion` (AES-256-GCM, fresh key and IV per assertion, key sent under the SP's certificate with RSA-OAEP), then the Response is signed. An encrypted assertion is always signed when the Response isn't. AES-CBC needs `allowInsecureCbc: true` and logs a warning; RSA PKCS#1 v1.5 isn't implemented. The SP certificate must be RSA ≥ 2048 bits; expiry warns. | `encrypt.test.ts`, `encryption-interop.test.ts` (node-saml, samlify) |
| Long-lived assertions | `NotOnOrAfter` defaults to 5 minutes, and `NotBefore` allows the configured clock skew. | `security.test.ts` |
| XSS or clickjacking on the POST page | Everything is HTML-escaped. The CSP is `default-src 'none'` with a per-response nonce, plus `base-uri 'none'` and `frame-ancestors 'none'`, along with `X-Frame-Options: DENY`, `Cache-Control: no-store` and a `<noscript>` button. **No `form-action`:** browsers apply it to the SP's redirect *after* its ACS, and real SPs redirect cross-site, so it would break sign-in (verified in Chromium). The form's action is always an allow-listed ACS URL. | `security.test.ts`, `e2e/browser` |
| Assertion for the wrong person or strength | A requested `<Subject>` must match the NameID we'd issue (else `UnknownPrincipal`). `RequestedAuthnContext` must include `authnContextClassRef` (else `NoAuthnContext`). Both are sent to the SP as signed SAML error Responses. | `review-findings.test.ts` #12 |
| Re-assigned or linkable identifiers | The NameID follows the format: `persistent` is an opaque per-SP HMAC of the user id (never the email, never re-assigned); `transient` is random per assertion; `emailAddress` is the verified email. | `review-findings.test.ts` #11 |
| Leaking secrets in logs | The private key, SAMLRequest/SAMLResponse payloads and rejected issuers are never logged. Debug logs carry error codes, IDs and, for schema errors, a short sanitised excerpt of the validator message (length-bounded, control characters removed). | `security.test.ts` ("logging") |
| Access policy | The `authorize({ user, session, serviceProvider })` hook runs on the fresh user. A denial or an exception means no assertion is issued. | `security.test.ts` |

## Known limitations (v1)

- There's no Single Logout and no IdP-initiated SSO.
- Encryption certificates are configured per SP in code; they aren't read from SP metadata. `keyAlgorithm: "rsa-oaep-sha256"` (`xmlenc11#rsa-oaep`) isn't supported by node-saml or samlify, and its `xenc11:MGF` element fails XSD validators that lack the XML Encryption 1.1 schema, so the default stays `rsa-oaep` (`rsa-oaep-mgf1p`).
- The HTTP-POST binding is answered through a single-use, 120-second, same-site GET re-entry (`sso?cid=`), because the SP's cross-site POST carries no `SameSite=Lax` cookies. Forwarding that link is equivalent to forwarding an HTTP-Redirect AuthnRequest URL.
- `AssertionConsumerServiceIndex` without a URL is rejected. SPs must send `AssertionConsumerServiceURL`.
- The `persistent` NameID is keyed with the Better Auth secret. Rotating the secret changes every persistent NameID.
- The WASM validator costs about 40–55 ms of CPU the first time it runs in each Workers isolate, which is above the Workers Free 10 ms limit for that request. Warm validations take about 0.1 ms.

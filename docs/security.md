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
- **Use a real database adapter.**
  - Replay protection relies on the database rejecting a duplicate primary key.
  - Better Auth's in-memory adapter doesn't enforce keys. It's fine for development, but it doesn't provide replay protection.

## What the plugin enforces

| Threat | Defence | Tested in |
|---|---|---|
| Assertion sent to an attacker | An ACS URL must match the SP's allow-list **exactly**. When the request names none, the first registered URL is used. Unregistered URLs are never used or echoed. | `security.test.ts`, `sp-registry.test.ts` |
| Unknown or spoofed SP | The `Issuer` must match a configured `entityId` exactly. | `security.test.ts` |
| Replayed AuthnRequest | `(spId, requestId)` is inserted into `samlIdpSeenRequest`. A duplicate primary key, and in the documented schema a composite `UNIQUE`, rejects a replay. There's no read-then-write. | `security.test.ts` (sequential, concurrent, cross-instance) |
| Replayed or raced resume link | The pending request is a Better Auth verification value, consumed once through `consumeVerificationValue`. It expires (default 10 minutes) and is bound to the starting browser by a signed cookie. | `security.test.ts` (10 concurrent resumes, one and five instances) |
| Revoked or banned user still holding a session | Right before signing, the user is re-read from the database (missing or banned → refused). Where sessions live in the database, the session row is re-read too (missing or expired → refused). | `security.test.ts` (banned; stale-cache session; deleted user) |
| Forged AuthnRequest from an SP that must sign | HTTP-Redirect signatures are verified over the raw query octets with the SP's certificate. SHA-1 is refused unless you opt in. Signed POST-binding requests aren't supported in v1 and are rejected. | `security.test.ts` |
| XML attacks on the parser | The size is capped, including the inflated size of DEFLATE data. DOCTYPE and ENTITY are rejected before parsing. The request is checked against the OASIS XSDs with libxml2 2.15 in WASM (no network, no file access), then parsed strictly and checked for structure: one `Issuer`, `Version` 2.0, a fresh `IssueInstant`, our `Destination`. | `validator.test.ts`, `security.test.ts`, `wasm-validator/test/` |
| Weak crypto | RSA-SHA256 / SHA-256 by default. SHA-1 needs `allowInsecureSha1: true` and logs a warning. RSA keys under 2048 bits, expired certs and mismatched key/cert pairs are rejected at startup. | `options.test.ts` |
| Long-lived assertions | `NotOnOrAfter` defaults to 5 minutes, and `NotBefore` allows the configured clock skew. | `security.test.ts` |
| XSS or clickjacking on the POST page | Everything is HTML-escaped. The CSP is `default-src 'none'` with a per-response nonce, `form-action` is limited to the ACS URL, and `frame-ancestors 'none'` is set, along with `X-Frame-Options: DENY`, `Cache-Control: no-store` and a `<noscript>` button. | `security.test.ts` |
| Leaking secrets in logs | The private key is never logged. SAML payloads are never logged; debug logs carry only error codes and IDs. | `security.test.ts` ("logging") |
| Access policy | The `authorize({ user, session, serviceProvider })` hook runs on the fresh user. A denial or an exception means no assertion is issued. | `security.test.ts` |

## Known limitations (v1)

- There's no Single Logout, no IdP-initiated SSO and no encrypted assertions.
- `IsPassive` without a session returns an error page rather than a SAML `NoPassive` status Response.
- `AssertionConsumerServiceIndex` without a URL is rejected. SPs must send `AssertionConsumerServiceURL`.
- The WASM validator costs about 40–55 ms of CPU the first time it runs in each Workers isolate, which is above the Workers Free 10 ms limit for that request. Warm validations take about 0.1 ms.

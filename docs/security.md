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
| Forged AuthnRequest from an SP that must sign | HTTP-Redirect signatures are verified over the raw query octets with the SP's certificate. The query is parsed by the plugin itself: names are decoded before matching (`Relay%53tate` is RelayState), duplicates are rejected, and the octets cover exactly the parameters used. SHA-1 is refused unless you opt in. HTTP-POST signatures are enveloped XML signatures, and they're accepted only when all of these hold (D-025):
  - exactly one ds:Signature, as a direct child of the AuthnRequest;
  - one Reference, to the request's own ID, and that ID is unique across `ID`/`Id`/`id` attributes;
  - allow-listed canonicalization, transforms, signature and digest (no XPath or `WithComments`);
  - no comments in the document;
  - verified only with the SP's configured certificates (KeyInfo is ignored).

  Each rule is mutation-tested. | `security.test.ts`, `post-signed-requests.test.ts`, `unit/xmldsig.test.ts` |
| XML attacks on the parser | The size is capped, including the inflated size of DEFLATE data. DOCTYPE and ENTITY are rejected before parsing. The request is checked against the OASIS XSDs with libxml2 2.15 in WASM (no network, no file access), then parsed strictly and checked for structure: one `Issuer`, `Version` 2.0, a fresh `IssueInstant`, our `Destination`. | `validator.test.ts`, `security.test.ts`, `wasm-validator/test/` |
| Weak crypto | RSA-SHA256 / SHA-256 by default. SHA-1 needs `allowInsecureSha1: true` and logs a warning. RSA keys under 2048 bits, expired certs and mismatched key/cert pairs are rejected at startup. | `options.test.ts` |
| Assertion contents (NameID, attributes) readable by the browser, extensions, proxies or logs between IdP and SP | Per-SP `encryption`: the signed assertion is encrypted into an `EncryptedAssertion` (AES-256-GCM, fresh key and IV per assertion, key sent under the SP's certificate with RSA-OAEP), then the Response is signed. An encrypted assertion is always signed when the Response isn't. AES-CBC needs `allowInsecureCbc: true` and logs a warning; RSA PKCS#1 v1.5 isn't implemented. The SP certificate must be RSA ≥ 2048 bits; expiry warns. | `encrypt.test.ts`, `encryption-interop.test.ts` (node-saml, samlify) |
| Long-lived assertions | `NotOnOrAfter` defaults to 5 minutes, and `NotBefore` allows the configured clock skew. | `security.test.ts` |
| Forged logout (someone ends a user's session) | LogoutRequests from an SP with certificates must be signed, and are verified like AuthnRequests. Without certificates, only the exact `SessionIndex` of *this browser's* session ends it. That value is a hash of the session ID, sent only to SPs in their assertions. Replayed LogoutRequests are refused, a cross-site drive-by to `/logout` needs a click, and `returnTo` is limited to same-origin paths and trusted origins. Each rule is mutation-tested. | `slo.test.ts` |
| Logout chain tampering | Hop state is single-use, named by the RelayState, and expires in 5 minutes. A participant's answer must come from that SP (by Issuer and signature, when it has certificates) and answer our request (`InResponseTo`); anything else is recorded as `PartialLogout`. The IdP session ends *before* the first hop, and the session cookie is cleared even on auto-POST responses (tested). | `slo.test.ts` |
| Unauthorised changes to stored SPs (registry) | The API is only mounted when `canManage` is configured. Every route needs an authoritative session: session and user re-read from the database, so demotion and revocation apply at once, even with the cookie cache on (mutation-tested). Impersonated sessions are refused, `canManage` must return exactly `true` (a throw denies), Better Auth's origin checks apply, and changes are logged with the acting user. | `registry.test.ts` |
| A stored SP row edited directly in the database | Rows are re-validated with the full option schema on every load, and an invalid row is ignored and logged. The lookup columns must match the JSON config. SPs defined in code can't be shadowed, and a disabled row is never used. | `registry.test.ts` |
| A tampered or hijacked SP metadata URL | Only **certificates** are taken from metadata. The entity ID must equal the configured one, and ACS URLs never come from it, so assertions can't be redirected. The fetch is https only, with a 5 s timeout, no redirects, 1 MiB at most, an XSD check, a strict parse, and a refusal of an expired `validUntil`. Optionally, the metadata signature is pinned (`metadata.signingCertificate`, verified with the XSW rules). Configured certificates stay trusted, and failures keep the last good copy, with backoff. | `sp-metadata-refresh.test.ts` |
| XSS or clickjacking on the POST page | Everything is HTML-escaped. The CSP is `default-src 'none'` with a per-response nonce, plus `base-uri 'none'` and `frame-ancestors 'none'`, along with `X-Frame-Options: DENY`, `Cache-Control: no-store` and a `<noscript>` button. **No `form-action`:** browsers apply it to the SP's redirect *after* its ACS, and real SPs redirect cross-site, so it would break sign-in (verified in Chromium). The form's action is always an allow-listed ACS URL. | `security.test.ts`, `e2e/browser` |
| Assertion for the wrong person or strength | A requested `<Subject>` must match the NameID we'd issue (else `UnknownPrincipal`). `RequestedAuthnContext` must include `authnContextClassRef` (else `NoAuthnContext`). Both are sent to the SP as signed SAML error Responses. | `review-findings.test.ts` #12 |
| Re-assigned or linkable identifiers | The NameID follows the format: `persistent` is an opaque per-SP HMAC of the user id (never the email, never re-assigned); `transient` is random per assertion; `emailAddress` is the verified email. | `review-findings.test.ts` #11 |
| Leaking secrets in logs | The private key, SAMLRequest/SAMLResponse payloads and rejected issuers are never logged. Debug logs carry error codes, IDs and, for schema errors, a short sanitised excerpt of the validator message (length-bounded, control characters removed). | `security.test.ts` ("logging") |
| Access policy | The `authorize({ user, session, serviceProvider })` hook runs on the fresh user. A denial or an exception means no assertion is issued. | `security.test.ts` |
| Unsolicited assertions to SPs that didn't ask for them | IdP-initiated SSO (`/saml2/idp/init`) is off unless the SP has `allowIdpInitiated: true`, re-checked when a parked request resumes. It always posts to the SP's first registered ACS URL; the caller can't choose one. | `idp-initiated.test.ts` |
| Open redirect at the SP through IdP-initiated RelayState | A caller-supplied `RelayState` is used only if it exactly matches the SP's `allowedRelayStates`; otherwise `idpInitiatedRelayState` (or nothing) is sent. | `idp-initiated.test.ts` |

## IdP-initiated SSO

`GET /saml2/idp/init?sp=<id>` sends an **unsolicited** Response: one that answers no AuthnRequest. It's off by default and enabled per SP with `allowIdpInitiated: true`. Before you enable it, know what it gives up. The SAML2Int profile and `@better-auth/sso` both advise against it unless an SP needs it.

- **Login CSRF.** Any website can link or redirect a signed-in user's browser to the init URL, and the user is then signed in to the SP without having asked. The identity is still the user's own (the IdP asserts only who is signed in), so this is not the classic "log the victim into the attacker's account". The risk is being dropped into an SP session, and at a deep link, that the user didn't choose. Mitigations:
  - The endpoint is **GET only**: launcher links and bookmarks are GETs. POST is not routed, and a cross-site POST would carry no `SameSite=Lax` cookies anyway.
  - **Fetch Metadata check.** A cross-site navigation that the user didn't trigger (`Sec-Fetch-Site: cross-site` without `Sec-Fetch-User: ?1`, for example a script or meta-refresh redirect on another site) gets a confirmation page on the IdP's origin instead of a Response. The page can't be framed. User clicks from a portal on another site, bookmarks, typed URLs and same-site links go straight through. Browsers that don't send Fetch Metadata, and user-activated clicks on an attacker's page, aren't stopped: this narrows the attack but doesn't close it.
  - The caller can't pick the ACS URL (always the SP's first) or an arbitrary RelayState (below).
  - Better Auth's rate limiter applies to the endpoint like every other route. Keep it on.
  - Enable it only for SPs that need it.
- **RelayState is an open-redirect vector at the SP.** In IdP-initiated SSO, RelayState conventionally carries the URL the SP should send the user to after sign-in, and many SPs follow it without checking. Forwarding a caller's value would let anyone craft a link to your IdP that signs the user in to the SP and then bounces them to a site of the attacker's choice, under a trusted-looking domain. So a caller's `RelayState` is used **only if it exactly matches** one of the SP's `allowedRelayStates`. Anything else is **ignored**, not rejected, so that a stale bookmark still signs the user in: the SP's `idpInitiatedRelayState` is sent instead, or no RelayState at all.
- **Replay.** An unsolicited assertion isn't tied to a request ID, so the SP can't use `InResponseTo` to check that it's fresh and single-use. The assertion is still short-lived (`NotOnOrAfter`, 5 minutes by default; keep `assertionLifetimeSeconds` low), audience-restricted, and addressed to one ACS URL (`Destination`, `Recipient`). **SPs that accept unsolicited Responses must remember assertion IDs until they expire and reject repeats.** Check that yours does. Every assertion ID is logged at info level (`issued assertion <id> for SP <sp>`) for correlation.
- Everything else is as for SP-initiated SSO: the user and session are re-read from the database, the account policy and `authorize()` run, the NameID follows the SP's format, and the Response and assertion are signed. Without a session, the request is parked as a single-use, browser-bound pending request (the same machinery as SP-initiated SSO) and resumes after sign-in.

## Known limitations (v1)

- Single Logout is front-channel and best effort: an SP that never sends the browser back stops the chain (the IdP session is already over). It's reported as `PartialLogout` only when the IdP can tell.
- For an SP **without certificates**, a LogoutRequest is authenticated only by the SessionIndex issued to that SP, so anyone can make the IdP produce a signed `Success` LogoutResponse for such an SP, with an `InResponseTo` and RelayState of their choosing. An SP should check `InResponseTo` against its own pending logout. Give SPs that do SLO a certificate.
- The registry's `metadata.url` can point at any https host, including internal ones reachable from a Node deployment. Only registry admins can set it, and fetch errors only reach the logs.
- IdP-initiated SSO has no `acs` parameter: it always uses the SP's first ACS URL.
- Encryption is configured per SP in code. `serviceProviderFromMetadata()` returns the SP's encryption certificates but doesn't turn encryption on. `keyAlgorithm: "rsa-oaep-sha256"` (`xmlenc11#rsa-oaep`) isn't supported by node-saml or samlify, and its `xenc11:MGF` element fails XSD validators that lack the XML Encryption 1.1 schema, so the default stays `rsa-oaep` (`rsa-oaep-mgf1p`).
- The HTTP-POST binding is answered through a single-use, 120-second, same-site GET re-entry (`sso?cid=`), because the SP's cross-site POST carries no `SameSite=Lax` cookies. Forwarding that link is equivalent to forwarding an HTTP-Redirect AuthnRequest URL.
- `AssertionConsumerServiceIndex` without a URL is rejected. SPs must send `AssertionConsumerServiceURL`.
- The `persistent` NameID is keyed with the Better Auth secret. Rotating the secret changes every persistent NameID.
- The WASM validator costs about 40–55 ms of CPU the first time it runs in each Workers isolate, which is above the Workers Free 10 ms limit for that request. Warm validations take about 0.1 ms.

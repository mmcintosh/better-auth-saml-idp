# Security

[Guide](README.md) › Security

An identity provider vouches for identities, so every protection here is **on by default and can't be turned off**, apart from a few explicit opt-outs for legacy SPs, noted below. This page explains each control: how it works, which options affect it, and the error it produces. The threat model, with the attack each control answers, is in [docs/security.md](../security.md), and the evidence for every claim (tests, mutation proofs, two adversarial reviews) is in [DECISIONS.md](../../DECISIONS.md).

- [Host requirements](#host-requirements)
- [Inbound message validation](#inbound-message-validation)
- [Timestamp validation](#timestamp-validation)
- [Replay protection](#replay-protection)
- [ACS URL allow-list](#acs-url-allow-list)
- [Signed requests](#signed-requests)
- [XML signature verification](#xml-signature-verification)
- [Algorithm policy](#algorithm-policy)
- [Size limits](#size-limits)
- [Account policy and fresh re-reads](#account-policy-and-fresh-re-reads)
- [Browser binding and the POST binding](#browser-binding-and-the-post-binding)
- [Pages the IdP serves](#pages-the-idp-serves)

## Host requirements

The plugin can't protect against a host misconfiguration it can't see. In production:

- **Set `baseURL`**, in the plugin or in Better Auth. Without it the IdP's own URLs (SSO URL in metadata, expected `Destination`, resume links) follow the request's `Host` header.
- **Use a real database.** Replay protection relies on UNIQUE constraints; Better Auth's in-memory adapter doesn't enforce them.
- **Don't cache sessions in KV** (`secondaryStorage` for sessions), and leave `session.cookieCache` off. Revoking a session must take effect at once; the plugin re-reads sessions from the database where it can, but a cached session outlives revocation elsewhere in Better Auth. See [docs/security.md](../security.md).
- **With any secondary storage, set `verification: { storeInDatabase: true }`**, so single-use values (pending requests, logout state) are consumed atomically.
- On Cloudflare Workers: put `samlIdp()` inside `withCloudflare`'s second argument, and use Workers Paid (the first request in an isolate compiles the XSD validator).

## Inbound message validation

**How it works.** Every AuthnRequest, LogoutRequest and LogoutResponse goes through the same pipeline before anything reads it:

1. **Size and encoding:** base64 is size-checked before decoding; DEFLATE (Redirect binding) is inflated with a hard 64 KiB cap, so a compression bomb stops early; UTF-8 must be valid.
2. **No DTDs:** any `<!DOCTYPE` is refused, so entity-expansion and external-entity attacks never reach a parser.
3. **XSD validation** against the OASIS SAML 2.0 schemas, with a WebAssembly build of libxml2 that also runs on Workers.
4. **Strict parse:** any parser warning or error rejects the document, as do two attributes with the same expanded name (Namespaces in XML §6.3) and elements nested more than 100 deep. The parse is linear in the input size.
5. **Structure:** the right root element, `Version="2.0"`, exactly one `Issuer`, an `ID`, `Destination` equal to this IdP's endpoint if present, and `ProtocolBinding` HTTP-POST if present.

HTTP-Redirect query parameters are parsed by the plugin itself: names are decoded before matching (`Relay%53tate` counts as `RelayState`), and every SAML parameter may appear at most once.

**Options.** None: there's nothing to turn off. `schemaValidator` can replace the validator (you shouldn't need to).

**Errors.** `INVALID_SAML_REQUEST` (the log and `npx better-auth-saml-idp decode` show which check failed).

## Timestamp validation

**How it works.**
- A request's `IssueInstant` must carry a time zone, can't be in the future (beyond the skew), and can't be older than **5 minutes** plus the skew. A LogoutRequest's `NotOnOrAfter` is honoured too.
- Assertions the IdP issues carry `NotBefore` (issue time minus the skew) and `NotOnOrAfter` (issue time plus `assertionLifetimeSeconds`), and the `SubjectConfirmationData` carries the same `NotOnOrAfter`, `Recipient` and `InResponseTo`, as SAML2Int requires.

**Options.**

| Option | Default | Effect |
|---|---|---|
| `clockSkewSeconds` | `60` | Tolerance for clock differences, both directions. |
| `assertionLifetimeSeconds` | `300` | How long issued assertions are valid. Over 300 logs a warning. |

**Errors.** `INVALID_SAML_REQUEST` ("IssueInstant is in the future", "AuthnRequest is too old", "IssueInstant must be an xs:dateTime with a time zone").

## Replay protection

**How it works.** Each (SP, request `ID`) may be processed once. The IdP inserts a row keyed by a hash of the pair into `samlIdpSeenRequest`, whose `key` column is UNIQUE: a second insert fails, in any instance, even under concurrency, without depending on KV or caches. Rows expire after the request's validity window and are swept automatically. LogoutRequests go through the same table.

Pending sign-ins and logout steps are stored as Better Auth verification values and **consumed** atomically: each `resume` link, POST re-entry and logout state works once.

**Options.** None.

**Errors.** `DUPLICATE_REQUEST_ID` (a replayed request), `PENDING_REQUEST_NOT_FOUND` / `LOGOUT_STATE_NOT_FOUND` (a used or expired link).

## ACS URL allow-list

**How it works.** A Response is only ever posted to one of the SP's `acsUrls`, compared **exactly** (no normalisation, no prefix matching). A request naming any other URL gets an error page, and the requested URL is never reflected in it. Without a requested URL, the first allow-listed URL is used. `AssertionConsumerServiceIndex` isn't supported (send the URL). ACS URLs must be https (http only for loopback hosts, for development).

**Errors.** `ACS_URL_NOT_ALLOWED`.

## Signed requests

**How it works.**
- **HTTP-Redirect:** the signature covers the exact query octets as received (`SAMLRequest`, `RelayState`, `SigAlg`, in that order, undecoded). A parameter name that needed decoding can't have been signed, so it's refused. This is verified with Node's crypto and the SP's certificate, with no XML involved.
- **HTTP-POST:** an enveloped XML signature on the request, checked with the rules in [XML signature verification](#xml-signature-verification).
- Any of the SP's certificates may have signed (SPs rotate keys). Certificates come from `spCertificate` and/or the SP's [metadata URL](service-providers.md#keeping-sp-certificates-current). A certificate embedded in the message is never trusted.
- If an SP has certificates, a signature that's present but invalid is always refused, even when signing isn't required.

**Options.**

| Option (per SP) | Effect |
|---|---|
| `requireSignedAuthnRequests` | Refuse unsigned requests. |
| `spCertificate` | The SP's signing certificates. |
| `metadata.url` | Learn them from the SP's metadata. |

Logout messages must be signed whenever the SP has certificates, requires signed requests, or uses `metadata`. If no certificate is available (for example a metadata fetch failed), they're refused rather than accepted unsigned.

**Errors.** `UNSIGNED_SAML_REQUEST`.

## XML signature verification

Used for POST-binding requests, SP logout messages, and pinned SP metadata. XML signatures have a long history of *signature wrapping* attacks (a valid signature over one element, while the application reads another), so verification follows an allow-list, checked **before** any cryptography:

1. Exactly one `ds:Signature`, and it's a direct child of the element being processed.
2. Exactly one `Reference`, whose URI is `#` plus that element's `ID`.
3. That ID value appears on exactly one element in the document, across `ID`, `Id` and `id` attributes: every attribute the signature library may resolve a reference through.
4. Canonicalization is exclusive C14N or C14N 1.0, never the `WithComments` variants. Transforms are enveloped-signature and those two only, with no XPath or XSLT. Signature is RSA-SHA256 or RSA-SHA512, digest SHA-256 or SHA-512. SHA-1 is allowed only with `allowInsecureSha1`.
5. No XML comments anywhere in a signed request. Canonicalization drops comments, so text split by one would still verify.
6. Only the configured certificates are tried; `KeyInfo` in the message is ignored.

Each rule has a test that fails when the rule is removed. Without rule 2, the signature library alone accepted a wrapped request end to end.

## Algorithm policy

| What | Default | Opt-in |
|---|---|---|
| Signatures the IdP makes | RSA-SHA256 / SHA-256 | `rsa-sha512` / `sha512`; `rsa-sha1` / `sha1` with `allowInsecureSha1` |
| Signatures the IdP accepts | RSA-SHA256, RSA-SHA512 | RSA-SHA1 with `allowInsecureSha1` |
| Assertion encryption | AES-256-GCM + RSA-OAEP | AES-128-GCM; `rsa-oaep-sha256`; AES-256-CBC with `allowInsecureCbc` |
| Never offered | | RSA PKCS#1 v1.5 key transport; C14N `WithComments`; keys under 2048 bits; non-RSA keys |

`allowInsecureSha1` and `allowInsecureCbc` log a warning at startup.

## Size limits

| Limit | Value | Error |
|---|---|---|
| Decoded request (AuthnRequest, LogoutRequest) | 64 KiB, checked before and during DEFLATE inflation | `INVALID_SAML_REQUEST` |
| RelayState | `relayStateMaxBytes` (default and maximum 1024) | `RELAY_STATE_TOO_LONG` |
| SP metadata fetched from `metadata.url` | 1 MiB, enforced while streaming | refresh fails and the last good copy is kept |
| Registry config (API) | 64 KB of JSON | `INVALID_SERVICE_PROVIDER` |
| Logout participants per session | 200 (more is reported as `PartialLogout`) | |

## Account policy and fresh re-reads

**How it works.** Right before signing, the user is re-read from the database: a deleted or banned user (the admin plugin's `banned`, respecting `banExpires`) gets nothing. Where the database holds sessions, the session row is re-read too, so a revoked or expired session gets nothing, even if Better Auth still has it cached. Then the [account policy](users-and-access.md#account-policy) applies (verified email; no impersonated or anonymous sessions), then the SP's `organization` rule, then `authorize()`.

**Errors.** `ACCOUNT_INACTIVE`, `EMAIL_NOT_VERIFIED`, `SESSION_NOT_ALLOWED`, `ACCESS_DENIED`.

## Browser binding and the POST binding

**How it works.**
- **Resume links are bound to the browser.** When a signed-out user is sent to sign in, the pending request is bound to a random value in a signed cookie in *that* browser. A `resume` link opened in another browser, for example a leaked link, is refused.
- **The HTTP-POST binding needs one extra step.** An SP's POST is a cross-site request, and browsers don't send `SameSite=Lax` cookies on those, so the IdP can't see the user's session. It validates the request, stores it, and answers with a `303` to a single-use, 120-second, same-site GET (`sso?cid=`), where the cookies are present. Single Logout does the same (`slo?cid=`).
- **IdP-initiated SSO and IdP-initiated logout are protected against drive-by CSRF.** A cross-site navigation the user didn't trigger (a Fetch Metadata `Sec-Fetch-Site: cross-site` without `Sec-Fetch-User`) gets a confirmation page instead of acting. Browsers that send neither header aren't challenged, so this narrows the attack rather than closing it.

**Errors.** `PENDING_REQUEST_NOT_FOUND`.

## Pages the IdP serves

- **Auto-POST page** (the Response to the SP): a nonce-based CSP (`default-src 'none'`), `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `no-store`, `Referrer-Policy: no-referrer`, and a `<noscript>` button. There's deliberately **no** `form-action`: browsers apply it to the SP's own redirect after its ACS, which real SPs send to other origins, and that would break sign-in (reproduced in Chromium). The form's action is always an allow-listed ACS URL.
- **Error pages:** the same headers plus `form-action 'none'`. They show a fixed message and a code, never request contents.
- **Everything is escaped:** values placed in XML and HTML (NameID, attributes, RelayState, URLs) are escaped, and RelayState is opaque to the IdP.

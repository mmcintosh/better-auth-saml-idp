# Troubleshooting

[Guide](README.md) › Troubleshooting

Start with the error code on the page (see the [error reference](errors.md)), the server log (the plugin logs as `[saml-idp]`; failed requests log the exact reason at debug level), and `npx better-auth-saml-idp decode` on the message from the browser's network tab.

## The SP says the signature is invalid, or the certificate isn't configured

- Compare fingerprints: `npx better-auth-saml-idp inspect https://auth.example.com` shows the SHA-256 fingerprint of each published certificate. The SP's must match the one that signs (`signing.certificate`).
- After a key rotation, the SP may still have the old certificate. See [key rotation](../key-rotation.md).
- **Cloudflare Access:** add each certificate as a separate entry. Pasting two PEM blocks into one box makes it trust neither ("Response uses a certificate that is not configured").
- Some SPs want only the Response or only the Assertion signed: set `signResponse` / `signAssertion` on that SP.
- SPs that can only do SHA-1 need `allowInsecureSha1` (and a warning comes with it).

## `UNKNOWN_SERVICE_PROVIDER`

The SP's `Issuer` doesn't match any `entityId` exactly. Decode the request to see it:

```bash
npx better-auth-saml-idp decode "<the /saml2/idp/sso?SAMLRequest=… URL>"
```

Look for scheme (`http` vs `https`), host, path and a trailing slash. With the registry, the SP may be disabled or its stored config may no longer validate (the log says so, and the API shows `valid: false`); other isolates may also still cache a miss for up to `cacheSeconds`.

## `ACS_URL_NOT_ALLOWED`

The SP asked for an ACS URL that isn't exactly in its `acsUrls`. Decode the request, then add that exact URL. There's no normalisation: case, trailing slashes and query strings all matter.

## `INVALID_SAML_REQUEST`

The debug log says which check failed. Common causes:
- **"IssueInstant is in the future" / "too old"**: the SP's clock is off, or the request is over 5 minutes old (a reused link). `clockSkewSeconds` allows up to 300.
- **"Destination does not match"**: the SP is configured with a different SSO URL than your metadata's. That's often a missing `baseURL`, so metadata built from the Host header differs from what the SP was given.
- **"only the HTTP-POST response binding is supported"**: the SP asked for the Artifact binding.
- **"AssertionConsumerServiceIndex is not supported"**: the SP must send `AssertionConsumerServiceURL`.
- **"schema: …"**: the SP sent XML that isn't valid SAML. `decode` shows the libxml2 message.

## `UNSIGNED_SAML_REQUEST`

The SP must sign (`requireSignedAuthnRequests`), or it has certificates and its signature didn't verify. `decode "<URL>" --cert sp.crt` verifies it exactly as the IdP does. Check that `spCertificate` has the SP's current certificate. With `metadata.url`, the log shows whether the last refresh failed.

## The user is sent to sign in again and again

- The sign-in page must send the browser to `callbackURL` after signing in. See [the sign-in page contract](getting-started.md#5-return-users-from-your-sign-in-page).
- The resume link only works in the browser that started the sign-in (it's bound to a cookie). Opening it elsewhere gives `PENDING_REQUEST_NOT_FOUND`.
- Cookies must reach the IdP. A sign-in page on another domain than the IdP can't set the IdP's session cookie.

## `EMAIL_NOT_VERIFIED`

The user hasn't verified their email, and the default [account policy](users-and-access.md#account-policy) requires it. Users created by an upstream SSO provider keep whatever `emailVerified` that provider gave them.

## `RELAY_STATE_TOO_LONG`

The SP's RelayState is over `relayStateMaxBytes`. The default and maximum is 1024 bytes; the spec says 80, but real SPs (Cloudflare Access among them) send more.

## Cloudflare Access: "Invalid login session"

An IdP-initiated sign-in: Cloudflare Access doesn't accept unsolicited Responses. Link to the protected application (or the App Launcher) instead; Access then starts an SP-initiated sign-in. See the [Cloudflare guide](../sp-cloudflare-access.md).

## Single Logout doesn't reach an SP

- The SP needs a `singleLogoutService`, and must have received an assertion in *this* session.
- An SP that doesn't send the browser back stops the chain; the originator is told `PartialLogout` when the IdP can tell.
- An SP that can only receive POST needs `binding: "post"`.

## The metadata refresh isn't picking up the SP's new certificate

- The log shows `[saml-idp] SP x: metadata refresh … failed (…)` with the reason: HTTP status, a redirect (not followed), `validUntil`, schema, the entity ID, or the pinned signature.
- A refresh happens every `refreshSeconds` (default a day), per isolate. After a failure it retries in 5 minutes, doubling.
- On Workers, [wire `waitUntil`](cloudflare-workers.md#background-tasks-wire-waituntil).

## Workers: "exceeded CPU" on the first request

The first SAML request in an isolate compiles the XSD validator (WebAssembly). Use Workers Paid; see [Cloudflare Workers](cloudflare-workers.md#requirements).

## Still stuck

Run `npx better-auth-saml-idp smoke` against the deployment to rule out the IdP side, and open an issue with the `decode --json` output. Remove personal data first: the NameID and attributes.

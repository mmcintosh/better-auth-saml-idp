# Error reference

[Guide](README.md) › Errors

The plugin reports problems in one of three ways:

1. **An HTML error page**, shown in the user's browser, for anything that can't safely go back to the SP: an unknown SP, an ACS URL that isn't allow-listed, a malformed or unsigned request, a replay. The page shows only a fixed message and the code (for example `ACS_URL_NOT_ALLOWED`), never the request contents. The details go to the server log at debug level.
2. **A signed SAML error Response** posted to the SP, when the request was valid but can't be satisfied (see [SAML status Responses](#saml-status-responses) below). The SP decides what to show.
3. **A JSON API error** from the [registry API](service-providers.md#registry-api), in Better Auth's usual `{ code, message }` shape.

Every error page is served with `Content-Security-Policy: default-src 'none'; form-action 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY` and `Cache-Control: no-store`.

The codes are exported as `SAML_IDP_ERROR_CODES` (and appear on the plugin's `$ERROR_CODES`).

## Sign-in errors (HTML page)

| Code | HTTP | Message | When it happens | What to do |
|---|---|---|---|---|
| `UNKNOWN_SERVICE_PROVIDER` | 400 | Unknown SAML service provider | The AuthnRequest's `Issuer` (or `/init?sp=`, or a stored request's SP) isn't registered, or a stored SP is disabled or no longer validates. | Register the SP. The `entityId` must match the SP's Issuer **exactly** (scheme, host, trailing slash). `npx better-auth-saml-idp decode` shows the Issuer the SP sent. |
| `ACS_URL_NOT_ALLOWED` | 400 | AssertionConsumerServiceURL is not registered for this service provider | The request names an `AssertionConsumerServiceURL` that isn't exactly one of the SP's `acsUrls`. The URL is never reflected in the page. | Add the exact URL to `acsUrls`. No normalisation is applied: `https://sp/acs` and `https://sp/acs/` are different. |
| `IDP_INITIATED_NOT_ALLOWED` | 400 | This application does not accept sign-in started from the identity provider | `/saml2/idp/init?sp=…` for an SP without `allowIdpInitiated`, or the opt-in was removed while the user signed in. | Set `allowIdpInitiated: true` on the SP, if the SP accepts unsolicited Responses. See [IdP-initiated SSO](flows.md#idp-initiated-sso). |
| `INVALID_SAML_REQUEST` | 400 | Invalid SAML request | The message failed a check: size, DOCTYPE, DEFLATE limit, base64, XSD schema, structure (root element, Version, one Issuer), `IssueInstant` (missing time zone, older than 5 minutes, or in the future), `Destination` not this IdP, a `ProtocolBinding` other than HTTP-POST, `AssertionConsumerServiceIndex` without a URL, `Subject` with BaseID/EncryptedID, duplicate or percent-encoded parameter names, SHA-1 without the opt-in, or an unsupported SigAlg. | Turn on debug logging for the exact reason, or run `npx better-auth-saml-idp decode "<URL>"`, which runs the same checks. |
| `UNSIGNED_SAML_REQUEST` | 400 | This service provider requires signed AuthnRequests | The SP requires signed requests (`requireSignedAuthnRequests`) and the request is unsigned, or it has certificates and the signature doesn't verify, or the signature fails the [XML signature rules](security.md#xml-signature-verification). Also used for logout messages that must be signed. | Check the SP's certificate in `spCertificate` (or `metadata.url`). `decode --cert sp.crt` verifies the signature exactly as the IdP does. |
| `DUPLICATE_REQUEST_ID` | 400 | This AuthnRequest has already been processed | The same (SP, request `ID`) was seen before: a replay, a double-submitted form, or an SP reusing IDs. Also for replayed LogoutRequests. | Nothing, for replays. An SP that reuses IDs is broken; see [Replay protection](security.md#replay-protection). |
| `RELAY_STATE_TOO_LONG` | 400 | RelayState exceeds the allowed length | `RelayState` is over `relayStateMaxBytes` (default 1024). | Raise `relayStateMaxBytes` (1024 at most), or shorten the SP's RelayState. |
| `PENDING_REQUEST_NOT_FOUND` | 400 | The SAML sign-in request has expired or was already used | The `resume` or `cid` link is unknown, expired (`pendingRequestTtlSeconds`, 600 s by default; 120 s for the POST re-entry), already used, or opened in a different browser from the one that started it. | Start again from the application. If users take longer than 10 minutes to sign in, raise `pendingRequestTtlSeconds`. |
| `ACCESS_DENIED` | 403 | You are not allowed to sign in to this application | `authorize()` returned something other than `true` or threw, or the SP's `organization` rule didn't match (or the organization plugin isn't installed). | Check your `authorize` function and the user's organization membership and roles. |
| `ACCOUNT_INACTIVE` | 403 | Your account is not active | The user was deleted or banned (admin plugin, respecting `banExpires`), or the session row was revoked or expired. Checked against the database right before signing. | Unban the user, or have them sign in again. |
| `EMAIL_NOT_VERIFIED` | 403 | Verify your email address before signing in to this application | `accountPolicy.requireEmailVerified` (the default) and the user's email isn't verified. | The user verifies their email. See [Account policy](users-and-access.md#account-policy). |
| `SESSION_NOT_ALLOWED` | 403 | This kind of session cannot be used to sign in to other applications | An admin-impersonation session, or an anonymous user, while the account policy refuses them (the default). | See [Account policy](users-and-access.md#account-policy). |
| `REAUTHENTICATION_REQUIRED` | 401 | This application requires you to sign in again | The SP sent `ForceAuthn="true"` and the session that came back through `resume` is older than the request. | The user signs in again (not just returning with the existing session). |
| `INTERNAL_ERROR` | 500 | Sign-in could not be completed | `nameId()` or `attributes()` threw or returned an empty NameID, organization memberships couldn't be loaded, or a logout participant couldn't be recorded. | See the server log (`[saml-idp] …`). |

## Logout errors (HTML page, titled "Sign-out could not be completed")

| Code | HTTP | Message | When it happens | What to do |
|---|---|---|---|---|
| `LOGOUT_NOT_SUPPORTED` | 400 | This application isn't set up for single logout | A LogoutRequest from an SP without `singleLogoutService`, or the originating SP lost it mid-logout. | Configure the SP's `singleLogoutService`. |
| `LOGOUT_STATE_NOT_FOUND` | 400 | The logout has expired or was already completed | A LogoutResponse or `slo?cid=` for an unknown, used or expired (5 min) logout. | Nothing; the IdP session already ended at the start of the logout. |
| `INVALID_RETURN_TO` | 400 | The return address after logout is not allowed | `/saml2/idp/logout?returnTo=` isn't a same-origin path or a Better Auth trusted origin. | Use a path (`/signed-out`), or add the origin to `trustedOrigins`. |

## Registry API errors (JSON)

| Code | HTTP | When |
|---|---|---|
| `UNAUTHORIZED` (Better Auth) | 401 | No valid session. |
| `REGISTRY_NOT_ALLOWED` | 403 | `canManage` didn't return `true` (or threw), the admin-plugin role check denied the action, or the session is an impersonation. |
| `INVALID_ORIGIN` (Better Auth) | 403 | A mutation from an untrusted origin. |
| `INVALID_SERVICE_PROVIDER` | 400 | The configuration failed validation; the response has `issues: string[]`, the same messages as startup validation. |
| `SERVICE_PROVIDER_EXISTS` | 409 | The `id` or `entityId` is taken by another stored SP. |
| `SERVICE_PROVIDER_IN_CODE` | 409 | The `id` or `entityId` belongs to an SP defined in code, which always wins. |
| `SERVICE_PROVIDER_NOT_FOUND` | 404 | `get`, `update` or `delete` of an id that isn't stored. |

## SAML status Responses

When a request is valid and the SP and ACS URL are trusted, a request that can't be satisfied gets a **signed SAML Response with an error status** instead of an error page, posted to the SP as usual. No assertion is included.

| Status (top / second level) | When |
|---|---|
| `Responder` / `NoPassive` | `IsPassive="true"` and the user has no session. |
| `Responder` / `NoAuthnContext` | `RequestedAuthnContext` can't be satisfied: our `authnContextClassRef` isn't listed (`exact`, `minimum`, `maximum`), `Comparison="better"`, or `AuthnContextDeclRef` is used. |
| `Responder` / `UnknownPrincipal` | The request's `Subject` names someone other than the signed-in user. |
| `Requester` / `InvalidNameIDPolicy` | `NameIDPolicy@Format` isn't the SP's `nameIdFormat` (or `unspecified`). |

A LogoutResponse carries `Success`, or `Success` / `PartialLogout` when an SP in the session couldn't be logged out; see [Single Logout](single-logout.md).

## Configuration errors (startup)

Invalid options throw `SamlIdpConfigError` when `samlIdp()` is called, listing every issue (`path: message`); `error.issues` has them as an array. Warnings (for example "no baseURL", "certificate expires in 12 days", "metadata signature isn't pinned") are logged once at startup. Run `npx better-auth-saml-idp check-config config.json` to see both without starting the app.

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
| `UNKNOWN_SERVICE_PROVIDER` | 400 | Unknown SAML service provider | The AuthnRequest's `Issuer` (or a missing `/init?sp=`, or a stored request's SP) isn't registered, or a stored SP is disabled or no longer validates. | Register the SP. The `entityId` must match the SP's Issuer **exactly** (scheme, host, trailing slash). `npx better-auth-saml-idp decode` shows the Issuer the SP sent. |
| `ACS_URL_NOT_ALLOWED` | 400 | AssertionConsumerServiceURL is not registered for this service provider | The request names an `AssertionConsumerServiceURL` that isn't exactly one of the SP's `acsUrls`. The URL is never reflected in the page. | Add the exact URL to `acsUrls`. No normalisation is applied: `https://sp/acs` and `https://sp/acs/` are different. |
| `IDP_INITIATED_NOT_ALLOWED` | 400 | This application does not accept sign-in started from the identity provider | `/saml2/idp/init?sp=…` for an SP without `allowIdpInitiated`, or one that doesn't exist (answered alike, so SP ids can't be listed), or the opt-in was removed while the user signed in. | Set `allowIdpInitiated: true` on the SP, if the SP accepts unsolicited Responses. See [IdP-initiated SSO](flows.md#idp-initiated-sso). |
| `INVALID_SAML_REQUEST` | 400 | Invalid SAML request | The message failed a check: size, DOCTYPE, DEFLATE limit, base64, XSD schema, structure (root element, Version, one Issuer), `IssueInstant` (missing time zone, older than 5 minutes, or in the future), `Destination` not this IdP, a `ProtocolBinding` other than HTTP-POST, `AssertionConsumerServiceIndex` without a URL, `Subject` with BaseID/EncryptedID, duplicate or percent-encoded parameter names, SHA-1 without the opt-in, or an unsupported SigAlg. | Turn on debug logging for the exact reason, or run `npx better-auth-saml-idp decode "<URL>"`, which runs the same checks. |
| `UNSIGNED_SAML_REQUEST` | 400 | This service provider requires signed AuthnRequests | The SP requires signed requests (`requestSignatures: "require"`) and the request is unsigned, or it has certificates and the signature doesn't verify, or the signature fails the [XML signature rules](security.md#xml-signature-verification). Also used for logout messages that must be signed. | Check the SP's certificate in `spCertificates` (or `metadata.url`). `decode --cert sp.crt` verifies the signature exactly as the IdP does. |
| `DUPLICATE_REQUEST_ID` | 400 | This AuthnRequest has already been processed | The same (SP, request `ID`) was seen before: a replay, a double-submitted form, or an SP reusing IDs. Also for replayed LogoutRequests. | Nothing, for replays. An SP that reuses IDs is broken; see [Replay protection](security.md#replay-protection). |
| `RELAY_STATE_TOO_LONG` | 400 | RelayState exceeds the allowed length | `RelayState` is over `relayStateMaxBytes` (default 4096). | Raise `relayStateMaxBytes` (4096 at most), or shorten the SP's RelayState. |
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
| `INVALID_TENANT` | 400 | [Tenant](multi-tenant.md#create-a-tenant) creation: no organization with that id, a `tenantKey` that isn't 1 to 64 of `A–Z a–z 0–9 _ -` (the organization id is used by default, and may not qualify), or one that is another organization's id; `issues` says which. |
| `TENANT_EXISTS` | 409 | The organization is already a tenant, or the `tenantKey` is taken. |
| `TENANT_NOT_FOUND` | 404 | `get`, `update` or `delete` of an organization that isn't a tenant. |
| `TENANT_HAS_SERVICE_PROVIDERS` | 409 | Deleting a tenant that still has SPs, in code or stored. Remove them first. |
| `TENANT_KEY_RETIRED` | 409 | Creating a tenant with a key that belonged to a deleted tenant. Keys are never reused ([why](multi-tenant.md#deleting-tenants-and-organizations)); choose another. |
| `INVALID_TENANT_SIGNING_KEY` | 400 | [Rotating](multi-tenant.md#rotating-a-tenants-key) in an uploaded key that isn't a matching RSA pair of at least 2048 bits, or only one of `privateKey` and `certificate`; `issues` says which. |
| `TENANT_SIGNING_KEY_EXISTS` | 409 | `rotate` while the tenant already has a next key: activate it first. |
| `TENANT_SIGNING_KEY_NOT_FOUND` | 409 | `activate` without a next key, or `retire` without a previous one (`state` says which). |
| `TENANT_SIGNING_KEY_TOO_NEW` | 409 | `activate` before the next key has been published for `minPublishedSeconds`; `activatableAt` says when. `force: true` skips the wait (for a leaked key). |

With tenants, `INVALID_SERVICE_PROVIDER` also covers an SP naming a `tenant` that doesn't exist, a change of `tenant` on update, and an `organization` rule on a tenant SP other than `{ id: <its tenant>, roles? }`. A request at an unknown or disabled tenant's URL, or naming an SP of another tenant, is the sign-in error `UNKNOWN_SERVICE_PROVIDER`; a tenant's metadata URL answers a plain `404 Not Found`.

## Assertion exchange errors

Thrown as `AssertionExchangeError` (`code`, and a message for your logs) by `verifyIssuedAssertion` to the authorization server that calls it ([Exchanging assertions for OAuth tokens](token-exchange.md)). Never shown to users. The calling server should answer the client with one generic error for all of them except the time codes, so a client can't tell `WRONG_CLIENT` or `ALREADY_EXCHANGED` apart from a forgery.

| Code | When it happens | Uses up the assertion? |
|---|---|---|
| `MALFORMED` | Not a lone, schema-valid `<saml:Assertion>` within 64 KiB, or not exactly the shape this IdP issues (a Response, an EncryptedAssertion, a DOCTYPE, an extra condition…). | No |
| `NOT_OURS` | The Issuer isn't this IdP or an enabled tenant, or the tenant's own key can't be used; or the assertion doesn't match what was recorded when it was issued. | No; yes for a record mismatch |
| `BAD_SIGNATURE` | Unsigned, signed by another key, or failing the XML signature rules (wrapping, algorithms, references). | No |
| `NOT_YET_VALID` / `EXPIRED` | Outside `NotBefore` and `NotOnOrAfter`, with `clockSkewSeconds`. Checked only after the signature. | No |
| `NOT_EXCHANGEABLE` | The audience SP is unknown, disabled, in another tenant, or has no `tokenExchange`. | No |
| `WRONG_CLIENT` | The SP's `tokenExchange.clientId` is a different client. | No |
| `ALREADY_EXCHANGED` | No record: exchanged before, expired, issued before the SP opted in, or its record couldn't be written at sign-in (logged as an error then). | (already gone) |
| `ACCOUNT_INACTIVE` | The user was deleted or banned, the email isn't verified (with `requireEmailVerified`), the user is anonymous or the session impersonated (unless allowed), the session ended, or the user left the SP's organization or tenant. | Yes |

## SAML status Responses

When a request is valid and the SP and ACS URL are trusted, a request that can't be satisfied gets a **signed SAML Response with an error status** instead of an error page, posted to the SP as usual. No assertion is included.

| Status (top / second level) | When |
|---|---|
| `Responder` / `NoPassive` | `IsPassive="true"` and the user has no session. |
| `Responder` / `NoAuthnContext` | `RequestedAuthnContext` can't be satisfied. With a fixed `authnContextClassRef`: it isn't listed (`exact`, `minimum`, `maximum`), `Comparison="better"`, or `AuthnContextDeclRef` is used. With `authnContext` levels: no level can deliver it, or the session still didn't after the user signed in again ([step-up](flows.md#requestedauthncontext)). |
| `Responder` / `UnknownPrincipal` | The request's `Subject` names someone other than the signed-in user. |
| `Requester` / `InvalidNameIDPolicy` | `NameIDPolicy@Format` isn't the SP's `nameIdFormat` (or `unspecified`). |

A LogoutResponse carries `Success`, or `Success` / `PartialLogout` when an SP in the session couldn't be logged out; see [Single Logout](single-logout.md).

## Configuration errors (startup)

Invalid options throw `SamlIdpConfigError` when `samlIdp()` is called, listing every issue (`path: message`); `error.issues` has them as an array. Warnings (for example "no baseURL", "certificate expires in 12 days", "metadata signature isn't pinned") are logged once at startup. Run `npx better-auth-saml-idp check-config config.json` to see both without starting the app.

With `tenants.enabled`, these are errors too, some when Better Auth starts rather than when `samlIdp()` is called: no organization plugin, no pinned base URL, no `registry.enabled`, and `tenants.delegation` without `keys: "per-tenant"`. A `tenant` on an SP without `tenants.enabled` is an error; an SP whose entity ID and an ACS URL match an SP in another tenant is a warning ([why](multi-tenant.md#signing-keys-shared-or-per-tenant)).

With per-tenant keys, a tenant whose own key can't be loaded (its secret version is gone, its row is damaged) refuses its sign-ins with `INTERNAL_ERROR` and its metadata with a 500, and logs why; it never signs with another key ([Per-tenant signing keys](multi-tenant.md#per-tenant-signing-keys)).

# Sign-in flows

[Guide](README.md) › Sign-in flows

## Endpoints

All paths are relative to your Better Auth base path (for example `/api/auth`).

| Method | Path | Purpose |
|---|---|---|
| GET | `/saml2/idp/metadata` | IdP metadata for SPs: entity ID, SSO (and SLO) URLs, certificates. `application/samlmetadata+xml`, `Cache-Control: private, max-age=300`, `Vary: Host`. |
| GET, POST | `/saml2/idp/sso` | Receives AuthnRequests over HTTP-Redirect (GET) and HTTP-POST. |
| GET | `/saml2/idp/sso?cid=` | Same-site re-entry of an HTTP-POST request (internal). |
| GET | `/saml2/idp/resume?rid=` | Where the sign-in page sends the user back (`callbackURL`). |
| GET | `/saml2/idp/init?sp=<id>` | IdP-initiated SSO, for SPs with `allowIdpInitiated`. |
| GET, POST | `/saml2/idp/slo` | [Single Logout](single-logout.md) messages from SPs. |
| GET | `/saml2/idp/logout?returnTo=` | IdP-initiated Single Logout. |
| GET, POST | `/saml-idp/service-providers/*` | [Registry API](service-providers.md#registry-api). |

## SP-initiated SSO

This is the normal flow: the user visits the SP, which sends them to the IdP with an AuthnRequest.

```
Browser            SP                          IdP (Better Auth)
   │  visit app     │                                │
   │───────────────>│                                │
   │  302 + AuthnRequest (Redirect) or auto-POST     │
   │<───────────────│                                │
   │──────────────────────────────────────────────── >│  /saml2/idp/sso
   │                                                  │  validate · replay check · SP lookup
   │                                                  │  signed? · ACS allow-list
   │        302 /sign-in?callbackURL=…/resume?rid=    │  (no session: park the request)
   │<──────────────────────────────────────────────── │
   │  sign in ─────────────────────────────────────── >│
   │  → callbackURL (resume) ──────────────────────── >│  re-read user · policy · authorize
   │                                                  │  sign (encrypt) Response
   │        auto-POST SAMLResponse → ACS URL          │
   │<──────────────────────────────────────────────── │
   │───────────────>│  verify, sign in               │
```

Step by step:

1. **Decode and validate** the request: size, DEFLATE, XSD, structure, `IssueInstant`, `Destination` ([details](security.md#inbound-message-validation)). RelayState is checked against `relayStateMaxBytes`.
2. **Find the SP** by the request's `Issuer`: code SPs first, then the [registry](service-providers.md#registry). Unknown means `UNKNOWN_SERVICE_PROVIDER`.
3. **Check the signature**, if the SP signs or requires signing ([signed requests](security.md#signed-requests)).
4. **Resolve the ACS URL**: the requested one if it's allow-listed, otherwise the first `acsUrls` entry. Anything else is `ACS_URL_NOT_ALLOWED`.
5. **Replay check**: the (SP, request `ID`) pair is recorded; a second time is `DUPLICATE_REQUEST_ID`.
6. **Unsatisfiable requests** get a signed SAML status Response (see [below](#requests-the-idp-cant-satisfy)).
7. **No session, or `ForceAuthn`**: the request is stored (bound to this browser) and the user is sent to `loginPage`. After signing in, they come back through `resume`.
8. **Issue**: the user and session are re-read from the database, then the [account policy](users-and-access.md#account-policy), the SP's `organization` rule and `authorize()` run. The NameID and attributes are computed, and the Response is signed (and encrypted), then auto-posted to the ACS URL with the RelayState.

### Bindings

- **HTTP-Redirect** (GET, DEFLATE + base64). Cookies arrive normally, so the IdP sees the session at once.
- **HTTP-POST** (a cross-site form POST). Browsers don't send `SameSite=Lax` cookies on it, so the IdP validates the request and answers `303` to a single-use, same-site `sso?cid=` GET, where the session is visible. This is transparent to users and SPs. node-saml's non-standard DEFLATEd POST requests are accepted too.
- **Responses** always use HTTP-POST (an auto-submitting form with a `<noscript>` button). The Artifact binding isn't supported.

### Requests the IdP can't satisfy

A valid request from a known SP that the IdP can't honour gets a signed SAML Response with an error status, posted to the SP, instead of an error page:

| The request says | The IdP answers |
|---|---|
| `IsPassive="true"` and the user has no session | `Responder` / `NoPassive` |
| `RequestedAuthnContext` the IdP can't meet | `Responder` / `NoAuthnContext` |
| a `Subject` other than the signed-in user | `Responder` / `UnknownPrincipal` |
| `NameIDPolicy` with another format than the SP's | `Requester` / `InvalidNameIDPolicy` |

### ForceAuthn and IsPassive

- **`ForceAuthn="true"`**: the user must sign in again, even with a session. The session that comes back through `resume` must be newer than the request, otherwise `REAUTHENTICATION_REQUIRED`. Verified live with Cloudflare Access's "reauthenticate" setting.
- **`IsPassive="true"`**: the IdP must not interact with the user. With a session, they're signed in silently; without one, the SP gets `NoPassive`.

### RequestedAuthnContext

Two ways to say how users authenticated:

**A fixed class** (`authnContextClassRef`, `unspecified` by default). Every assertion states it. A request's `RequestedAuthnContext` is satisfied when that value is listed (with `Comparison` `exact`, `minimum` or `maximum`). `Comparison="better"` and `AuthnContextDeclRef` are never satisfied, because there's no ordering between classes. Set it to what your sign-in really guarantees, for example `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` for password sign-in over TLS.

**Step-up levels** (`authnContext`), as Keycloak does with levels of authentication. List the classes your sign-in can deliver, weakest first, and say which one the current session achieved:

```ts
const PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const MFA = "https://refeds.org/profile/mfa";

samlIdp({
  // …
  authnContext: {
    levels: [PASSWORD, MFA],
    // Better Auth's two-factor plugin only creates a session after the second factor, so a
    // session of a user with 2FA on passed it (see the caveat below).
    current: ({ user }) => (user.twoFactorEnabled === true ? MFA : PASSWORD),
  },
});
```

For each SP request:
- **Already met:** the assertion states the class the session achieved. Comparisons follow SAML Core §3.3.2.2.1 on your level order: `exact` (listed), `minimum` (at least as strong), `better` (stronger), `maximum` (no stronger). Classes outside `levels` only match exactly.
- **Reachable but not met:** the user goes back to your `loginPage` with `prompt=login` and `acr_values=<the weakest class that would do>`. Your page must then require what that class means (for example the second factor, or enrolling one), and a fresh session is required. On the new session the request is judged again.
- **Not met after that,** or not reachable by any level: the SP gets `NoAuthnContext`, with no loops. An IsPassive request that would need a step-up gets `NoPassive`.
- `current` runs on the user and session as re-read just before signing. It must return one of `levels`; anything else, or a throw, issues nothing (`INTERNAL_ERROR`).
- **Be precise about what a session proves.** With Better Auth's two-factor "trust this device" option, a user with 2FA on may sign in without the second factor. If your app has that, or any way to create sessions without credentials, record when the second factor was actually completed (a session field) and have `current` read it.
- `authnContext` and `authnContextClassRef` are exclusive.

## IdP-initiated SSO

The user starts at your app ("Open HubSpot") instead of at the SP. The IdP posts an **unsolicited** Response, with no `InResponseTo`.

```ts
{
  id: "hubspot",
  entityId: "…",
  acsUrls: ["…"],
  allowIdpInitiated: true,
  idpInitiatedRelayState: "https://app.hubspot.com/",       // optional: where the SP lands the user
  allowedRelayStates: ["https://app.hubspot.com/reports"],  // optional: values a link may choose
}
```

Link to `/api/auth/saml2/idp/init?sp=hubspot` (or `authClient.samlIdp.launch("hubspot")`).

- **Off by default, per SP.** Unsolicited Responses are easier to misuse, and the SP must accept them. **Cloudflare Access doesn't** (tested: "Invalid login session"). Check your SP first.
- **Without a session**, the user signs in first and comes back through `resume`; the opt-in is checked again then.
- **RelayState** comes only from `allowedRelayStates` (exact match) or `idpInitiatedRelayState`; any other value a link passes is ignored. That keeps launcher links from becoming open redirects at the SP.
- **Drive-by protection:** a cross-site navigation the user didn't make (a script or an embedded redirect) gets a confirmation page instead of an assertion. Clicked links and bookmarks go straight through.
- **Replay** of an unsolicited Response can't be detected by `InResponseTo`, so SPs should track assertion IDs, and short assertion lifetimes help.

**Errors.** `UNKNOWN_SERVICE_PROVIDER` (no or unknown `sp`), `IDP_INITIATED_NOT_ALLOWED`.

## Metadata

`/saml2/idp/metadata` publishes the entity ID, the SSO URL for both bindings, the NameID formats in use, the signing certificate and any `additionalCertificates`, the SLO URL when [Single Logout](single-logout.md) is on, and `WantAuthnRequestsSigned="true"` only when every SP requires signing (never with a registry, since SPs added later might not). With `signMetadata: true`, the document is signed. `npx better-auth-saml-idp inspect <url>` shows what SPs see.

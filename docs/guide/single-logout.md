# Single Logout

[Guide](README.md) › Single Logout

Signing out of one application can sign the user out of the IdP and of every other application they reached through it. That's SAML Single Logout (SLO).

## Enable it

```ts
samlIdp({
  // …
  singleLogout: { enabled: true },
  serviceProviders: [
    {
      id: "app",
      entityId: "https://app.example.com/saml/metadata",
      acsUrls: ["https://app.example.com/saml/acs"],
      spCertificate: appCert,                                   // strongly recommended, see below
      singleLogoutService: { url: "https://app.example.com/saml/slo" }, // binding: "redirect" (default) | "post"
    },
  ],
});
```

This adds:
- the `samlIdpSessionParticipant` table ([schema](schema.md#samlidpsessionparticipant-with-singlelogoutenabled); D1 migration `0004`);
- the `/saml2/idp/slo` endpoint, for SPs' LogoutRequests and LogoutResponses over both bindings;
- the `/saml2/idp/logout` endpoint, for IdP-initiated logout;
- `SingleLogoutService` in the IdP metadata.

SPs take part when they have a `singleLogoutService`. `serviceProviderFromMetadata` fills it in from the SP's metadata. Cloudflare Access doesn't support SAML SLO.

## How it works

Every time an SP receives an assertion, the IdP records it as a **participant** of the session: the NameID and SessionIndex that SP was given.

### Started by an SP

```
User clicks "sign out" at SP A
   │ A → IdP: LogoutRequest (signed)        /saml2/idp/slo
   │ IdP: authenticate the request, END THE IDP SESSION
   │ IdP → B: LogoutRequest (signed by the IdP)   ─┐ one hop per other participant,
   │ B → IdP: LogoutResponse                        ─┘ through the browser
   │ IdP → A: LogoutResponse  Success | Success/PartialLogout
```

1. The LogoutRequest is validated (XSD, structure, `IssueInstant`, `Destination`, RelayState size), authenticated (see below), and checked for replay.
2. It must be about **this browser's** session: its SessionIndex must be the one this SP was given for this session. A signed request without a SessionIndex must name the NameID this SP was given. A request about anyone else ends nothing, and is still answered `Success`, since there's no session of that principal here.
3. **The IdP session ends first**: the Better Auth session row, its cookie (cleared even on auto-POST pages) and the participant list. Everything after this is notification; if the chain breaks, the user is already signed out of the IdP.
4. Each **other** participant gets a LogoutRequest signed by the IdP, over its binding (query-signed Redirect, or an auto-posted, XML-signed form). Its LogoutResponse comes back to `/saml2/idp/slo` and continues the chain. The state of each step is a single-use value named by the RelayState, valid for 5 minutes.
5. The originating SP gets a signed LogoutResponse over its binding, to `responseUrl` if set:
   - `Success` when every participant confirmed;
   - `Success` / `PartialLogout` when one failed, answered for another request, had a bad signature, has no `singleLogoutService`, or couldn't be listed.

An HTTP-POST LogoutRequest is a cross-site POST without cookies, so, as for sign-in, it re-enters on a single-use same-site `slo?cid=` GET before the session is looked at.

### Started by your app

Put a "sign out everywhere" link or button in your app:

```ts
authClient.samlIdp.signOutEverywhere({ returnTo: "/" });
// or link to /api/auth/saml2/idp/logout?returnTo=%2F
```

The IdP ends its session, notifies every participant in turn, then redirects to `returnTo`. That must be a same-origin path or an origin in Better Auth's `trustedOrigins` (otherwise `INVALID_RETURN_TO`). Without a session, it just redirects. A cross-site drive-by (not a click) gets a confirmation page first, so other sites can't silently sign your users out everywhere.

Better Auth's own `/sign-out` only ends the IdP session. Use `signOutEverywhere` where you want SPs signed out too.

## Authentication of LogoutRequests

A forged LogoutRequest could sign someone out, so every one must be authenticated:

- **SPs with certificates** (`spCertificate` or `metadata.url`), or that require signed requests, **must sign** their logout messages, and the signature is verified like an AuthnRequest's. If no certificate is available, for example because a metadata fetch failed, the message is refused rather than accepted unsigned.
- **SPs without certificates** can end the session only with the right SessionIndex. That's a keyed MAC over (session, SP), different for every SP and every session, known only to the SP it was sent to. One SP's value can't end the session in another SP's name.

Give SPs that use SLO a certificate. For certificate-less SPs, anyone can make the IdP produce a signed `Success` LogoutResponse addressed to that SP (with no effect at the IdP), so such SPs must check `InResponseTo` against their own pending logout.

## Options and errors

| Option | Where | Description |
|---|---|---|
| `singleLogout.enabled` | server | Turns SLO on. |
| `singleLogoutService.url` | SP | Where the SP receives LogoutRequests. |
| `singleLogoutService.binding` | SP | `"redirect"` (default) or `"post"`, for both directions. |
| `singleLogoutService.responseUrl` | SP | Where the SP receives LogoutResponses, if not `url`. |

| Error | When |
|---|---|
| `LOGOUT_NOT_SUPPORTED` | The SP has no `singleLogoutService`. |
| `UNSIGNED_SAML_REQUEST` | A LogoutRequest that must be signed isn't, or doesn't verify. |
| `DUPLICATE_REQUEST_ID` | A replayed LogoutRequest. |
| `LOGOUT_STATE_NOT_FOUND` | An unknown, used or expired logout step. |
| `INVALID_RETURN_TO` | `returnTo` isn't same-origin or trusted. |
| `INTERNAL_ERROR` | At sign-in: the participant couldn't be recorded, so no assertion is issued (a later logout couldn't reach the SP). |

## Limits

Front-channel logout is best effort by nature, everywhere:
- An SP that never sends the browser back stops the chain there. The IdP session is already over.
- If the user closes the tab mid-chain, the remaining SPs aren't notified.
- At most 200 participants per session are notified; beyond that the answer is `PartialLogout`.
- Participant records follow the session's expiry, including Better Auth's sliding refresh, and are swept when it expires.

Tested with node-saml as the SP, in both directions: its signed LogoutRequest ends the session, and it validates the IdP's LogoutResponse.

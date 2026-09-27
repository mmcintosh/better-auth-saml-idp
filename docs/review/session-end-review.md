# Design review: telling SAML SPs when an IdP session ends out of band

Reviewer: independent, fresh eyes. Date: 2026-09-27. Scope: better-auth-saml (Repo A, `main` @ c6d68a4) and conexxus-auth (Repo B), read-only.
Key: **[code]** = verified by reading code (file:line); **[spec]** = OASIS text; **[doc]** = vendor documentation (URL); **[judgment]** = my opinion.

---

## 0. Summary

- **What Repo A already guarantees [code].** Once the Better Auth session row is gone, Repo A issues no new assertion on it. Every issuing path reads the session from its authoritative store. It then reads the session row and the user again, from the database, immediately before signing. That covers Repo B's disable, factor change and admin session revoke: all three delete the session rows. The requirement's fallback clause ("at least no new assertion issued once the session is gone") is **already met**. One caveat: Repo A doesn't know Repo B's `status: "disabled"` field. It relies on the rows being deleted, plus Repo B's own global before-hook.
- **What is missing [code].** Repo A has no reaction at all to a session deleted by anyone other than its own `/slo` and `/logout`:
  - no event;
  - no audit row;
  - no LogoutRequest;
  - its participant rows are orphaned until they expire.
  
  Assertions also carry no `SessionNotOnOrAfter`, so SP sessions are bounded only by each SP's own policy.
- **SOAP back-channel SLO is the wrong first build [doc].** Of the ten SPs asked about, only the two open-source ones document receiving SOAP LogoutRequests: Shibboleth SP and SimpleSAMLphp. Okta, Salesforce, Auth0, AWS IAM Identity Center, Cloudflare Access, Google Workspace, Zoom and Slack either don't accept IdP-initiated logout at all, or accept it only through the browser. For SaaS SPs, the levers that actually work are vendor session-revoke APIs and SCIM deactivation. Neither belongs in a SAML library; both belong to the host.
- **Recommendation [judgment].** Build three small things first:
  1. a `session.delete` database hook that turns an out-of-band session end into a **`session.ended` event**, carrying the per-SP participants the IdP could not tell. The host (conexxus) acts on it and audits it, as `revocation.notify` rows it already has.
  2. an opt-in per-SP **`SessionNotOnOrAfter`**, capped at the IdP session's expiry.
  3. participant rows kept (marked ended) long enough for a retry.
  
  Defer SOAP back-channel until a real SP in infowall's set needs it. The seam for it is designed in now. Document the rest honestly.

---

## 1. What Repo A already guarantees (verified in code)

### 1.1 No assertion from a deleted session

Every endpoint that can issue an assertion first takes the session from the session store, not the cookie cache:
- `src/endpoints/sso.ts:76`: `proceed()` → `getAuthoritativeSessionFromCtx(ctx)` (review 4, R4-2);
- `src/endpoints/resume.ts:26`, the same;
- `src/endpoints/init.ts:92`, the same (IdP-initiated SSO).

All three funnel into `issueResponse` (`src/endpoints/issue.ts:175`). It calls `eligiblePrincipal` (`issue.ts:113-148`) **before any signing**, at `issue.ts:184`:
- `issue.ts:119-121`: `findUserById` from the database; the user is refused if missing, or if `banned` and the ban hasn't expired.
- `issue.ts:128-141`: the session row is re-read by token:
  - from the database whenever it holds sessions (`!secondaryStorage || storeSessionInDatabase`), which is conexxus's case: no `kv`, per `auth.ts` "No `kv`: a KV session hit skips the database";
  - otherwise from secondary storage.
  
  A missing or expired session gives `ACCOUNT_INACTIVE` (`issue.ts:138-139`).
- The only uncovered case is a *stateless* host (`issue.ts:127`: "Stateless hosts have no server-side record"). That doesn't apply to conexxus.

So a session deleted by conexxus's admin disable (`admin.ts:209`, `deleteUserSessions`), by the lazy disable in the global before-hook (`auth.ts` before-hook, "status is re-checked on every session read"), by a factor change (`auth.ts:~418`, `deleteSessions(others)`), by admin "revoke sessions" (`admin.ts:227`) or by "reset factors" (`admin.ts:~258`) **cannot yield another assertion**. The window is a race of milliseconds: a request that passed the `issue.ts:133` read before the delete committed. It is inherent and acceptable.

**Caveat, conexxus-specific [code].** Repo A's account check is `isBanned` (`issue.ts:96-102`), which reads Better Auth admin-plugin fields. Conexxus disables with its own `user.status = "disabled"` column (`admin.ts` `guardedUpdate(... "status" ...)`). Repo A never reads it. Today that is covered three times over by conexxus:
- the sessions are deleted;
- `databaseHooks.session.create.before` refuses new sessions for disabled users (`auth.ts:288-298`);
- the global before-hook deletes sessions and throws on every path outside `DISABLED_PASS_THROUGH`, and the SAML paths are outside it.

Even so, the one check that runs *at signing time with a freshly read user* is the SP's `authorize()`, which receives the user from `issue.ts:119`. **Conexxus's SAML `authorize` must refuse `status !== "active"`**, mirroring `authorizeGate`'s first check (`auth.ts:578`). Cost: one line. It closes the dependency on a hook ordering nobody tests across the two repos.

### 1.2 What Repo A does when a session ends

- **Its own logouts only.** `/saml2/idp/slo` (SP-initiated) and `/saml2/idp/logout` ("sign out everywhere") call `endSession` (`src/endpoints/slo.ts:94-102`):
  1. list participants;
  2. `deleteSession`;
  3. clear the cookie;
  4. `forgetParticipants`.
  
  Then a front-channel chain notifies the other participants (`slo.ts:105-130`), and `emit({type:"logout"})` fires (`slo.ts:173`, `slo.ts:311`). These need the user's browser.
- **Database hooks [code].** The plugin registers only `session.update.after`, to extend participant expiry (`src/index.ts:147-165`). There is **no `session.delete` hook**. A session deleted anywhere else leaves its `samlIdpSessionParticipant` rows in place until `expiresAt`. They are then swept (`src/storage/sweep.ts:218`), silently. The swept rows include the NameID, which may be an email.
- **Events [code].** `LogoutEvent.initiatedBy` is `"sp" | "idp"` (`src/events.ts`). No event exists for "the session ended and the SPs were not told".
- **Assertions [code].** `buildResponseXml` (`src/saml/response.ts:~121`) emits `<AuthnStatement AuthnInstant SessionIndex>` with **no `SessionNotOnOrAfter`**. `NotOnOrAfter` on the Conditions and SubjectConfirmationData is `assertionLifetimeSeconds` (default 300; `options.ts:514`). That bounds only the *assertion's* acceptance window, not the SP session.
- **Logout Reason [code].** `buildLogoutRequest` hard-codes `Reason="urn:oasis:names:tc:SAML:2.0:logout:user"` (`src/saml/logout.ts:111`). An admin revocation should say `...:logout:admin` (Core §3.7.1).

### 1.3 The exact gap

| Concern | Status |
|---|---|
| No new assertion after session delete | **Met** [code] |
| No new assertion after a conexxus disable, if sessions were somehow not deleted | Met by conexxus hooks, not by Repo A; add the `authorize` status check |
| SP told when the session ends out of band | **Missing**: no mechanism, no event, no audit |
| Bound on how long an SP session outlives the IdP session | **Missing**: no `SessionNotOnOrAfter`; SP policy only |
| The host can learn which SPs hold sessions for the user, to act itself | **Missing** once the session is deleted: participant rows are keyed by `hash(session id)` (`storage/participants.ts:29`) with no `userId`, and nothing announces them |

---

## 2. Mechanisms for browserless IdP-initiated logout

### 2.1 The spec [spec]

- **Profiles §4.4** (intro) allows the protocol "combined with a synchronous binding, such as the SOAP binding, or with asynchronous 'front-channel' bindings". A front-channel binding "may be required… in cases in which a principal's session state exists solely in a user agent in the form of a cookie". That is the typical SaaS SP.
- **Profiles §4.4.3.3**: the IdP picks a binding "consistent with the capability of the responder and the availability of the user agent". Without a user agent, **SOAP (or another synchronous binding) is the only conformant choice.**
- **Profiles §4.4.3.4**: in back-channel mode, the responder "MUST authenticate itself… either by signing the `<LogoutResponse>` or using any other binding-supported mechanism".
- **Bindings §3.2** (SOAP 1.1 over HTTP, `urn:oasis:names:tc:SAML:2.0:bindings:SOAP`), a request-response binding:
  - a SAML-level error still returns HTTP 200 with a `<samlp:Status>` (§3.2.3.3);
  - message authentication relies on XML signatures or TLS client authentication (§3.2 defers to the SOAP binding's security considerations).
  
  Repo A already has both halves of a signature-based trust: its signing key is in the SP's metadata, and it holds `spCertificates` for verifying the SP's response. **No mutual TLS is needed** if both messages are signed. The brief's "mutually trusted signature" already exists.
- **Core §3.7.3.2**: the session authority "SHOULD attempt to contact each session participant using any applicable/usable protocol binding", and MUST report `PartialLogout` if it can't confirm them all. It MAY start logout itself when "credentials may have been compromised", which is the admin-disable case. It MUST set `NotOnOrAfter` on the request.
- **Core §2.7.2 `SessionNotOnOrAfter`**: "a time instant at which the session between the principal… and the SAML authority issuing this statement MUST be considered ended". Strictly this describes the *IdP-side* session. SPs that honor it use it as an upper bound on their own session. It is advisory from the SP's point of view.

**Adversarial note on §3.7.3.2 [judgment]:** "SHOULD attempt… any applicable binding" does not make an IdP non-conformant for not implementing SOAP. It obliges us to use the bindings the SP advertises and we support, and to be honest (PartialLogout, audit) about the rest.

### 2.2 Who actually supports it

From vendor documentation and source, gathered by a research pass. D = documented, I = inferred, U = unknown.

| SP | Accepts IdP-initiated LogoutRequest | SOAP back-channel receive | Honors `SessionNotOnOrAfter` | Programmatic revoke / deprovision |
|---|---|---|---|---|
| Okta (inbound SAML IdP) | No: SLO is SP-initiated only (D: [help.okta.com idp-enable-slo](https://help.okta.com/oie/en-us/content/topics/security/idp-enable-slo.htm), [Okta KB](https://support.okta.com/help/s/article/Is-IDPinitiated-Single-LogOut-supported)) | No (I) | U | `DELETE /api/v1/users/{id}/sessions` (D: [Okta API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserSessions/)) |
| Auth0 (SAML connection) | U, leaning no (I; [Auth0 docs](https://auth0.com/docs/authenticate/login/logout/log-users-out-of-saml-idps)) | No (I) | U | `DELETE /api/v2/users/{id}/sessions` (D: [Auth0 API](https://auth0.com/docs/api/management/v2/users/delete-sessions-for-user)) |
| Salesforce | Front-channel only, "same browser" (D: [Salesforce SLO](https://help.salesforce.com/s/articleView?id=sf.security_auth_slo_saml_sp_configuring.htm)) | No (I) | U | Session removal, SCIM deactivate (D: [Salesforce SCIM](https://help.salesforce.com/s/articleView?id=sf.identity_scim_deactivate_reactivate_user.htm)) |
| AWS IAM Identity Center | **No**: "doesn't support SAML Single Logout initiated by an identity provider" (D: [AWS](https://docs.aws.amazon.com/singlesignon/latest/userguide/authconcept.html)) | No | U (own session duration) | SCIM; delete active sessions (D: [AWS revoke](https://docs.aws.amazon.com/singlesignon/latest/userguide/revoke-user-permissions.html)) |
| Cloudflare Access | Not documented (U); D-028 already records "Cloudflare Access doesn't do SAML SLO" | No (I) | U | Per-user and per-app revoke; SCIM deprovision revokes sessions (D: [CF session mgmt](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/)) |
| Google Workspace | **No** SLO in either direction (D: [Google SAML FAQ](https://knowledge.workspace.google.com/admin/apps/saml-sso-faq)) | No | U, likely no | Directory API `users.signOut` (D: [Google API](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/signOut)) |
| Zoom | Sign-out URL redirect only (I/U) | No (I) | U; admin auto-logout setting (D: [Zoom SSO guide](https://library.zoom.com/admin-corner/account-and-endpoint-management/sso-field-guide)) | Revoke SSO token; SCIM (D: [Zoom API](https://developers.zoom.us/docs/api/rest/reference/user/methods/)) |
| Slack | **No**: "does not support Single Logout or session duration configured in your IDP" (D: [Slack](https://slack.com/help/articles/205168057-Custom-SAML-single-sign-on)) | No | **No** (D, same page) | `admin.users.session.reset`; SCIM (D: [Slack API](https://docs.slack.dev/reference/methods/admin.users.session.reset/)) |
| Shibboleth SP 3 | Yes | **Yes**; needs a server-side session store with a reverse index by NameID (D: [SP3 SLO](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334844), [SessionCache](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334650/SessionCache)) | **Yes**: session lifetime shortened "if an IdP indicates it should be shorter" (D: [SP3 Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions)) | n/a |
| SimpleSAMLphp SP | Yes | **Yes**: SOAP is a listed SLO binding (D: [docs](https://simplesamlphp.org/docs/stable/saml/sp.html), [source](https://github.com/simplesamlphp/simplesamlphp/blob/master/modules/saml/src/Controller/ServiceProvider.php)) | **Yes**: `$state['Expire'] = SessionNotOnOrAfter` (D, source) | n/a |
| node-saml / passport-saml | Parses one over Redirect/POST; the app ends its sessions itself | No ([issue #454](https://github.com/node-saml/passport-saml/issues/454)) | No (I, source grep) | n/a |
| Keycloak as broker SP | Yes; finds broker sessions server-side by SessionIndex or NameID ([SAMLEndpoint.java](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/broker/saml/SAMLEndpoint.java)) | No SOAP receive; a server-side POST works | U | Admin REST (I) |

**Prior art on the IdP side:**
- **Keycloak as IdP** sends real SOAP when the SP advertises a SOAP SLO. Otherwise it sends a "legacy backchannel logout", a server-to-server POST or Redirect LogoutRequest ([SamlProtocol.java](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/protocol/saml/SamlProtocol.java)).
- **Shibboleth IdP 5** propagates over SOAP "when possible" ([LogoutConfiguration](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199510118/LogoutConfiguration)).
- Both are mature IdPs, and both treat back-channel SAML logout as best-effort against a minority of SPs.

**Conclusion [doc plus judgment].** For the SPs infowall is realistically going to federate (SaaS plus its own apps), SOAP SLO reaches roughly none of the commercial ones. The Okta and Auth0 demo SPs Repo A already interops with (D-034, D-035) would not accept it. SOAP would reach Shibboleth and SimpleSAMLphp SPs, which are university and self-hosted territory.

### 2.3 Alternatives, rated

| Mechanism | Reach | Effect on an admin disable | Cost in Repo A |
|---|---|---|---|
| SOAP back-channel LogoutRequest | Shibboleth SP, SimpleSAMLphp; Keycloak-style "POST server-to-server" reaches a few more | Immediate, where supported | Medium: SOAP envelope build and parse, response verify, per-SP binding config, outbound fetch with timeouts, XSD for the SOAP envelope, fuzzing surface |
| `SessionNotOnOrAfter` | Shibboleth, SimpleSAMLphp confirmed; most SaaS unknown; Slack confirmed ignores | Bounds exposure to at most N minutes, only where honored | Tiny: one attribute |
| SCIM deactivate | Most SaaS (AWS, Salesforce, Slack, Zoom, Cloudflare, Okta) | Immediate and durable, but it *deprovisions the account*, which is heavier than a logout | Out of scope: a provisioning product, not an IdP plugin |
| Per-SP session-revoke APIs (Okta, Auth0, Google, Slack, Salesforce, AWS, Cloudflare) | Per vendor | Immediate | Out of scope: host code, using per-SP API credentials. Repo A's job is to *tell the host* who to call and with what identifiers |
| Deferred front-channel logout at the user's next IdP visit | ~0 for a disable | **None**: a disabled user never comes back through the IdP. Their SP session keeps them at the SP, which never redirects to the IdP until its session expires. For a factor change the user *is* at the IdP, but their SP sessions belong to the same person, and ending them is policy, not security | Medium (pending-logout store, a page interstitial). **Reject** for this problem |
| Short SP session lifetimes, configured at the SP | All SPs, manually | Bounds exposure | Documentation only |

---

## 3. Design options for Repo A

### Option A: document only
- **Pros:** zero code.
- **Cons:** conexxus's revocation contract ("every step audited, nothing silently skipped", `revoke.ts:13-15`, DECISIONS 2c) would have a silent hole for every SAML SP. An admin reads "disabled", and the SP sessions live on with no record. **Not honest enough** [judgment].

### Option B: a `session.delete` hook that reports and preserves participants (recommended core)
Register `databaseHooks.session.delete.after` (and `before`, see below). For each deleted session:
1. Load its participants (`sessionKeyOf(session.id)`).
2. Unless Repo A's own `endSession` is the deleter (see "reentrancy"), classify the end:
   - `expired`: `session.expiresAt <= now`, the lazy delete in `getSession` (`better-auth/dist/api/routes/session.mjs:159-162`), which fires the hook [code];
   - `revoked`: otherwise.
3. Emit a new event, `session.ended`, with `{ userId, sessionId, reason: "expired" | "revoked", participants: [{ spId, entityId, nameId, nameIdFormat, sessionIndex, notified: false }] }`. The audit table gets it too.
4. Mark the participant rows `endedAt = now` instead of deleting them. Keep them until their `expiresAt`, so a host retry or a later SOAP send can still find them.

**Verified constraints:**
- `deleteManyWithHooks` runs the delete hooks once per matched row, with the row (`id`, `token`, `userId`, `expiresAt`) (`better-auth/dist/db/with-hooks.mjs:153-188`) [code]. `deleteUserSessions` and `deleteSessions` both go through it (`internal-adapter.mjs:503-537`) [code].
- **The hook context is `undefined` outside a Better Auth endpoint** (`tryGetCurrentAuthEndpointContext`). Conexxus's admin page calls `(await c.auth.$context).internalAdapter.deleteUserSessions(...)` from Hono handlers (`admin.ts:209, 227, ~258`). **So for the admin disable, the most important case, `hookCtx` is undefined.**
  - The oauth-provider's own per-session back-channel hook returns early on `!hookCtx` (`@better-auth/oauth-provider/dist/authorize-*.mjs:4425-4449`) [code].
  - Repo A's existing `session.update.after` hook does the same (`src/index.ts:156`).
  - **The new hook must not depend on `hookCtx`.** It must use the `AuthContext` captured in the plugin's `init(ctx)`: `ctx.adapter`, `ctx.logger`, `ctx.runInBackground`. `create-context.mjs:212` binds `runInBackground` to `advanced.backgroundTasks.handler`. That is conexxus's per-request `waitUntil` (`auth.ts` `buildAuth(..., waitUntil)`), so it works from the admin page too.
  - The current `emit()` takes a `GenericEndpointContext` (`events.ts:58`) for the IP and user agent. It needs a variant that takes the `AuthContext` and omits both.
- **Reentrancy [code].** `endSession` deletes the session (`slo.ts:97`) *after* listing participants and *before* `forgetParticipants`. The new hook would fire in the middle and report "revoked, not notified" for SPs the front-channel chain is about to notify.
  - **Fix:** mark the session in a module-level `Set` of session ids being ended by SLO (or a `WeakMap` keyed on the endpoint context, as the oauth-provider does). The hook skips those.
  - Don't "fix" it by forgetting participants before the delete. A failed delete would then lose the SP list (review 3, R3-2's reasoning).
- **Side effect to embrace [judgment].** Better Auth's own `/sign-out` also fires the hook. Today the guide says `/sign-out` "only ends the IdP session" (`docs/guide/single-logout.md`, "Started by your app"), silently. With the hook, that becomes a `session.ended` event with `reason: "revoked"`: honest. Consider a third reason, `signed-out`. The hook can tell sign-out apart only through `hookCtx.path === "/sign-out"` when a context exists; otherwise it reports `revoked`.
- **Expiry noise.** `reason: "expired"` events fire on every lazily deleted expired session.
  - Emit them to the callback, but **don't write them to the audit table**.
  - Or skip them entirely when `SessionNotOnOrAfter` was issued (Option C): the SP was told the end time in advance.
  - Rows that expire without a delete (swept) never fire anything. That is correct.

- **Pros:**
  - It is the smallest change that makes out-of-band ends *visible*, with exactly the identifiers the host needs: the NameID and SessionIndex per SP, which the host cannot otherwise reconstruct because the participant rows are keyed by a session hash.
  - It needs no route, so it doesn't touch the conexxus allow-list.
  - It is Workers-safe: a few database reads, no fetch.
- **Cons:**
  - One schema change: `endedAt` (nullable), plus `userId` (for retries by user; see Option D). That means a D1 migration `0007`.
  - Emitting from a database hook is new territory for Repo A (D-038 has one emission point per outcome). It keeps D-038's "observers, never gates" rule.

### Option C: `SessionNotOnOrAfter` (recommended, tiny)
Per SP, and globally: `sessionNotOnOrAfter?: false | "idp-session" | { maxSeconds: number }`. It emits `SessionNotOnOrAfter = min(session.expiresAt, authnInstant + maxSeconds)` on the AuthnStatement.
- `issueResponse` already has `session.session.expiresAt` (`issue.ts:261`) and `createdAt` (`issue.ts:250`).
- **Pros:**
  - It is conformant (Core §2.7.2) and trivial.
  - It bounds exposure for Shibboleth and SimpleSAMLphp SPs, and possibly others.
  - It makes natural expiry consistent between the IdP and the SP.
- **Cons:**
  - Most SaaS SPs are unknown or ignore it, and Slack is documented to ignore it.
  - With `"idp-session"`, Better Auth's sliding refresh (`updateAge`) extends the IdP session but not the SP's cap. The SP then comes back for a silent re-SSO. That is correct behaviour, but an SP without passive re-auth may show a login bounce.
  - Recommend **default `false`** before 1.0, so the live Okta and Auth0 demos don't change [judgment].
  - Put it in the options schema for stored SPs as well (D-040 decision 4 style: explicit value, unknown keys rejected).

### Option D: a server-only back-channel logout call (defer SOAP; design the seam now)
A server-only endpoint, `auth.api.samlIdpBackChannelLogout({ body: { userId, reason } })`, with `metadata: { SERVER_ONLY: true }`. There is no HTTP route, so the allow-list is unaffected, and `hookCtx` exists because it runs as an endpoint. It:
1. finds the user's participant rows (live or ended, not expired): **this needs a `userId` column**;
2. for SPs with `singleLogoutService.binding === "soap"`, sends a signed LogoutRequest (`Reason=...:logout:admin`, `NotOnOrAfter` per Core §3.7.3.2) in a SOAP 1.1 envelope, with `fetch(url, { method: "POST", redirect: "manual", signal: AbortSignal.timeout(5000) })` (the same Workers lessons as conexxus `revoke.ts:166-179`);
3. verifies the SP's signed LogoutResponse (`InResponseTo`, `Issuer`, signature with `spCertificates`, `Destination` if signed);
4. returns `{ spId, outcome: "ok" | "partial" | "no_backchannel" | "timeout" | "http_4xx" | "bad_response" | "unsigned" }[]` and emits `logout` events.

- **Workers notes:**
  - Outbound fetch is fine.
  - "A Worker cannot fetch its own URL" only matters if an SP is on the same zone. For infowall's own apps on the same Cloudflare zone, use a service binding or a custom-domain Worker. This is a deployment note [judgment; verify per deployment].
  - Subrequest limits (50 on the free plan, 1000 on paid) and 30 s wall time under `waitUntil` cap the fan-out. Run the sends in parallel with a per-SP timeout, as `revoke.ts:146` does.
- **Keycloak-style "server-side POST binding" fallback.** It works against SPs that look up sessions by SessionIndex (Keycloak, some SimpleSAMLphp stores), and fails silently or benignly on cookie-bound SPs. **Don't do it by default** [judgment]. It sends a browser-binding message where no browser is, and success is unverifiable: an HTTP 200 from an HTML form handler proves nothing. If it is ever offered, it must be a per-SP opt-in (`backChannel: "post"`), and its outcome recorded as `sent_unverified`, never `ok`.
- **Pros:** real logout for Shibboleth and SimpleSAMLphp SPs; mirrors conexxus's OIDC path.
- **Cons:**
  - The new attack and parse surface: SOAP envelope parsing, XSD, fuzzing, the D-037 cost caps.
  - A new metadata binding in `serviceProviderFromMetadata`.
  - Per-SP interop testing (a Shibboleth SP container in `e2e/`).
  - **No current infowall SP needs it** (unverified: I don't know infowall's SP list; ask).

### Option E: an event hook for SCIM and SP APIs
This *is* Option B's `session.ended` event. Repo A shouldn't hold per-vendor credentials or call vendor APIs; that belongs to the host. The event must carry what those APIs need:
- `userId` (the host maps it to the SCIM id, email and so on);
- `spId` and `entityId` (which vendor);
- `nameId` and `nameIdFormat` (the account key at the SP).

---

## 4. Fit with conexxus's constraints

| Constraint | Option B (event) | C (`SessionNotOnOrAfter`) | D (SOAP) |
|---|---|---|---|
| **Fixed `AUDIT_EVENTS`** (`idp-core/src/audit.ts:14-41`) | Map to the **existing** `revocation.notify`: `client = "saml:<spId>"`; result `fail`; reason `"<disabled\|admin_signout>:no_backchannel_slo"`. **No new audit event name needed** | None | Same `revocation.notify` rows with `ok` or `fail:<why>`: exactly `revoke.ts:132-136`'s `record()` |
| **Route allow-list** (`idp-core/src/allowlist.ts`) | No route | No route | Server-only endpoint, no route. (Separately, the merge must add `/saml2/idp/{metadata,sso,resume,init,slo,logout}` through `allowedRoute(..., extra)`; the registry routes stay off, since the admin page writes directly) |
| **Hook context is `undefined` from the admin page** | Must use the `init` `AuthContext` (see 3.B) | n/a | Called explicitly from `revokeDownstream`, so a context exists |
| **Mirror `revokeDownstream`** | Conexxus's `revokeDownstream` can't see SAML participants itself (hashed keys, no `userId`). Two ways to make it: collect events from the hook in a per-request list and record them after `deleteUserSessions`; or call a Repo A helper `listSamlParticipants(auth, userId)` (needs the `userId` column), then record each as `revocation.notify fail no_backchannel_slo` | n/a | `revokeDownstream` calls `auth.api.samlIdpBackChannelLogout` after the OIDC loop, in parallel, and records each outcome |
| **"Only clients the user used"** (Mark, 2e; `revoke.ts:104-111`) | Participant rows are exactly "SPs this user got assertions from in a live session". They are narrower than conexxus's 13-month audit look-back. SP sessions outliving participant rows are covered only by `SessionNotOnOrAfter`, or by conexxus's audit rows (the SAML `assertion.issued` event → a conexxus audit row) | Makes participant lifetime ≥ SP session lifetime, when honored | Same |
| **Retry** ("Sign out of all applications", `admin.ts:274-282`) | Needs participant rows to survive the session delete: hence `endedAt` rather than deleting | n/a | Same; plus conexxus's `toldNames` (`revoke.ts:121`) picks up failed `saml:<spId>` names from its audit log |
| **Workers limits** | A few database queries in `waitUntil` | None | Fan-out subrequests; 5 s timeout each; parallel |

**Conexxus-side findings from this read (outside Repo A, but they affect the merged story) [code]:**
1. **Admin "revoke sessions" (`admin.ts:222-229`) and "reset factors" (`admin.ts:~246-259`) do not call `revokeDownstream`.** They call `deleteUserSessions` outside an endpoint context, so the oauth-provider's per-session back-channel hook exits on `!hookCtx` too. **No OIDC client is told** in those two cases.
   - The brief's statement that conexxus "sends OIDC back-channel logout… when that happens" holds for disable (`admin.ts:213`, and the lazy path `auth.ts` before-hook).
   - It holds for a user's own factor change, because that runs in an endpoint (`auth.ts:~418`), so the provider hook fires; the Workers `redirect` issue is patched (`patches/@better-auth+oauth-provider+1.7.6.patch`).
   - It does **not** hold for these two admin actions. Worth confirming with a test; this is from reading, not execution.
   - The SAML design should hook the same place conexxus fixes this: a single "session(s) ended out of band" function that both OIDC and SAML fan out from.
2. **Per-request Better Auth instance.** Conexxus builds `betterAuth()` per request (`buildAuth(app, env, cf, waitUntil)`). Repo A's guide (`docs/guide/cloudflare-workers.md:57`) says not to: the key parse, the XSD compile, and the SP directory and metadata caches are per-instance. The merge needs a plan here: hoist `samlIdp(...)` construction to module scope and pass it in. Not a correctness bug, but a latency and cost one [judgment].

---

## 5. Policy gate interplay (the coordinator's second point)

Conexxus's `authorizeGate` → `canUseClient(PolicyInput)` → `{ allow } | { allow:false, reason, reauthenticate? }` (`idp-core/src/config.ts:60-67`, `auth.ts:519-600`). Repo A's per-SP `authorize(ctx)` (`types.ts:69-75, 166`; called at `issue.ts:209`) is the right seam, but it lacks:

| Need | Repo A today | Change |
|---|---|---|
| Fresh `user` (status, roles) | ✔ re-read at `issue.ts:119`, passed in | none; the host parses `roles` and loads entitlements (async is allowed) |
| `session.mfaCompletedAt` | The session object from `getAuthoritativeSessionFromCtx` carries additional fields [code, by Better Auth's schema]; `eligiblePrincipal` re-reads the row but passes the *earlier* object to `authorize` (`issue.ts:209` uses `session.session`) | Pass the re-read row (`current`) to `authorize`, so freshness comes from the same read that proves the session exists |
| An SP label | `ServiceProviderInfo` has `id`, `entityId` (`types.ts`, D-040 decision 1) | Use `id` as the label; or add an optional `label` to SP config and `ServiceProviderInfo` |
| A deny reason | `authorize` returns a boolean; the denial is a generic `ACCESS_DENIED` page (`issue.ts:214`) | Allow `boolean \| { allow:false; reason?: string; reauthenticate?: boolean }`. Put `reason` into the `denied` event's `detail`, so conexxus audits `authorize denied <reason>` |
| **Force re-login and resume** | The machinery exists for ForceAuthn: `parkForLogin(..., {reauthenticate})` → `prompt=login` (`sso.ts:45-53, 87-95`); resume refuses a session older than the pending request (`resume.ts:237-238` in the concatenation, i.e. `resume.ts:~49`) | On `{reauthenticate:true}`: if `request.isPassive`, return a SAML `NoPassive`; otherwise park with `forceAuthn: true` and redirect to login with `prompt=login`. **Loop guard:** a request already resumed after a forced re-login that is denied again must get the error page, not another park (conexxus's 2d "no loops" rules). On the SSO POST binding, go through the existing `cid` re-entry |
| Deny back to the SP | An error page | Optionally a SAML `Responder/RequestDenied` Response to the validated ACS (as `samlError` does), mirroring conexxus's "a denial goes back to the console". Per-SP opt-in |

This is an API change to land **before 1.0**. It widens the return type, which is additive, and it's in the same spirit as D-040. It is independent of the logout work.

---

## 6. Recommendation

### Build first (the minimum that is honest and secure)

1. **`session.delete` hooks → `session.ended` event**, plus audit row (Option B).
   - `before`: capture participants into a map keyed by session id (the oauth-provider pattern), skipping sessions in the SLO-in-progress set.
   - `after`: mark the rows `endedAt` and emit.
   - Use the `init` `AuthContext`; never require `hookCtx`.
   - Event shape:
     ```ts
     interface SessionEndedEvent extends EventBase {
       type: "session.ended";
       userId: string;
       sessionId: string;
       reason: "revoked" | "signed-out" | "expired";
       /** SPs that got assertions in this session and were NOT sent a LogoutRequest. */
       participants: { spId: string; entityId: string; nameId: string; nameIdFormat: string; sessionIndex: string }[];
     }
     events.onSessionEnded?: (e: SessionEndedEvent) => void | Promise<void>;
     ```
   - Audit: store `revoked` and `signed-out` only when `participants.length > 0`; never store `expired`.
   - The event is emitted whenever `singleLogout.enabled` (participants are recorded only then).
   - **Also recommend recording participants without SLO enabled.** Otherwise the event is empty for hosts that don't use SLO. Decide one way:
     - (a) a new `sessionTracking: { enabled }` option that records participants whenever events or the audit log need them;
     - (b) require `singleLogout` for this feature.
     
     My judgment: (a). Revocation visibility matters more than SLO.
2. **Schema:** `samlIdpSessionParticipant.userId` (indexed) and `endedAt` (nullable). D1 migration `0007`.
   - The sweep keeps deleting by `expiresAt`.
   - `listParticipants` for SLO ignores rows with `endedAt` set.
   - Add a helper, `listEndedParticipants(adapter, userId)`, exposed as a server-only endpoint `auth.api.samlIdpListSessionParticipants({ body: { userId } })`, so the host's "Sign out of all applications" retry can find them.
3. **`sessionNotOnOrAfter`**: per SP and global, `false | "idp-session" | { maxSeconds }`, default `false` (Option C).
4. **Conexxus wiring** (their side):
   - SAML `authorize` refuses `status !== "active"`.
   - `onSessionEnded` writes `revocation.notify` / `fail` / `<reason>:no_backchannel_slo` / `client = "saml:<spId>"`, then calls vendor APIs where they have them (Okta and Auth0 session delete, for the demos).
   - The admin UI's "notify failed" notice then covers SAML SPs too.
   - Fix finding 4.1 (admin revoke and reset don't tell OIDC clients) in the same change.
5. **Docs:** a "When the session ends without the browser" section in `single-logout.md`:
   - what is guaranteed (no new assertions);
   - what isn't (SP sessions continue);
   - the SP support matrix above, with links;
   - `SessionNotOnOrAfter`;
   - the event;
   - "use SCIM or vendor APIs for SaaS".
   
   Also fix the claim that Better Auth's `/sign-out` "only ends the IdP session" silently: it now emits `session.ended`.

### Defer
- **SOAP back-channel SLO** (Option D). Build it when a named infowall SP advertises a SOAP `SingleLogoutService` (Shibboleth or SimpleSAMLphp). The shape is already fixed above:
  - `singleLogoutService.binding: "soap"`;
  - the server-only `samlIdpBackChannelLogout`;
  - outcomes mirroring `revoke.ts`.
  
  Estimated cost: SOAP envelope, a new XSD, fuzz targets, an e2e Shibboleth container.
- **The `authorize` return-type widening and reauthenticate** (section 5). Land before 1.0, but separately.
- **Reject:** deferred front-channel logout at the next visit (no effect on a disable); a server-side POST-binding "back-channel" by default (unverifiable success).

### Test plan
Run on both runtimes, Node and workerd/D1, as the existing suites do.
1. **No assertion after an out-of-band delete** (a regression pin for 1.1): sign in, get an assertion, call `internalAdapter.deleteUserSessions(userId)` **outside any endpoint** (as conexxus's admin page does), then replay SSO with the old cookie → `ACCOUNT_INACTIVE`, and no `assertion.issued` event. Mutation check: remove the `issue.ts:138` check and see the test fail.
2. **The hook fires with no context:** the same out-of-band delete emits exactly one `session.ended` with `reason: "revoked"`, listing both SPs with the right `nameId` and `sessionIndex` (compare with the `assertion.issued` events). Delivery goes through `backgroundTasks.handler`, as in D-038's delayed-handler test, so a handler outside background tasks fails.
3. **Reentrancy:** SP-initiated SLO and `/logout` emit `logout` and **no** `session.ended`. Mutation: drop the in-progress set → the test fails.
4. **Sign-out:** Better Auth `/sign-out` emits `session.ended` with `reason: "signed-out"`.
5. **Expiry:** an expired session lazily deleted by `get-session` emits `reason: "expired"` and writes no audit row.
6. **Ended rows:**
   - `endedAt` is set, the rows survive until `expiresAt`, then the sweep removes them;
   - SLO's `listParticipants` ignores ended rows;
   - `samlIdpListSessionParticipants({userId})` returns them;
   - participants of a *different* user are never returned (a cross-user isolation test).
7. **A failing hook never blocks the delete:** make the participant read throw; the session delete still succeeds, and an error is logged. That is D-038's observer rule; mutation-check it.
8. **`SessionNotOnOrAfter`:**
   - absent by default;
   - with `{maxSeconds: 600}`, it equals `min(expiresAt, createdAt + 600)`;
   - with `"idp-session"`, it equals `expiresAt`;
   - it validates against the assertion XSD;
   - node-saml still accepts it;
   - a stored SP with a bad value fails registry validation.
9. **Conexxus integration** (in conexxus):
   - disabling a user with SAML participants writes `revocation.notify fail saml:<sp> ...:no_backchannel_slo`;
   - `disabled_notify_failed` shows;
   - "Sign out of all applications" re-emits for the same SPs (from ended rows);
   - a disabled user with a surviving session (inject one) gets no SAML assertion, both through the before-hook and with the before-hook removed, relying on `authorize`.
10. When SOAP is built: a Shibboleth SP 3 container in `e2e/`, where a disable ends its session (check `Shibboleth.sso/Session` after); plus negative tests for an unsigned or forged SOAP LogoutResponse, a wrong `InResponseTo`, a 3xx, a timeout, and an oversized envelope (the D-037 caps).

### What is verified vs judgment
- **Verified from code:**
  - all of section 1;
  - the hook mechanics and the `hookCtx`-undefined behaviour (Better Auth 1.7.6 dist, oauth-provider dist);
  - conexxus call sites;
  - conexxus finding 4.1 (from reading; not executed).
- **Verified from spec:** the Profiles §4.4 / §4.4.3.3 / §4.4.3.4, Bindings §3.2 and Core §2.7.2 / §3.7.3.2 quotations. These came from a research pass that fetched the OASIS PDFs, not re-read line by line by me.
- **From vendor docs:** the SP matrix entries marked D. Entries marked I or U are unconfirmed: Okta's and Auth0's handling of `SessionNotOnOrAfter` in particular is unknown and worth a live check against the demo tenants.
- **Judgment:**
  - the prioritisation;
  - the default `false` for `SessionNotOnOrAfter`;
  - rejecting deferred logout and POST back-channel;
  - `sessionTracking` independent of SLO;
  - the per-request-instance concern;
  - the claim that infowall's SPs are mostly SaaS (**ask for the actual SP list**: it decides whether SOAP ever earns its cost).

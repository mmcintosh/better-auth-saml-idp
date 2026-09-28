# Security review 5: better-auth-saml-idp before 1.0.0-rc.1

- **Scope:** `git diff 4a44664..HEAD -- src examples/workers-hono/src`, covering D-040 to D-045 and the example admin page.
- **HEAD reviewed:** d3185da, then 73b52c3 (the HEAD moved during the review; the `src/` files reviewed are unchanged).
- **Baseline:** `pnpm test` gives 124 files passed and 9 skipped; 1150 tests passed and 54 skipped. Earlier review tests (`test/review*`) all pass.
- **Method:** code reading, one scratch reproduction test, and reading the relevant Better Auth 1.7.5 and @better-auth/sso sources.

The scratch test is `zz-review5-slo-marker.test.ts`, in this directory. I copied it into `test/` for the run and deleted it afterwards. Other people were editing `CHANGELOG.md`, `README.md` and `docs/` in the working tree during the review. Those edits are not mine.

**Overall:** I found no Critical, High or Medium issues. There are 3 Low findings (one verified by test) and a few Info items.

---

## Verified findings

### L-1 (Low): a failed Single Logout delete leaves an `endingBySlo` marker that later suppresses `session.ended`

- **Where:**
  - `src/storage/participants.ts:131-139`: `markEndingBySlo` / `consumeEndingBySlo`.
  - `src/endpoints/slo.ts:94-104`: `endSession`.

**What happens:**
- `endSession` calls `markEndingBySlo(id)` before `internalAdapter.deleteSession(token)`. Nothing removes the marker if the delete throws, or if the delete finds no row.
- `consumeEndingBySlo` ignores the marker's age. Old entries are pruned only when the next `markEndingBySlo` runs. So in an isolate with no further SLO traffic, a stale marker lives indefinitely, not for 60 s.
- When the session is later deleted by other means (an admin revoke, `/sign-out`, expiry), the delete hook sees the marker and returns early. No `session.ended` event fires, nothing is written to the audit log, and the participant rows keep `endedAt: null`. `samlIdpListSessionParticipants` then shows them as live, for a session that no longer exists.

**Scenario:**
1. The IdP-initiated logout (or an SP LogoutRequest) hits a transient database error on `deleteSession`. The response is a 500, and no SP was told.
2. An administrator then revokes the user's sessions to be sure.
3. The host's `onSessionEnded` handler never fires, so its SCIM or SP-API cleanup never runs. Every SP session stays alive, and nothing records that fact.

**Evidence:** the scratch test, run against the node project.
- **Control run** (no failed SLO): `session.ended events=1`; rows are `[{spId:'test-sp', endedAt: <date>}]`.
- **Failed-delete run:** `logout status: 500`, then `session.ended events=0`; rows are `[{spId:'test-sp', endedAt: null}]`.
- **Unit check:** a marker is still consumed (returns `true`) 24 h after it was set.

**Suggested fix:**
- Wrap the delete, e.g. `markEndingBySlo(id); try { await deleteSession(...) } catch (e) { consumeEndingBySlo(id); throw e }`.
- Make `consumeEndingBySlo` return `true` only when `Date.now() - at <= 60_000`.
- Cap the size of the Map.

### L-2 (Low): `requestSignatures: "ignore"` with a metadata URL no longer requires signed logout messages

- **Where:**
  - `src/endpoints/slo.ts:77`: `mustSign = sp.requestSignatures !== "ignore"`.
  - `src/options.ts:140-146`: the refinement rejects `"ignore"` together with `spCertificates`, but not together with `metadata`.

**What changed:**
- Before D-040, `mustSign` was `spCertificates.length > 0 || requireSignedAuthnRequests || metadata !== undefined`. An SP with `metadata.url` therefore always had to sign LogoutRequests and LogoutResponses.
- Now, an explicit `"ignore"` plus `metadata.url` passes validation, loads the certificates and never uses them. Unsigned LogoutRequests are then authenticated only by the SessionIndex. That value is a per-SP HMAC, which the SP and the user's browser both see.
- DECISIONS.md D-040 (line 1153) says the new rule has "the same outcome as the old `mustSign`". That is not true for this one combination.
- **Impact is small.** The SessionIndex is unguessable, and the only party who can end the session this way is one that saw this browser's assertion. But the change silently weakens the protection for a config an operator might pick when an SP's AuthnRequest signatures are broken.

**Suggested fix:** do one of these, and correct the sentence in D-040:
- reject `"ignore"` together with `metadata`, the same way as with `spCertificates`;
- warn about the combination;
- keep `mustSign` true when `metadata` is set.

### L-3 (Low, example only): the admin page's own routes accept impersonated sessions

- **Where:** `examples/workers-hono/src/admin.ts:30-43` (`requireAdmin`); the example installs `admin()` (`auth.ts:145`).

**What happens:**
- The plugin's registry API refuses sessions that have `impersonatedBy` set (`registry.ts:36`). The admin page's own routes do not: `/admin`, `/admin/api/audit` and `/admin/api/from-metadata`.
- A Better Auth admin-role user who impersonates a `SAML_REGISTRY_ADMINS` user can therefore read the audit feed. That feed contains user ids, SP ids, denial details and "N SPs not told". Registry mutations are still refused.
- `requireAdmin` also decides on `auth.api.getSession`, which may come from the cookie cache, where the registry API re-reads the user from the database. Stale `emailVerified` or email values can pass for the life of the cache.

**Suggested fix:** in `requireAdmin`, add:
- `if (session.session.impersonatedBy) return 403`;
- `disableCookieCache: true`, or a `findUserById` re-read.

These are reference-code patterns that hosts will copy.

---

## Suspicions (not verified)

### S-1 (Info): `session.createdAt` stands in for "authenticated at", and D-044 now leans on it

- **Where:** `src/endpoints/resume.ts:48`; `src/endpoints/issue.ts:233-237`.

ForceAuthn, and now `reauthenticate`, trust any session created after the pending request. Better Auth plugins can create a session for a user from an existing session without asking for credentials again:
- `device-authorization` approve plus token (`routes.mjs:455`). Combined with `bearer`, a client that holds a stolen session could mint a "fresh" one.
- admin impersonation, which issuance already refuses by default.

This is a property of Better Auth, not a plugin bug, and it already applied to ForceAuthn. I did not build an end-to-end exploit.

**Suggested action:**
- Document that hosts needing true re-authentication should have `authorize` check a host-set field (for example, the last MFA time on the session row, which `authorize` already receives).
- Or refuse sessions with `impersonatedBy`, or ones created by known non-credential paths, when `reauthenticate` is in play.

### S-2 (Info): `listUserParticipants` truncates silently

- **Where:** `src/storage/participants.ts:106-121`; `endParticipants` at `:91-97`.

`findMany` has `limit: 200`, no sort and no `truncated` flag. Ended rows are kept until the original session expiry, so a heavy user (many devices or sessions times many SPs) can exceed 200 rows. A host's "sign out of all applications" would then skip SPs without knowing it.

**Suggested fix:** return `{ participants, truncated }` and sort by `expiresAt desc`. Do the same for the `session.ended` payload.

---

## Info

- **I-1: the loop guard can cost an extra sign-in** (`issue.ts:235`). It fires only when `request.forceAuthn` is set. Take a request without ForceAuthn, from a user with no session:
  1. The user signs in (session created after `request.createdAt`).
  2. `authorize` still says `reauthenticate`, so the request is re-parked and the user must sign in a second time.
  3. Only then does the guard deny.

  This is a UX issue with no security impact. `new Date(session.createdAt) >= request.createdAt` alone, without the `forceAuthn` condition, would stop after one round.
- **I-2: `logSafe` does not strip U+2028 or U+2029** (`src/saml/request.ts:57`). These LINE and PARAGRAPH SEPARATOR characters can split lines in some log viewers. This matters because the host's `authorize` `reason`, which may carry user-derived text, is now logged through `logSafe` at info level. Suggest adding `  ` to the class.
- **I-3: `from-metadata` checks the size cap after parsing.** It calls `c.req.json()` on the whole body before the 1 MB check on `xml` (`admin.ts:82-83`). The route is admin-only and checks the session first, so the only effect is memory and CPU bounded by the Workers body limit. Suggest checking `content-length` first.
- **I-4: one inline style attribute is blocked by the page's own CSP.** `admin.ts:156` has `style="width:auto"`, which the nonce-only `style-src` blocks. It is cosmetic.
- **I-5: migrations fail closed.** Hosts not on D1 have to migrate stored SP JSON (0006) and add the participant columns (0007) themselves. Without that, stored SPs become `valid: false`, which the strict schema enforces, and, with session tracking on, every issuance fails with INTERNAL_ERROR (participant not recorded). Nothing fails open. I checked migration 0006's mapping (`requireSignedAuthnRequests` to `requestSignatures`, `signResponse`/`signAssertion` to `sign`); it is correct or stricter.

---

## Areas checked with no finding

- **`requestSignatures`** (`request.ts:410-419`): `"ignore"` never verifies. `"verify-if-signed"` rejects bad signatures and fails closed when certificates exist only in metadata that hasn't loaded. `"require"` rejects unsigned requests. A signed request must carry Destination. Stripping a signature under `"verify-if-signed"` is inherent to that policy, and the ACS URL stays allow-listed.
- **SLO `mustSign`:** for every other combination it matches the old rule. The `byNameId` match still needs `mustSign && signed`.
- **Reauthenticate and resume** (`issue.ts:227-243`, `resume.ts`):
  - The re-park sets `createdAt = now` and `forceAuthn = true`. Resume refuses sessions created before that (the existing test covers this).
  - IsPassive returns NoPassive.
  - The request is re-parked through `parkForLogin`, which reuses this browser's signed binding cookie. A re-parked rid used from another browser fails the binding check.
  - I found no way to reuse a consumed rid, or to replay the SAML request ID.
- **`nameId: { field }`** (`nameid.ts`):
  - It refuses fields without `input: false` in any definition, and fields unknown to the server.
  - Prototype names (`constructor`) are refused.
  - The check runs at startup, at registry save, when a record is viewed, and at issuance; an empty value gives ACCESS_DENIED.
  - Better Auth's OAuth and @better-auth/sso provisioning (`parseAdditionalUserInputFromProviderProfile`) drops `input: false` fields, so an upstream IdP in the D-045 broker cannot set them either.
- **Participants:** `endParticipants` touches only rows under the hashed `sessionKey`. `listUserParticipants` filters on an exact `userId` match, so a case-insensitive collation can't widen it. Rows from before the upgrade have no `userId` and are excluded.
- **`samlIdpListSessionParticipants`:** it is `createAuthEndpoint.serverOnly`, which sets `SERVER_ONLY` and has no path, so better-call never routes it. The existing test gets a 404 on three candidate paths. `isAction: false` has no runtime effect in 1.7.5.
- **Races on the SLO Map:** the delete and its hook run in the same request and isolate (`queueAfterTransactionHook`), so isolates do not matter. Concurrent SLOs of one session are harmless; the only problem is L-1.
- **Injection:**
  - `reason` passes through `logSafe(..., 200)` and then `logSafe(..., 300)` in `fail` (apart from I-2).
  - Admin page:
    - All stored data is rendered with `textContent` or `.value`.
    - `href` values are built with `encodeURIComponent` on regex-limited ids.
    - `CODE_LAUNCHABLE` JSON is escaped for `<`.
    - The server-side HTML uses `esc()`.
    - The CSP is nonce-only for scripts, with `frame-ancestors 'none'` and `base-uri 'none'`.
  - CSRF: POST `from-metadata` requires the same Origin and has no side effects. The registry POSTs go through Better Auth's origin check and are JSON-only.
  - The metadata and certificate downloads use fixed `Content-Disposition` filenames, so there is no header injection.
  - There are no open redirects: the sign-in redirect is constant, and `safeReturnTo` is unchanged.
- **DoS:**
  - The 1024-character ID stays inside `MAX_REQUEST_BYTES`. Replay keys are SHA-256 hashes, and `requestId` is `text` on MySQL (the field has no index); it is `varchar(8000)` on MSSQL.
  - Registry `findMany` is capped at 1000, the audit query at 50, and participant queries at 200.
- **Output:** `sessionEnd` never goes past the IdP session's expiry. Every `sign` value signs at least one part, including with encryption.
- **Schema and baseURL:** the new columns are optional. `withBasePath` is idempotent across repeated `init` calls.

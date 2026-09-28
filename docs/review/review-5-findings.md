# Review 5: everything since 4a44664 (D-040 to D-047), before 1.0.0-rc.1

- **Reviewed:** `main` at fad67c2 (2026-09-27). Scope: `git diff 4a44664..HEAD`, with the two internal pre-release reports (`pre-release-security-review.md`, `pre-release-docs-api-review.md`) taken as already covered; D-046's fixes and D-047 (step-up) landed after those reports, so they got the closest look, along with the areas the maintainer asked about: step-up, the `session.ended` event, and the example admin page.
- **Baseline:** `pnpm typecheck` and `pnpm lint` clean; `pnpm test` 126 files passed, 9 skipped; 1200 tests passed, 54 skipped.
- **Method:** code reading of every changed `src/` and `examples/workers-hono/src/` file, the relevant Better Auth 1.7.5 internals (`internal-adapter.mjs`, `with-hooks.mjs`, the admin, session and update-user routes), and a proof test per finding in `test/review5/` (Node project). Nothing in `src/` was changed.

**Overall:** no Critical or High findings. Two Medium functional findings in step-up (a headline feature of this release), two Low, and a few Info items. The security fixes from D-046 hold. I'd fix R5-1 and R5-2 before rc.1: as shipped, an SP that sends `ForceAuthn` with its `RequestedAuthnContext` can never be stepped up.

---

## Findings

### R5-1 (Medium, functional): the first sign-in round never carries `acr_values`, so `ForceAuthn` SPs can't be stepped up

- **Where:** `src/endpoints/sso.ts:77-84` (`proceed` parks with no `acr`), `src/endpoints/sso.ts:90-98` (`parkForLogin`), `src/endpoints/issue.ts:266` (the step-up loop guard).
- **What happens:** `stepUpTarget` is only computed at issuance. When the request is parked before issuance (no session, or the SP sent `ForceAuthn`), the login redirect has `prompt=login` at most, and no `acr_values`. The login page therefore can't know that more than a password is wanted.
  - **Signed-out user, `minimum` MFA:** password sign-in, resume, judged insufficient, re-parked *now* with `acr_values`, second sign-in. Works, at the cost of an extra round (the same shape as the internal review's I-1).
  - **SP `ForceAuthn="true"` + `RequestedAuthnContext`** (a common pairing: "re-authenticate with MFA"): the request is parked with `forceAuthn: true`, the page does a password sign-in, resume accepts the fresh session, and the loop guard (`request.forceAuthn && session.createdAt >= request.createdAt`) fires: `NoAuthnContext`. The page was never told which level to deliver, and there is no second chance. Step-up is unreachable for such an SP.
- **Proof:** `test/review5/r5-step-up-first-round.test.ts`, "R5-1" block: the first and third tests fail (the redirect has no `acr_values`; the third also shows the `NoAuthnContext` dead end after the one round).
- **Suggested fix:** compute the target when the request is validated (`sso.ts` already calls `stepUpTarget` there for the early refusal) and pass `{ acr: target }` on the first park too, in `proceed`, whenever a context was requested. The guard then stays valid: a page that was told the level and still didn't deliver it deserves `NoAuthnContext`. Add the two failing tests to `step-up.test.ts`.

### R5-2 (Medium, functional): after an `authorize()` re-authentication round, step-up is refused without its own round

- **Where:** `src/endpoints/issue.ts:230-240` (D-044 re-park sets `forceAuthn: true`), `src/endpoints/issue.ts:266` (step-up guard keys on `request.forceAuthn`).
- **What happens:** the two mechanisms share one flag. `authorize` says `reauthenticate`, the request is re-parked as `forceAuthn`, the user signs in again (password), `authorize` is now satisfied, and the step-up check finds the context unmet. Because `forceAuthn` is set and the session is fresh, the guard answers `NoAuthnContext`. `acr_values` was never sent.
- **Proof:** `test/review5/r5-step-up-first-round.test.ts`, "R5-2" block (fails: `NoAuthnContext` where a step-up round was expected).
- **Suggested fix:** either of:
  - record *why* a request was re-parked (for example `stepUp: true` on the pending request) and let each guard key on its own reason; or
  - send `acr_values` on every park when a context was requested (the R5-1 fix, applied to the D-044 re-park too), so one round is always enough for a page that honours it.

### R5-3 (Low, privacy): participant rows outlive a deleted user

- **Where:** `src/index.ts:96-144` (hooks on `session` only), `src/storage/participants.ts:292-302` (ended rows kept until `expiresAt`).
- **What happens:** Better Auth's `deleteUser` (user self-deletion and the admin plugin's `removeUser`) deletes the sessions through the hooks, so `session.ended` fires correctly. But the `samlIdpSessionParticipant` rows, marked ended, stay until the old session's expiry (7 days by default), each carrying the NameID, usually the email. Nothing keys off the user's deletion. The audit table has the same data under a documented retention; the participant table's copy isn't mentioned in the privacy notes.
- **Proof:** `test/review5/r5-session-ended-user-delete.test.ts` (fails: one row still names the deleted user).
- **Suggested fix:** a `user.delete.after` database hook that deletes participant rows by `userId` (the same observer rules as the session hook). Mention the participant table next to the audit log in `observability.md`'s personal-data note.

### R5-4 (Low, semantics): `Comparison="maximum"` below the achieved level asks for a sign-in round that can't help

- **Where:** `src/endpoints/issue.ts:259-269`, `src/saml/request.ts:389-404`.
- **What happens:** with `levels: [PPT, MFA]` and a session `current()` reports as MFA, a `maximum` PPT request is unmet, `stepUpTarget` is PPT, and the user is sent to sign in again with `acr_values=PPT`. A host's `current` typically reads user state (`twoFactorEnabled`), so the fresh session is MFA again and the guard answers `NoAuthnContext`. The round trip is a dead end by construction.
- **Proof:** `test/review5/r5-step-up-maximum.test.ts` (fails: a 302 to sign-in where an in-protocol answer was expected).
- **Suggested fix:** never park for `maximum`. Either answer `NoAuthnContext` at once, or issue with the achieved class and document that reading of §3.3.2.2.1 ("as strong as possible" is what the IdP can offer). The first is the conservative choice.

### R5-5 (Info): `RequestedAuthnContext` class refs are stored unbounded in pending rows

- **Where:** `src/saml/request.ts:328-337`, `src/storage/pending.ts:382`.
- The Subject was bounded (1024 characters) before landing in a pending row (R4-L2). The new `classRefs` list has no cap of its own, only the message's 64 KiB and 200-element limits, and it is copied into up to three verification rows (continuation, park, re-park). Bounded, so not a DoS, but inconsistent with the Subject rule. Suggest at most 16 refs of at most 1024 characters, refusing the rest as `INVALID_SAML_REQUEST`.

### R5-6 (Info, docs)

- `SECURITY.md:26` says "nothing is published to npm yet"; false from rc.1. Say "release candidates on the `next` tag; only `main` gets fixes until 1.0.0".
- `.github/workflows/ci.yml:84` comment still says Keycloak 26.4 (compose runs 26.7).
- `docs/guide/flows.md` (RequestedAuthnContext) doesn't say what happens when an SP sends `ForceAuthn` together with a context. After the R5-1 fix: "the first sign-in redirect already carries `acr_values`".
- `docs/guide/observability.md:91` (personal data) should also name the participant table (R5-3).

### R5-7 (Info, tests): the example admin page has no automated test

- `pnpm e2e` drives the example IdP on workerd through Keycloak, SimpleSAMLphp and the node-saml SP, but never opens `/admin`. The page's server routes (`requireAdmin`, `from-metadata`, `audit`) and its script are covered only by the example's typecheck. One Playwright spec (sign in as a listed admin, see the SP list, convert a metadata document, disable an SP, confirm a non-admin gets 403 and the impersonation refusal) would pin the D-046 L-3 fix.

### R5-8 (Info, admin page): Disable re-validates the stored config

- `examples/workers-hono/src/admin.ts:208`: "Disable" calls update with the row's current config, which runs the full validation. An invalid row (hand-edited, or older than a tightening) can't be disabled until it's fixed. It isn't used for sign-in anyway (`valid: false`), so this is cosmetic, but the button's error message will confuse.

---

## Checked with no finding

- **`session.ended` coverage.** Every Better Auth path that ends a database session goes through `deleteWithHooks` or `deleteManyWithHooks` (`deleteSession`, `deleteSessions`, `deleteUserSessions`, `deleteUser`), including `preserveSessionInDatabase`, which is a `deleteManyWithHooks` with a custom update. The admin plugin's ban, revoke, set-password and remove-user routes, `/revoke-sessions`, `/revoke-other-sessions`, `/change-password` with `revokeOtherSessions`, the two-factor plugin and the lazily deleted expired session (`/get-session`) all reach the hook with the row and, inside a request, its endpoint path. `reason` classification (`expired` by `expiresAt`, `signed-out` by `/sign-out`, else `revoked`) matches. The startup warning for secondary-storage-only sessions is the right one: that path bypasses the hooks.
- **The SLO marker (D-046 L-1 fix).** Cleared on a throwing delete; ignored after a minute; the no-hook secondary-storage case leaves a marker that only ever expires. Hook and delete run in one request and isolate.
- **Step-up matching.** `satisfiesAuthnContext` follows §3.3.2.2.1 on the level order, with equal-level boundaries right; classes outside `levels` match only exactly; DeclRefs never; `Comparison` is XSD-enumerated so the cast is safe; `current()` results outside `levels`, or throws, issue nothing. The achieved class is what the assertion states. IsPassive gets `NoPassive`; the early refusal at request time fires only for unreachable requests.
- **Re-authentication and resume.** The re-park sets `createdAt = now` and reuses the browser binding; a stale return is `REAUTHENTICATION_REQUIRED` and consumes the pending row; no way found to reuse a consumed rid or replay the request ID across a re-park.
- **`authorize` verdicts** (D-044): only `true` and `{ allow: true }` allow; `reason` goes through `logSafe` twice; the session passed is the row just re-read.
- **Registry API** (D-040 decisions 2, 3, 5): one record shape on every route, exact-match row lookups, both permission checks required when both are configured, impersonated sessions refused, user re-read from the database, `sensitiveSessionMiddleware` on every route, the create and update read-back removed.
- **NameID from a field** (D-041): the writable-field rule, checked at startup, on save, on view and at issuance; prototype names refused by the field-name regex.
- **`baseURL` rule** (D-040 decision 6): idempotent across repeated `init`; custom `basePath` honoured; mismatch warning.
- **Request signatures** (D-040 decision 4) and the L-2 warning: `"ignore"` never verifies; `"verify-if-signed"` fails closed without loaded certificates; logout needs a signature unless `"ignore"`.
- **Admin page** (L-3 fix included): database re-read, impersonation refused, cookie cache bypassed; nonce CSP, `textContent` everywhere, `esc()` on server-rendered strings, same-origin check on the only POST, Content-Length check before parsing, fixed download filenames, no open redirect.
- **Release path:** tag must match `package.json`, `private` must be gone, the commit must be on `main`, the CHANGELOG must have the version's section, the tested tarball is the published one, staged publishing with a required reviewer, `next` tag for pre-releases. `pnpm pack:check` passes in CI. `package.json` `files` covers `dist`, the wasm and the notices; LICENSE and README are added by npm.

## What a project should have before its first release: present

CHANGELOG (first-release notes), SECURITY.md with a private reporting path, CONTRIBUTING with a release checklist, LICENSE and THIRD_PARTY_NOTICES, a versioning and support policy, issue forms, a CI matrix (lowest and latest peer, Node 22 and 24, three real databases, wasm reproducibility, secret scan, e2e in Chromium), CodeQL, Scorecard, OSV, a dependency audit that blocks, and a release pipeline with provenance and an SBOM. The DECISIONS record with mutation proofs per feature is unusual and worth keeping up.

## Before rc.1, in order

1. Fix R5-1 and R5-2 (one change: send `acr_values` on every park when a context was requested; optionally the per-reason flag). Move the `test/review5` step-up tests into `step-up.test.ts`.
2. Decide R5-4 (no round for `maximum`) and R5-3 (a `user.delete.after` hook); both are small.
3. Docs: R5-6.
4. The release checklist in CONTRIBUTING: version, `private`, the CHANGELOG section, tag.

## Tried and rejected

- **Replay of a re-parked request across browsers:** the re-park rehashes the current browser's binding cookie; a rid used elsewhere fails the binding check.
- **Forging `session.ended` reasons or suppressing the event through the SLO marker from a request:** the marker is set only by the plugin's own logout, after the session was authenticated, and expires in a minute.
- **Growing the participant table from outside a session:** rows are written only at issuance, after the account policy.
- **`current()` returning a class outside `levels` to bypass the comparison:** refused with `INTERNAL_ERROR` before comparison.
- **`Comparison` values outside the enumeration:** refused by the XSD before parsing.
- **Case-folding collations widening `listUserParticipants`:** exact-match filter after the query (R4-L8 pattern).
- **Admin page:** stored config or SP ids reaching `innerHTML` or an `href` unescaped (none: `textContent` and `encodeURIComponent` on regex-limited ids); a cross-site POST to `from-metadata` (Origin check); an impersonated admin reading the audit feed (refused since D-046).

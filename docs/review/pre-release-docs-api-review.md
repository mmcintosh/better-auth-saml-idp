# Docs/API consistency review before 1.0.0-rc.1 (2026-09-27)

Reviewed on main at d3185da. No repo files were modified. `pnpm build` succeeded, and `pnpm docs:check` passed (303 links; relative links and anchors).
Doc snippets were type-checked in scratchpad/tc/snippets.ts against src/index.ts and src/client.ts.

## Must fix before rc.1

1. **The docs still say the release waits for better-auth-cloudflare 0.4.** README.md:20 and README.md:166 ("Not on npm yet ... don't run npx"), README.md:193, CHANGELOG.md:7 ("1.0.0 waits for 0.4"), README roadmap :58 (from scripts/comparison/data.py) and examples/workers-hono/README.md:8.
   - rc.1 is published to the `next` dist-tag (release.yml:89-94), so install and npx instructions need `@next`: README.md:188-190 and getting-started.md:10.
2. **better-auth-cloudflare ≥ 0.4 is stated as a hard Workers requirement.** See README.md:200, getting-started.md:14 and cloudflare-workers.md:9.
   - The plugin has no dependency on it: it is a devDependency only (DECISIONS:193), and 0.4 isn't on npm.
   - Suggested wording: "if you use better-auth-cloudflare, ≥ 0.4 (or main)".
   - versioning.md:38 implies a declared range for it, but there is none.
3. **The client docs name a method that doesn't exist.** options.md:182 lists `serviceProviders.{list,...}`. The list route is `/saml-idp/service-providers`, so the client call is `authClient.samlIdp.serviceProviders()`, and `.list` fails to type-check.
4. **Two server-side snippets don't compile under strict TS.**
   - service-providers.md:141 `auth.api.samlIdpCreateServiceProvider(...)`: registry endpoints are typed optional (TS2722, needs `!` or a guard). The same applies to `auth.api.samlIdpListSessionParticipants` (CHANGELOG:53, events.ts doc).
   - Its `body.serviceProvider` is typed `Record<string, unknown>`, so a `ServiceProviderConfig` (for example from `serviceProviderFromMetadata`) isn't assignable.
   - service-providers.md:135 `error.issues` isn't on the client error type.
5. **The README options tables are missing options.**
   - `sessionNotOnOrAfter` is absent, both globally (README:298-320) and per SP (README:324-341).
   - `events` doesn't list `onSessionEnded` (README:310). The same gap is in the features line at README:41 and the roadmap at :57.
   - `singleLogoutService` doesn't list `responseUrl` (README:338).
   - `encryption` doesn't list `allowInsecureCbc` (README:337).
6. **The registry API is described as needing `canManage` only.** See README:359, README:496 and README:515-516. The code also mounts it with `permissions: true` (index.ts:158), and options.md:76 is correct.
7. **Old option names remain outside DECISIONS and the changelog history.**
   - README:68, scripts/comparison/data.py:69 and docs/comparison/index.html:90 (generated) still say "signResponse and signAssertion".
   - CHANGELOG.md:70 ("Per-SP signResponse/signAssertion") and CHANGELOG.md:93 (`spCertificate`) are in *Added*, which describes current features, yet those names are now rejected.
   - The other hits are legitimate: e2e/lib/keycloak.mjs:40 (Keycloak's own key), migration 0006, and test/unit/options.test.ts (it tests that the old names are rejected).
8. **Things are missing from the CHANGELOG.**
   - D-045 (identity-broker recipe, tested).
   - The example admin page (87d1b51, f7ddd2e).
   - Salesforce verified live with SLO (it appears only as a Fixed item).
   - Newly exported types: `AuthorizeResult`, `SessionLimit`, `NameIdSource`, `SessionEndedEvent`, `ServiceProviderRecord`. Line 29 lists only three types.
   - For a first release, the *Changed* section (renames, "old names are rejected", route moves) describes unreleased states. Either fold it into *Added* or label it "for users of pre-release main".

## Schema / migrations

- The tables, columns, types, nullability and indexes agree across src/schema.ts, example schema.ts, migrations 0001-0007 and schema.md. The exceptions:
  - schema.md:33-43 omits `uniqueIndex(sp_id, request_id)`, which README:228, the example and the migrations all have (src/schema.ts:9 says hosts should add it).
  - schema.md:14 lists migrations 0001-0005 only; it is missing 0006 (stored-config renames) and 0007.
  - schema.md:125 and schema.md:130 list the audit `type` values without `session.ended`, which is recorded (events.ts, all reasons except expired).
  - examples/workers-hono/src/schema.ts:124 says "migration 0006/0007", but only 0007 adds that column.
  - Migration 0001's header says "D1 test host schema; must match test/support/d1/schema.ts", which is confusing in an example.

## Exports / dist

- index.ts exports every type a user needs, and dist/index.d.ts matches. `exports` covers `.` and `./client`. No gaps.

## Nice-to-have

- Keycloak is now 26.7 (e2e/docker-compose.yml:6), but README:118, CHANGELOG:86 and docs/testing-with-sps.md:10 say 26.4.
- The roadmap item "Admin page in the example" (README:89) is still unchecked, and "Admin UI: out of scope" (:99) needs a note about the example page.
- options.md:118: "(code SPs only)" is placed after "a throw is ACCESS_DENIED", so it reads as though ACCESS_DENIED applies only to code SPs.
- The `@better-auth/core` peer dependency isn't mentioned in the requirements (README:197, getting-started:14).
- getting-started first-run confusion:
  - Step 3 `serviceProviders: []` logs "every AuthnRequest will be rejected".
  - Step 4 (:67) omits the audit and onSessionEnded tables.
  - Step 6 (:120) and README:285 omit the Salesforce guide.
- README:234 "Upgrading from a pre-release..." is confusing for new users; consider squashing the example migrations for 1.0.
- users-and-access.md:165 `session.mfaCompletedAt` isn't on `Session`, so it won't type-check. Mark it as a host field.
- CHANGELOG section order (Fixed, Changed, Security, Added) differs from Keep a Changelog, and there is a stray blank line at :63.

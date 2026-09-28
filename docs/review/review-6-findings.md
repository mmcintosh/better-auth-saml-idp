# Review 6: multi-tenant IdP phase 1, and everything since 1.0.0-rc.1

- **Reviewed:** branch `review-6` = multi-tenant phase 1 at 5c1da05 (`git diff b22e70a..5c1da05`, D-052), plus `git log v1.0.0-rc.1..b22e70a` (Next.js example, Prisma/Drizzle matrix, Bun/Deno smoke, CI, Scorecard/SBOM). Date: 2026-09-28.
- **Method:** read every changed `src/` file, the design (`multi-tenant-design.md`, maintainer decisions §9), the guide and D-052; then tried to break each isolation claim with tests. A proof test for each finding is in `test/review6/`. Nothing in `src/` was changed. Reviews 4 and 5 were not redone.

## In plain words

The core of phase 1 holds. I could not make an SP of one tenant receive anything issued under another tenant's name or the root's, by any route: tenant URLs, the root URLs, IdP-initiated sign-in, resumed or re-entered requests, or Single Logout. Non-members are refused. Disabled and unknown tenants look the same from outside. With tenants off, the output is unchanged.

The problems are at the edges of a tenant's life: what happens when things are deleted, and upgrading on MongoDB.

1. **When a customer's organization is deleted, its tenant carries on (R6-1, Medium).** The tenant is tied to an organization id and nothing else. Some databases hand out a freed id again: SQLite and D1 do this with `generateId: "serial"`. There, the next organization anyone creates gets the old id, and with it the old customer's IdP identity and SPs. I proved it end to end: an ordinary user created an organization and received a signed assertion, under the deleted customer's name, carrying the customer's admin role.
2. **A deleted tenant's key can be given to another organization (R6-2, Low).** Tenant URLs and entity IDs are built from the key and "never change", but deleting the tenant frees the key. The next tenant created with it gets the same entity ID, and the first customer's SPs still trust that entity ID. Only your own administrators can do this, and it can happen by accident (two customers both called "acme").
3. **Upgrading an existing registry on MongoDB doesn't work (R6-4, Medium).** With two or more stored SPs, the documented backfill fails on its first write. Until someone fixes the collection by hand, the registry can't save SPs either. Postgres and MySQL upgrade exactly as documented; I re-ran every step.
4. **Some refusals leave the tenant out of the event and the audit row (R6-3, Low).** Those rows look like the root IdP's, so a per-tenant audit query misses them.

Outside tenancy, since rc.1 (R6-5 to R6-8), the one that matters is **R6-5**: a routine advisory in the Next.js example's dependencies would block the release job, although the published package is unaffected. The rest are docs and example wording.

**Verdict:** phase 1 is fit for rc.2 **after R6-1 and R6-4 are fixed**. R6-2 and R6-3 are small and worth doing in the same pass. Nothing needs redesigning. Fix R6-5 before cutting rc.2 as well, so an unrelated advisory can't stop the release.

---

## Findings

### R6-1 (Medium, isolation): a deleted organization's tenant stays enabled, and passes to whoever gets that organization id next

- **Where:** `src/saml/tenant-directory.ts` (a tenant is `organizationId` + `tenantKey`, nothing else), `src/saml/identity.ts:identityFor`, `src/endpoints/issue.ts` (membership is checked by organization id), `src/endpoints/tenants.ts` (nothing reacts to organization deletion).
- **What goes wrong:** the organization plugin lets an organization's owner delete it; by default any user can create a new one. Deleting an organization leaves its `samlIdpTenant` row enabled: its metadata is served, its URLs route, and its SPs stay configured. Membership is judged by organization id alone. With `advanced.database.generateId: "serial"`, SQLite's `INTEGER PRIMARY KEY` (what Better Auth's migrator creates, and common on D1) gives the next row the highest freed id. So the next organization created takes the deleted one's id, and with it the tenant.
- **Scenario:** a customer's tenant "globex" (organization 2, the newest) has an SP for a cloud console that maps a constant admin role. The customer's owner deletes the organization. Any user creates an organization, gets id 2, and is its owner. They open `/saml2/idp/sso/globex` and receive a signed Response, Issuer `…/metadata/globex`, with the customer's role, for a user the customer never admitted. An SP that trusts this identity, such as a cloud console, signs them in to the customer's account with that role.
- **Even without id reuse:** a deleted organization's tenant is still listed, its metadata is still served, and it can't be told apart from a live one. The tenant API refuses to delete a tenant that has SPs, but the organization under it can be deleted freely.
- **Proof:** `test/review6/r6-org-id-reuse.test.ts` (Node; the workerd test schema uses text ids). It fails: the Response is a 200 with the assertion.
- **Suggested fix:** bind the tenant to *this* organization, not just its id.
  - Store the organization's `createdAt` in the tenant row at creation.
  - When a tenant is routed to or issues, also load the organization (cached with the tenant) and treat the tenant as absent if the organization is gone or its `createdAt` differs.
  - Document the organization plugin's `organizationHooks.beforeDeleteOrganization` as the place to refuse deleting a tenant's organization, or to disable its tenant.
  - Add the test above to `tenants.test.ts`.

### R6-2 (Low, isolation): a deleted tenant's key can be reused by another organization, which gets the same entity ID

- **Where:** `src/endpoints/tenants.ts` `samlIdpDeleteTenant` (deletes the row, which frees `tenantKey`) and `samlIdpCreateTenant` (only the UNIQUE column decides).
- **What goes wrong:** the guide says the key "can't change", because SPs pin the entity ID and URLs built from it. Deleting the tenant frees the key, though. A tenant for another organization created with the same key gets byte-identical entity ID, metadata, SSO and SLO URLs. The first customer's SPs are still configured with that entity ID and the shared certificate. This is the same danger design §1 names for slugs ("every URL and entity ID derived from `acme` now names the attacker's tenant"). Keys are chosen only by host administrators, so this is an accident, not an attack: for example, "acme" chosen for a second customer called Acme. A tenant still cached for up to `tenants.cacheSeconds` in another isolate also answers with the old key.
- **Scenario:** customer A (key `acme`) leaves. Its SPs are removed from the registry, but its CRM still trusts `…/metadata/acme`. Months later a new customer is onboarded with key `acme`, and a host administrator registers an SP for them with the entity ID of A's CRM. No overlap warning fires, because A's SP is gone. B's users now get assertions that A's CRM accepts.
- **Proof:** `test/review6/r6-tenant-key-reuse.test.ts` (Node and workerd). It fails: create returns 200 with A's entity ID.
- **Suggested fix:** make keys single-use. "Delete" becomes retire: the row stays, disabled, with `organizationId` released but `tenantKey` still reserved (or a small reserved-keys table). Say so in the guide.

### R6-3 (Low, audit): several refusals of tenant SPs are recorded without their tenant

- **Where:** `fail(...)` calls that name an SP but pass no `tenantOf(sp)`:
  - `src/endpoints/init.ts:66` (`IDP_INITIATED_NOT_ALLOWED`);
  - `src/endpoints/resume.ts:45,47,50` (`IDP_INITIATED_NOT_ALLOWED`, `ACS_URL_NOT_ALLOWED`, `REAUTHENTICATION_REQUIRED`);
  - `src/endpoints/sso.ts:147` (continuation "SP changed tenant");
  - `src/endpoints/slo.ts:148,233,234` (`LOGOUT_NOT_SUPPORTED`, "changed tenant").
- **What goes wrong:** D-052 and the guide say `denied` events carry `tenantId` when the SP belongs to a tenant, and the audit column exists "for filtering in SQL". These events have none, and their audit rows get `tenantId = NULL`, which is the root IdP's value. A per-tenant audit view (the reason for the column, design §5.5) silently misses them. They would even be counted as root activity.
- **Proof:** `test/review6/r6-denied-tenant.test.ts` (Node and workerd). Both tests fail: `tenantId` is undefined for `IDP_INITIATED_NOT_ALLOWED` (event and audit row) and for `REAUTHENTICATION_REQUIRED`.
- **Suggested fix:** add `...tenantOf(sp)` at each site listed. A unit test could check that every `fail(` passing `spId:` also spreads `tenantOf`, in the style of the identity lint test.

### R6-4 (Medium, upgrade): on MongoDB, the documented upgrade can't complete with two or more stored SPs, and the registry stops accepting writes

- **Where:** `src/schema.ts` `tenantRegistrySchema` (UNIQUE index `saml_idp_service_provider_lookup_key_unique` on the required `lookupKey`), `src/endpoints/tenants.ts` `backfillEndpoint` (writes through `adapter.update`), guide "Database", MongoDB paragraph.
- **What goes wrong:** Better Auth's MongoDB adapter creates a model's declared indexes itself, *before* the first `create`/`update` of that model in each process (`ensureModelIndexes` in `@better-auth/mongo-adapter`). The backfill's first `update` therefore builds the UNIQUE `lookupKey` index while the old documents all lack the field. MongoDB indexes a missing field as `null`, so two such documents are a duplicate key: the index build fails with E11000, and the update fails with it. The adapter forgets the failed build, so every later `create`/`update` of the model retries and fails the same way. The backfill can never get past its first row, and registry create and update fail too. The guide's instruction, "run step 3 before the UNIQUE index on lookupKey is created", can't be followed: the plugin gives no way to run step 3 without creating the index. D-052 lists "the upgrade steps on a populated MongoDB collection" as not verified; this is what that would have found. With one stored SP it works; with two or more it fails.
- **Scenario:** a MongoDB host with a registry of several SPs turns on tenants and calls `auth.api.samlIdpBackfillServiceProviderKeys()` as documented. It throws `E11000 … dup key: { lookupKey: null }`. Every stored SP now fails sign-in (no key), and the registry can't save any SP. Nothing issues under a wrong identity: it fails closed, but as an outage.
- **Proof:** `test/review6/r6-mongodb-upgrade.test.ts`. It runs with `ADAPTER_DB=mongodb` (a single-node replica set, as in CI) and fails with the E11000 index-build error.
- **Suggested fix:** document a MongoDB backfill that runs **before** tenants are turned on, in `mongosh`, which computes the same key. Checked: `require("crypto").createHash("sha256").update("saml-idp:sp\u0000" + tenantId + "\u0000" + entityId).digest("base64url")` in mongosh equals `lookupKeyOf`. For example: `db.samlIdpServiceProvider.find({ lookupKey: { $exists: false } }).forEach(d => db.samlIdpServiceProvider.updateOne({ _id: d._id }, { $set: { tenantId: "", lookupKey: <that hash of "" and d.entityId> } }))`. Alternatively, have the backfill write through the raw collection on MongoDB. Then add a populated-collection case to the adapter matrix (the proof test can move there).

### Info

- **I-1: backfill limits.** `backfillEndpoint` reads at most 10,000 rows, with no paging and no report of the cap, and the first failed write aborts it midway, with no per-row error. The second case happens, for example, when the old `UNIQUE(entityId)` was dropped before the backfill and a new SP took an old one's entity ID. Suggest paging, and catching and reporting per row. Also say in the Postgres/MySQL section of the guide what it already says for SQLite: drop the old constraint *after* the backfill.
- **I-2: tenant administration isn't in the audit log.** Creating, disabling and deleting tenants only goes to `logger.info`. Design §5.5 wanted registry actions audited. Not claimed by D-052, but worth it now that a tenant is a customer's identity.
- **I-3: a chosen key may equal another organization's id.** Organization B's tenant can take key `<A's id>`, so the URL that looks like A's is B's, and A can't later use its default key. It only confuses; admin-only. Refusing a key equal to another organization's id costs one query.
- **I-4: Single Logout mid-chain after a tenant is disabled.** A participant's LogoutResponse that arrives at a tenant URL disabled since the chain started fails on "unknown tenant", before the hop is looked up. The rest of the chain and the originator's answer are then lost. The session has already ended. The answer could be matched by RelayState first, as it is at any enabled URL.
- **I-5: turning tenants off again** (not a documented operation). With tenants off, stored lookups go by `entityId` alone. Where a root SP and a tenant SP share an entity ID (a new install without the old UNIQUE), `findOne` can return the tenant row. That row fails validation ("tenant: requires tenants.enabled"), so the root SP becomes unreachable. It fails closed.

---

## Deviations from the design listed in D-052: are they sound?

1. **Tenants need `registry.enabled`:** sound. Tenants live in the database, and failing at startup is right.
2. **`lookupKey` required, not nullable:** sound for SQL, and needed for MongoDB's UNIQUE index. But it is the direct cause of R6-4 on MongoDB, so the MongoDB upgrade needs its own procedure.
3. **Backfill as a server-only endpoint:** sound: `createAuthEndpoint.serverOnly` has no URL, and the key can't be computed in SQL. It fails on MongoDB (R6-4); see also I-1.
4. **Old `UNIQUE(entityId)` kept:** sound, and the safe direction. The guide's drop SQL is correct: I ran the whole documented upgrade (steps 1 to 4, then the drop) on Postgres 17 and MySQL 8.4 (`test/review6/r6-sql-upgrade.test.ts`, passes on both). Old SPs sign in afterwards, and one entity ID in two tenants goes from 409 to 200.
5. **Overlap warning needs the same entity ID and a shared ACS URL:** sound. Without a shared ACS URL, the Audience/ACS pair can't land at the other SP.
6. **Registry records carry `tenantId` only with tenants on:** sound, and keeps tenants-off output unchanged.
7. **A code SP's tenant must exist and be enabled:** sound (fails closed; tested).
8. **Not built (`canManage` with `tenantId`, `keys` in the record, CLI `--tenant`):** acceptable for phase 1. The reason given for `canManage` (it would turn 403s into an existence oracle before the row is loaded) is right.

## Upgrade path for a registry with rows

- **Postgres / MySQL:** correct and complete as documented (proof: `r6-sql-upgrade.test.ts`, passing).
- **SQLite / D1:** covered by the maintainer's tests. D1 migration 0008 and the guide's rebuild SQL match the example's schema.
- **MongoDB:** broken (R6-4).
- **Can a half-done upgrade leave the IdP unsafe?** I found no way.
  - Before the backfill, old rows are found by no lookup: they fail closed, and their records say so.
  - With tenants turned on before the column exists, lookups error (500).
  - A rollback to rc.1 after tenant SPs were stored is also safe: rc.1's SP schema is `.strict()`, so a stored config with `tenant` fails validation and is ignored, rather than becoming a root SP.
  - The one sharp edge, a backfill aborted midway, is in I-1.

## "With tenants off, output is byte-identical"

It holds.
- `tenants-off.test.ts` and its snapshot were committed in edde4bf, whose `src/` is identical to b22e70a (`git diff b22e70a edde4bf -- src` is empty). The snapshot hasn't been touched since.
- The normaliser only replaces per-run values: certificates, `_`-hex IDs, instants, digests, signature values, session indexes, tokens and nonces.
- Reading the code agrees: every tenant branch is keyed on `options.tenants` or `sp.tenantId`, the schema is unchanged, and no route is added.
- The only visible change without tenants is the documented, deliberate `ServiceProviderInfo.tenantId: null` passed to `authorize`.

---

## Everything else since v1.0.0-rc.1

No High findings. One Medium in release plumbing, three Low. A helper read these files on a scratch copy of b22e70a and ran the runtime smoke (including a tampered Response, which is rejected), the Drizzle and Prisma matrix on Postgres (10/10 each), `pnpm deploy` for the SBOM tree, and `tsc` on the Next.js example. I checked each claim below against the files myself.

### R6-5 (Medium, release): an advisory in an example's dependency blocks releases and every PR

- **Where:** `.github/workflows/release.yml:25` and `.github/workflows/dependencies.yml:20` (`pnpm audit --prod --audit-level low` at the workspace root); `pnpm-workspace.yaml` (`examples/*`).
- **What goes wrong:** at the root of a workspace, `pnpm audit --prod` covers every workspace package's production dependencies: Next.js, React, Hono, Better Auth and the rest, about 285 packages against the plugin's 4. The workflow's own header says only "what `npm install better-auth-saml-idp` brings in" should block. The Next.js example added a dependency that gets frequent advisories.
- **Scenario:** a low-severity Next.js advisory is published. The release `verify` job fails, so no rc or 1.0 can go out, and every PR's runtime audit is red until the example is bumped, although the published tarball is unaffected.
- **Proof:** unproven by a test (it is CI configuration). Evidence: `pnpm -r list --prod --depth 0`, and `pnpm audit --prod --json` reports 285 dependencies.
- **Suggested fix:** `pnpm audit --prod --filter better-auth-saml-idp` (the root package only). Give the examples their own non-blocking audit if wanted.

### R6-6 (Low, docs): "✅ CI" for Drizzle and Prisma table creation isn't what CI tests

- **Where:** `docs/guide/databases.md:25-27` ("Tables: `npx auth generate`, then your migration / `prisma migrate`", ✅ CI); `test/adapters/orm-schemas.ts`; `adapter-matrix.test.ts` `withDrizzle`/`withPrisma`.
- **What goes wrong:**
  - In CI, the tables and every UNIQUE index come from Better Auth's Kysely migrator. Drizzle and Prisma are only the query layer.
  - The Drizzle schemas in `orm-schemas.ts` declare no unique index at all. `prisma migrate` is never run.
  - So nothing checks that a *generated* Drizzle or Prisma schema carries the UNIQUE keys that replay protection and the registry rely on. That is the same class of gap that once disabled replay protection on MongoDB (D-033).
  - The paragraph under the table half-says this ("The tables are created by Better Auth's migrator"), but the table's Tables column and ✅ say otherwise.
- **Scenario:** a host follows the Drizzle row, generates a schema, and a missing UNIQUE on `samlIdpSeenRequest.key` goes unnoticed: AuthnRequest replay protection is silently off.
- **Proof:** unproven: Better Auth's schema generator isn't a dev dependency here, so the generated schemas can't be produced in a test.
- **Suggested fix:** either create the tables from the generated schemas in those matrix entries (drizzle-kit push / `prisma db push`), so the existing "8 concurrent inserts → 1" UNIQUE test covers them; or reword the Tables column to "Better Auth's migrator (Drizzle/Prisma as the query layer)".

### R6-7 (Low, example): the Next.js sign-in page's `acr_values` handling can't be reached

- **Where:** `examples/nextjs/src/lib/auth.ts:75` (`authnContextClassRef: PASSWORD_CLASS`, no `authnContext.levels`); `examples/nextjs/src/app/sign-in/page.tsx`; `examples/nextjs/README.md:59`; the CHANGELOG and README ("honours … acr_values").
- **What goes wrong:** the README says the page tells the user when `acr_values` asks for MFA, "then the IdP answers the SP with NoAuthnContext". With the example's configuration, the IdP answers an unsatisfiable RequestedAuthnContext at the SSO endpoint, before any redirect. `acr_values` is only ever sent with `authnContext.levels`, and then only for a level the host declared reachable. The branch is dead, and a host copying the page may believe it does step-up.
- **Proof:** `test/review6/r6-nextjs-acr-values.test.ts` (Node and workerd). It fails: 200 `NoAuthnContext` from the SSO endpoint, not a redirect with `acr_values`.
- **Suggested fix:** fix the README and CHANGELOG wording, or configure `authnContext.levels` in the example if it is meant to show step-up.

### R6-8 (Low, docs): the memory-adapter warning row in databases.md no longer renders

- **Where:** `docs/guide/databases.md:29-30`. The new paragraph was inserted between table rows, so `| Any | Better Auth's memory adapter | | ❌ doesn't enforce uniqueness: development only |` renders as literal text after the paragraph.
- **Proof:** unproven by a test (Markdown rendering; `docs:check` checks links only). Visible in any Markdown preview.
- **Suggested fix:** move the paragraph below the last row.

### Info (since rc.1)

- **Prisma engines downloaded at run time.** D-051 says "Prisma 6 bundles its engine, so no install scripts are needed". But `@prisma/engines@6.19.3` in the store has no binaries: pnpm 10 blocks its postinstall, and `prisma generate` downloads the engines from Prisma's CDN on each CI run, unpinned by the lockfile. This is CI only; it affects flakiness and supply-chain pinning (D-050's intent).
- **Release order.** `release.yml` stages the npm version (line 96) before `attest-build-provenance` (line 100). If attestation fails, a staged version exists and no GitHub release does, and a re-run fails at `stage publish`. The version is only staged, not live, so the damage is a manual cleanup. Attesting first avoids it.
- **D-049's count.** It says 13 `runs-on` lines; there are now 15 (the runtimes and nextjs jobs came later).
- **Prisma coverage wording.** The README roadmap's "Prisma and Drizzle on Postgres/MySQL" reads as if Prisma on MySQL is covered. Only Postgres is. The databases.md table and D-051 are accurate.
- **Next.js example keys.** `next start` also loads `.env.local`, so a deploy built from a directory where `pnpm keys` was run carries the development key and secret. The README says to use a secret store; one more sentence there would help.
- **Runtime versions.** The runtimes job pins action SHAs but not the Bun and Deno versions. That's acceptable for a smoke test.

### Tried and rejected (since rc.1)

- **Next.js sign-in page `callbackURL`:** same-origin only. `//host`, `javascript:`, backslash and userinfo tricks are refused. A resume link is bound to the parking browser anyway. The `prompt=login` handling never auto-continues.
- **Secrets:** none committed. `.env.local` is gitignored and written with mode 0600.
- **Workflows:**
  - no `pull_request_target`, and no `github.event.*` in `run:`;
  - new actions are SHA-pinned;
  - `permissions: contents: read` at the top, with `attestations: write` only on publish;
  - the npm CLI is pinned by integrity, with no install scripts.
- **SBOM:** the syft config is valid, and the deploy tree holds only the plugin's runtime dependencies.
- **Runtime smoke:** not vacuous. A tampered Response fails its signature check, and any failure exits non-zero.
- **Adapter matrix:** can't pass while skipping. `ADAPTER_REQUIRED` throws on missing variables, and an unknown database throws.

---

## Tried and rejected (held up)

**Routing and lookup**
- **Tenant key variants:** `ACME` for `acme`, `ac%6De`, a trailing slash, `acme/x`, an empty key, and a key with dots are all 404 or unknown. MySQL's case-insensitive collation is covered by the exact-match checks in `TenantDirectory.row` and `findTenant`, and a case-folded duplicate is refused as `TENANT_EXISTS`.
- **Organization id vs slug:** tenant creation checks the organization by id. A code or stored SP naming a slug (or another case of the id) finds no tenant and is refused. A slug in `organization` is refused by `tenantOrganization`.
- **Cross-tenant lookup:** an Issuer of tenant A at B's URL, a tenant SP at the root URL, and a root SP at a tenant URL all give `UNKNOWN_SERVICE_PROVIDER`. The stored-row tenant re-check and the issuance request-tenant check back each other up.

**Re-entered and resumed requests**
- **Re-entry at another URL:** an SSO POST continuation re-entered at another tenant's URL or the root's is refused. So is an SLO POST continuation. On resume and after a pending request's SP changed tenant, issuance compares `request.tenantId` with the SP's identity.
- **Deleting and re-creating a stored SP id in another tenant mid-login:** the pending request is refused (`request.tenantId` mismatch).

**Other flows**
- **IdP-initiated `/init?sp=`:** issued under the SP's own tenant, with membership enforced. A disabled tenant gets nothing, never the root identity.
- **SLO across tenants:** each participant gets its own tenant's identity, and the originator's is answered from its own. A participant's LogoutResponse Destination is checked against its own tenant's URL. A disabled participant is skipped as `PartialLogout`.

**Membership**
- Membership is re-read at every issuance (a deleted member is refused at once). The issuance guard refuses a tenant SP without its rule.
- Organization attributes without `only` are scoped to the tenant's organization. `only` naming other organizations is a host-administrator choice.

**Keys and oracles**
- **`lookupKey`:** computed only by `lookupKeyOf`, in registry create/update, the directory and the backfill. Collisions would need a NUL in an organization id (impossible: the tenant must exist), and a hit is re-checked for tenant and entity ID anyway. The same hash was checked in mongosh.
- **Existence oracles:** unknown, disabled and non-tenant keys get the same 404 on metadata (status, headers, body), and the same `UNKNOWN_SERVICE_PROVIDER` on SSO and SLO. An *enabled* tenant is distinguishable, which the design accepts (metadata is public). The cache timing is documented.

**Registry API and permissions**
- **Permissions:** tenant routes need `samlTenant`. Tenant SPs are managed with `samlServiceProvider`, as documented. Organization owners and admins get 403. Impersonated sessions are refused. The backfill endpoint has no URL.
- **Races and constraints:**
  - Deleting a tenant while an SP is being created in it can leave an SP pointing at a missing tenant, which fails closed.
  - Tenant creation races are decided by UNIQUE columns, which the MongoDB adapter declares too.
  - Entity IDs are unique per tenant between code and stored SPs (`inCode` per tenant).

**Events and compatibility**
- **Events:** `assertion.issued`, SP-initiated `logout`, `session.ended` participants, and audit rows of issued assertions carry the right `tenantId`. Only the `denied` paths in R6-3 don't.
- **Rollback to rc.1:** tenant SP rows fail rc.1's strict schema, so they are ignored rather than served as root SPs.

---

## Command results (baseline, before adding the review tests)

- `CI=true pnpm test`: 139 files passed, 10 skipped; 1324 tests passed, 58 skipped (exit 0). This matches D-052's count.
- `pnpm lint`: clean (174 files).
- `pnpm typecheck`: clean.
- `pnpm build`: built `dist/`.
- `pnpm docs:check`: 373 links checked, OK.

After adding `test/review6/`, `pnpm lint` (181 files) and `pnpm typecheck` are still clean. The proof tests fail as intended: R6-1 on Node; R6-2, R6-3 and R6-7 on Node and workerd; R6-4 against MongoDB 8.2 (a temporary single-node replica set, since removed). `r6-sql-upgrade.test.ts` passes on Postgres 17 and MySQL 8.4. The adapter-only files skip without `ADAPTER_DB`.

# Multi-tenant IdP: design review

Reviewer's design for the roadmap item "One IdP identity per organization" (README.md:87), against `main` at d7ceb12. No repo files were changed.

Labels used throughout:
- **[verified]**: read in this repo's code or docs (file:line), or in a cited vendor doc.
- **[judgment]**: my recommendation or inference.

---

## 0. Recommendation in one paragraph

Build it in three phases. **The tenant boundary must not depend on SPs checking `Issuer` correctly.**

- **Phase 1:** per-organization entity ID, metadata and SSO/SLO URLs, all under one shared signing key. Only the host's own admins may register tenant SPs.
- **Phase 2:** per-tenant signing keys, stored encrypted in the database, with the existing three-step rotation per tenant.
- **Phase 3:** delegated tenant administration, where an organization's owners and admins manage their own SPs. It is **allowed only once per-tenant keys are on**, and startup enforces that.

Three choices keep the change small and safe:
- `spId` stays globally unique, so replay keys, SessionIndexes, participants, pending requests and audit rows need no change.
- Only entity-ID uniqueness becomes per tenant.
- Tenancy is a new opt-in option. With it off, the schema and every byte of output are unchanged.

---

## 1. What varies per tenant

### What the plugin does today [verified]

There is one IdP identity:
- **Entity ID:** `options.entityId`. It is the `Issuer` in Responses (src/saml/response.ts:113, 116), in error Responses (response.ts:221), and in LogoutRequests and LogoutResponses (src/endpoints/slo.ts:122, 147).
- **Signing key:** `options.signing`, used at response.ts:192–194 and 225, slo.ts:134–135 and 155–156, and for metadata (src/endpoints/metadata.ts:41–46).
- **Endpoints:**
  - SSO: `SSO_PATH = "/saml2/idp/sso"` (src/saml/idp.ts:396);
  - SLO: `/saml2/idp/slo`;
  - metadata: `METADATA_PATH` (metadata.ts:8).
- **samlify IdP object:** one per base URL (idp.ts:419–448, 474–491). It uses `options.entityId` and `options.signing`.

### What other IdPs do

| Product | Entity ID / Issuer | Signing key scope | Notes |
|---|---|---|---|
| **Okta** | "A unique Okta Entity ID is generated for each application" (the "Identity Provider Issuer") [verified: support.okta.com, "Beginner's Guide to SAML"] | **Per app** by default: "the active certificate is scoped only for your app integration, while inactive certificates are scoped for your entire org"; generate, then activate [verified: help.okta.com, "Manage signing certificates"] | Tenancy is the Okta org itself (`{org}.okta.com`, host-based). Inside an org, each app is its own IdP identity. |
| **Auth0** | Per tenant (`urn:{tenant}.auth0.com` by default) [judgment: from memory, not re-verified today] | Tenant signing key, downloadable per application [verified: Auth0 "Configure Auth0 as SAML IdP" (SSO URL `https://{tenant}.auth0.com/samlp/CLIENTID`, certificate from the app's Advanced Settings)] | Tenancy is host-based (`{tenant}.auth0.com`, or a custom domain). The repo's own comparison notes "tenant-wide key" for one product (docs/comparison.md:45). |
| **WorkOS** | Not a SAML IdP: it is the **SP** side. Each organization's connection gets its own SP entity ID, ACS URL and metadata [verified: workos.com/docs/integrations/saml] | n/a | The mirror image of this feature: a distinct SAML identity per customer connection. |
| **Keycloak** | Per realm: descriptor at `/realms/{realm}/protocol/saml/descriptor` [verified: several third-party guides; the Issuer is the realm URL, from memory] | **Per realm:** one active key pair, passive keys for verification, disabled keys; rotate by adding a higher-priority key [verified: Keycloak Server Admin, "Configuring realm keys"] | **Path-based** tenancy. The closest analogue to this design. |
| **authentik** | Per provider: the Issuer defaults to `https://authentik.company/application/saml/<application_slug>/metadata/` (2026.5) [verified: docs.goauthentik.io/add-secure-apps/providers/saml] | Per provider: selectable signing certificate [verified: same page] | Path-based. The entity ID is the metadata URL. |

**What they have in common [judgment]:** no mainstream IdP puts every customer behind one entity ID *and* one key. Keycloak (path-based realm, per-realm keys) is the model to copy. The authentik pattern of "the entity ID is the metadata URL" is the right default for entity IDs.

### Routing: path, query or host

| Option | Verdict |
|---|---|
| **Path, endpoint first: `/saml2/idp/sso/:tenant`, `/saml2/idp/slo/:tenant`, `/saml2/idp/metadata/:tenant`** | **Recommended.** Better Auth's router supports path parameters (it has `/callback/:id` and `@better-auth/sso`'s `/sso/saml2/sp/acs/:providerId` [verified: node_modules/better-auth/dist/api/routes/callback.mjs:26; @better-auth/sso/dist/index.mjs:4198]). Better Auth's `skipOriginCheck` matches by **prefix** (`currentPath.startsWith(skipPath + "/")`) [verified: node_modules/better-auth/dist/api/middlewares/origin-check.mjs:27–30], so the existing `SSO_PATH` and `SLO_PATH` entries (src/index.ts:162) cover the tenant routes with no change. |
| Path, tenant first (`/saml2/idp/o/:tenant/sso`) | Works, but needs a new `/saml2/idp/o` skip-origin prefix. That prefix would also cover anything added under it later. Rejected for that reason. |
| Query (`/saml2/idp/sso?tenant=`) | Rejected. SAML HTTP-Redirect signs the exact query string, SPs build it themselves, and several SPs drop or reorder query parameters on the SSO URL. The `Destination` check (sso.ts:222, 233) would also need to reason about the query. |
| Host-based (`acme.idp.example.com`) | Deferred to Phase 4. It needs wildcard DNS and TLS, and it collides with the base-URL-per-Host cache (idp.ts:467–491, bounded at 32). It also makes cookies per host, which breaks the single IdP session. Custom domains per tenant are a separate feature. |

**Tenant identifier in the URL: the organization's `id`, never its slug [judgment, security]:**
- Slugs change: the organization plugin allows updating them.
- Slugs can be claimed: by default, users create organizations (src/organizations.ts:304–308, and the warning in users-and-access.md). If org A frees the slug `acme` and an attacker's org takes it, every URL and entity ID derived from `acme` now names the attacker's tenant.
- Entity IDs must never change: SPs pin them.

For friendlier URLs, a host-chosen **immutable** `tenantKey` in the tenant row (see §6) can replace the org id. Default it to the org id.

**Default entity ID:** `${baseURL}/saml2/idp/metadata/${tenantKey}`. This is the authentik convention, and it is self-describing. The root IdP keeps `options.entityId` unchanged.

---

## 2. Where tenant keys live

### The options

| Option | Isolation | Operability | Workers fit | Verdict |
|---|---|---|---|---|
| **A. One shared key, per-tenant entity IDs** | Only the `Issuer` string separates tenants (see §5.1). | Trivial: nothing new to protect or rotate. | Perfect. | **Phase 1 only**, and only while SP management stays with the host's admins. |
| **B. Per-tenant keys in the database, encrypted** | A cryptographic boundary: tenant B's key can't produce anything tenant A's SPs accept. | The plugin generates, rotates and publishes keys. | Good, with per-isolate caching (below). | **Phase 2 default.** |
| **C. Host callback `resolveTenantSigning(tenant) => SigningConfig`** | As good as the host's store (KMS, Secrets Store, Vault). | The host owns generation and rotation. The plugin can't enforce "certificate matches key" or uniqueness until call time. | Callback latency on every cache miss. | **Deferred escape hatch.** Build it when a named host needs KMS or an HSM. Not needed for the first version. |

### The details of option B

**Envelope encryption:**
- Use Better Auth's own `symmetricEncrypt` / `symmetricDecrypt` [verified: node_modules/better-auth/dist/crypto/index.d.mts:17–32].
  - The cipher is XChaCha20-Poly1305 (crypto/index.mjs:7, 33) with versioned secrets (`SecretConfig { keys: Map<version, secret>, currentVersion }`, @better-auth/core types/secret.d.mts:2–9).
  - So rotating the key-encryption key is Better Auth's own `secrets` rotation, not a new mechanism.
  - An optional `tenants.keyEncryptionSecret` override covers hosts that want a separate secret.
- **The cipher has no AAD parameter [verified: signature].** So the plaintext is the JSON `{ v: 1, tenantId, kid, privateKeyPem }`, and after decryption the plugin **checks that `tenantId` and `kid` match the row** [judgment, security]. Without this, anyone who can write to the database could copy tenant A's ciphertext into tenant B's row, and B would then sign with A's key.
- **Honest limit [judgment]:** on Workers, the encryption secret and the database binding sit in the same Worker. The encryption protects backups, dumps, read replicas, and SQL-injection-style **read-only** database leaks. It doesn't protect against a compromise of the Worker itself. Document it that way. Don't call it an HSM.

**Key generation:**
- It runs **only on the admin path** (creating a tenant, or starting a rotation), never on sign-in.
- Generating an RSA-2048 key costs tens to hundreds of milliseconds of CPU [judgment]. Warm SSO requests are measured at a 16/24 ms median/p90 (DECISIONS.md D-017).
- The self-signed certificate builder already exists in the CLI (src/cli/keygen.ts:1–60, `selfSignedCertificate`). Move it to a shared module.
- **Verify on workerd before committing** that `generateKeyPairSync("rsa")` works under `nodejs_compat`. If it doesn't, use `crypto.subtle.generateKey` (RSASSA-PKCS1-v1_5), export PKCS#8, then call `createPrivateKey` [unverified].
- Also accept a key the host uploads (from `keygen`), for hosts that generate keys offline.

**Caching per isolate:**
- An LRU of parsed `KeyObject` values plus the certificate, keyed by `(tenantId, kid, row.updatedAt)`.
- Bounded (256 entries, say), like `MAX_CACHED_BASE_URLS` (idp.ts:467) and the directory cache (sp-directory.ts:501).
- Freshness follows `registry.cacheSeconds` (default 60 s), so a rotation or a disabled tenant reaches other isolates within that time, exactly as for stored SPs (D-027). Document it.
- A cache miss costs one database read, one decryption and one `createPrivateKey`, all small next to the XSD validation already on the SSO path.

**Runtime checks, the same as at startup today (src/options.ts:334–360):** RSA, at least 2048 bits, and certificate matches key. They run at load time. A failing tenant key refuses to issue (`INTERNAL_ERROR`) and is logged. It never falls back to the shared key [judgment: a silent fallback would reopen §5.1].

---

## 3. Binding SPs to tenants, and routing

### Keep `spId` globally unique [judgment, and the most important simplification]

`spId` is the key for everything the plugin stores [verified]:
- replay: `seenRequestKey(spId, requestId)` (src/storage/seen.ts:403–405);
- `sessionIndexOf(secret, sessionId, spId)` (storage/participants.ts:35);
- participant rows (schema.ts, `logoutSchema`);
- `ValidatedRequest.spId` in pending requests and continuations (sso.ts:243–253);
- audit rows (`samlIdpAuditEvent.spId`, schema.ts:248);
- `/init?sp=` (init.ts:351–352).

If `spId` stays unique across tenants, **none of these change**, and a request ID can't collide across tenants: two tenants' SPs are two different `spId`s.

### Entity-ID uniqueness becomes per tenant

The same SP entity ID really does appear in several tenants [judgment, well known]:
- AWS IAM SAML uses one audience (`urn:amazon:webservices`) for every AWS account;
- Google Workspace uses `google.com` unless a domain-specific issuer is chosen.

Today the registry refuses that: `entityId` has `unique: true` and a UNIQUE index (schema.ts:223, 232). Code SPs are deduplicated globally (options.ts:552–557), and `inCode(id, entityId)` compares entity IDs globally (sp-directory.ts:546–548).

**Schema, only when `tenants.enabled`:** add two columns to `samlIdpServiceProvider`:
- **`tenantId: string`, required.** Store `""` for root SPs, not `NULL`. In SQL, `NULL`s are distinct under UNIQUE, so a nullable composite key would let two root SPs share an entity ID [judgment, adversarial]. The column is indexed.
- **`lookupKey: string`, UNIQUE.** It holds `sha256b64url("saml-idp:sp\0" + tenantId + "\0" + entityId)`, the same pattern as the replay key (schema.ts:198–209). It needs a single-column UNIQUE index, which Better Auth, the MongoDB `indexes` workaround (schema.ts:205–208) and every adapter in the matrix already handle.

**The old `entityId` UNIQUE constraint can stay [judgment, compatibility]:**
- Better Auth's migrator adds columns but won't drop an existing constraint.
- A host that leaves it in place can't register the same entity ID in two tenants: the insert fails with a 409 conflict. That's the safe direction.
- Drop it by hand, with documented SQL, to allow shared entity IDs.
- New installs that enable tenants get the schema without it.

**Lookup:** `SpDirectory.byEntityId(adapter, tenantId, entityId, log)`.
- Code SPs are looked up by `(tenant, entityId)`.
- Stored SPs are looked up by `lookupKey`.
- The cache key includes the tenant (it is `${field}\0${value}` today, sp-directory.ts:592).
- After loading a stored row, **re-check that the row's `tenantId` equals the route's tenant**, as the exact-match rule already does against collation surprises (sp-directory.ts:598–600).
- `inCode` becomes per tenant.

**Routing rule [judgment, security]:** the tenant in the request path must equal the SP's tenant.
- The root routes (`/saml2/idp/sso`, `/saml2/idp/slo`) find **root SPs only**.
- A tenant SP reached through the root route is `UNKNOWN_SERVICE_PROVIDER`, never "found, then issued under the root identity".
- A test pins that.

**Paths that find the SP by `spId`, not by route:** resume, the POST continuation, `/init?sp=`, SLO hops and `finish()` (sso.ts:216, init.ts:352, slo.ts:116, 142, 221, 231).
- The tenant is derived from the SP.
- `ValidatedRequest` gains `tenantId`. On resume and continuation, a mismatch with the SP's current tenant fails the same way "SP changed" does (sso.ts:217). This is defence in depth, since the tenant is immutable.
- `/init?sp=` keeps its URL. The Response is issued under the SP's tenant identity.
- `Destination` checks use the tenant's SSO and SLO URLs (sso.ts:222, 233; slo.ts:79, 213).

### Who may sign in through a tenant

A tenant SP gets an **implied, mandatory membership rule**: `organization: { id: tenantOrgId }`. It's built on `matchOrganization` (organizations.ts:375–383) [verified: that function exists; the "implied" part is judgment].
- An explicit `organization` on a tenant SP must be `{ id: <the same org>, roles? }`. A slug, or a different org, is a config error. `roles` narrows who may sign in.
- **Membership can't be turned off in v1.** It is what "this org's IdP" means, and `authorize` / `registry.authorize` can only narrow it further.
- **Attributes come for free [verified]:** organization attributes without `only` already scope to "the SP's own organization when it has a rule" (src/attributes.ts:29–35). So a tenant SP never learns about the user's other organizations.
- **Fails closed** without the organization plugin, as today (issue.ts:206). With `tenants.enabled` and no organization plugin, startup fails with a `SamlIdpConfigError`.

### Persistent NameIDs must include the tenant [judgment, privacy bug if missed]

`defaultNameId` computes `HMAC(secret, "saml-idp:persistent\0" + sp.entityId + "\0" + user.id)` (issue.ts:160–163) [verified].
- With AWS registered in tenants A and B, a user who belongs to both gets the **same** persistent NameID at both. That lets the two tenants link the same person across organizations.
- **Fix:** for tenant SPs only, use `"saml-idp:persistent\0" + tenantId + "\0" + entityId + "\0" + userId`.
- Root SPs keep the old derivation, so existing persistent NameIDs don't change.
- Email NameIDs are the same across tenants by nature. Document that.

---

## 4. Backward compatibility

- **`tenants` absent or `enabled: false`** [judgment, to be pinned by tests]:
  - no new tables or columns: the schema is conditional, like `registry`, `sessionTracking` and `auditLog` (schema.ts:193–197);
  - no new routes;
  - metadata identical byte for byte (test);
  - persistent NameIDs unchanged (test);
  - the Issuer and key paths unchanged.
- **Enabling tenants on an existing registry:** additive columns (`tenantId` defaults to `""`, and `lookupKey` is backfilled). This needs a small migration script, or computing it lazily is also possible: rows whose `lookupKey` is null are read through the old `entityId` lookup until backfilled.
  - **Recommended:** a one-time backfill in the documented migration (D1 SQL plus an `npx better-auth-saml-idp` helper). No lazy dual path: it's simpler to review.
- The root IdP keeps working next to tenants: the same `entityId`, key and URLs. A host can move one customer at a time.
- **Public API:** everything is additive, so it's fine before or after 1.0 under D-040's rules:
  - `ServiceProviderInfo` gains `tenantId: string | null`;
  - `ServiceProviderRecord` gains `tenantId`;
  - events gain `tenantId`.
  - One nuance: `ServiceProviderInfo`'s exact keys are asserted in test/unit/public-api.test.ts (D-040 decision 1). Update that assertion deliberately.

---

## 5. Security

### 5.1 Cross-tenant confusion (the core threat)

- **Scenario:** tenant B's administrator registers, in tenant B, an SP with **tenant A's Salesforce entity ID and ACS**. That's legal once uniqueness is per tenant. They also add a static attribute `{ value: "victim@a.com" }`. Stored SPs can map constants and any user field [verified: attributes.ts:50–54; the `{ value }` source, options.ts:70].
  - The IdP issues an assertion to A's ACS, with `Audience` = A's SP entity ID and `Issuer` = B's entity ID.
- **With a shared key (Phase 1):**
  - The only thing that stops A's Salesforce is its check that `Issuer` equals A's IdP entity ID.
  - Salesforce does check it: Okta support's "The Issuer in the SAML response did not match the Issuer configured" error shows such checks exist.
  - **Not every SP does.** Some verify only the signature against the pinned certificate, and some multi-account SPs identify the user by attribute [judgment].
- **With per-tenant keys:** A's SP trusts only A's certificate. B's assertion fails signature validation at every SP that verifies signatures at all.

**Decision [judgment]:**
- (a) Phase 1 (shared key) **refuses delegated SP management**: only host administrators create tenant SPs, as today.
- (b) `tenants.delegation` is a **startup error unless `tenants.keys: "per-tenant"`**.
- (c) Even the host administrator gets a registry **warning** when a tenant SP's `(entityId, acsUrls)` overlaps an SP in another tenant under a shared key.

**IdP-side confusion:** a request for tenant B naming SP A's entity ID is looked up in B only (§3). A test covers each direction, and the root route.

### 5.2 Tenant enumeration through metadata URLs

- Metadata is public by design: it holds certificates and URLs. What enumeration reveals is **which organizations use SAML**, and their count, if organization ids are sequential. `advanced.database.generateId: "serial"` makes ids guessable [judgment].
- **Mitigations:**
  - only organizations with a **tenant row** are tenants. An organization without one, a disabled tenant and a nonexistent id all get the same 404 body and status;
  - metadata carries **no organization name or slug**: no `<Organization>` element, and a certificate CN of `saml-idp tenant <tenantKey>`, not the company name;
  - the optional random `tenantKey` (§1) for hosts with serial ids;
  - Better Auth's rate limiter covers the route.
- **Residual:** a timing difference between "cached tenant" and "database miss". Low value to an attacker. Document it.

### 5.3 Rotating each tenant's key

- Mirror the documented three steps (signing-and-encryption.md "Rotation"; D-019) per tenant, with key rows in states `next | active | retired`:
  1. `rotate` creates a **next** key. Metadata publishes it next to the active one (today's `additionalCertificates` slot).
  2. `activate` makes next the active key. The old one stays published as `previous`.
  3. `retire` removes the old certificate from metadata.
- Guards [judgment]:
  - activation is refused unless the next key has been published for at least `minPublishedSeconds` (default 24 h; the host can override it);
  - at most one active and one next key per tenant, enforced by a UNIQUE `(tenantId, state)` key for active/next (again via a hashed `lookupKey` column);
  - expiry warnings per tenant at 30 days, as for the root key.
- Blast radius: one tenant's key leaking affects only that tenant's SPs. Emergency rotation is `rotate` + `activate` with `force`, and it is audited.

### 5.4 The admin API

Today's rules [verified]:
- the registry manager check uses `sensitiveSessionMiddleware`;
- impersonation is refused and the user is re-read from the database;
- `permissions` (the admin plugin) and/or `canManage` decide (registry.ts:383–405).

**Phase 1:** unchanged. `canManage` gains an additive `tenantId` in its context.

**Phase 3 delegation**, `tenants.delegation: { roles: ["owner", "admin"] }`: a member holding one of those roles **in that organization** (re-read through `loadMemberships`, never from the session's `activeOrganizationId`) may manage SPs **of that tenant only**.

Rules to test, adversarially:
- **List** is filtered by `tenantId` in the query, not after fetching.
- **Get, update and delete** load the row and compare `row.tenantId`. Otherwise it's an IDOR, since `spId` is global.
- `tenantId` is **immutable** on update, like `id` (registry.ts:554–555).
- Delegated administrators can't create root SPs, or SPs in another tenant.
- They can't use **`metadata.url`** unless the host allows it. It is server-side fetching (D-026), and D-029 accepted "registry `metadata.url` can reach internal https hosts" only because the registry was *admin-only*. That acceptance doesn't survive delegation [judgment, SSRF].
- **Attribute and NameID fields are limited to an allow-list** (`tenants.delegation.userFields`, default `["email", "name", "id"]`). Without it, a tenant administrator could map any user column (the host's `role`, `banReason`, internal flags) into their SP and exfiltrate it for their members. Stored SPs can already map any field (attributes.ts:50–54); the host's own administrators were trusted with that.
- Tenant keys can't be read through the API: only certificates.
- **Tenant creation stays with host administrators** (or `auth.api` server-only). Otherwise any user who creates an organization gets an IdP. That is harmless with per-tenant keys and delegation, but it's the host's call.

### 5.5 The audit log

- Events gain `tenantId`. `samlIdpAuditEvent` gains an indexed `tenantId` column when tenants are enabled, so a later tenant-administrator audit view can filter in SQL.
- Anonymous refusals still aren't stored (D-038). Neither is an unknown tenant.
- Registry and key-rotation actions are audited too. Today registry changes only go to `logger.info` (registry.ts:484).

### 5.6 `session.ended` (D-043)

- There is one Better Auth session per user across tenants.
- Participants gain `tenantId`, derived from the SP at emission time (index.ts:144–146 already resolves `entityId` there).
- No behaviour change beyond that: the host routes the event per tenant.

### 5.7 Single Logout across tenants

**There is one IdP session, not one per tenant [judgment].** Better Auth users and sessions are global. A user in orgs A and B has one session, so logout from any SP ends it and must reach SPs in both tenants. The alternative, per-tenant sessions, needs Better Auth changes. Deferred.

Required changes [verified that each site is hard-wired today]:
- `nextHop` builds each LogoutRequest with **the participant SP's tenant** entity ID and key (slo.ts:122, 134–135; today `state.options.entityId` / `state.options.signing`).
- `finish` answers the originator with **the originator's tenant** identity (slo.ts:147, 155–156).
- The `Destination` of a participant's LogoutResponse is checked against the SLO URL of **that SP's tenant**, not the URL of the route it arrived on, since the hop state carries `spId` (slo.ts:229–236). Accept either URL form, but compare against the tenant's.
- An SP-initiated LogoutRequest at `/saml2/idp/slo/:tenant` looks up the SP in that tenant only (slo.ts:256).
- **Privacy [judgment]:** the chain is browser redirects. SP-A never sees SP-B's messages, and each SP only receives messages from its own tenant's issuer. The only cross-tenant signal is timing. Acceptable, and documented.

### 5.8 Refactor to make all of this checkable

Introduce `IdpIdentity { tenantId: string | null; entityId; signing (resolved); ssoUrl; sloUrl }`, returned by `identityFor(ctx, state, sp | tenantId)`.
- `buildSignedResponse`, `buildSignedErrorResponse`, `renderMetadata`, `buildLogoutRequest/Response`, `signedPostMessage` and `redirectBindingUrl` take the identity, **not `options`**.
- Then grep for `options.entityId` / `options.signing` outside `identityFor` in CI (a lint test). Any remaining hard-wired use is a cross-tenant bug. That's the cheapest structural guard.

---

## 6. API shape

### Options

```ts
samlIdp({
  entityId, signing, serviceProviders, registry, /* unchanged: the root IdP */
  tenants: {
    enabled: true,
    /** "shared" (Phase 1): tenants sign with `signing`. "per-tenant" (Phase 2): database keys. */
    keys: "shared" | "per-tenant",
    /** Default: Better Auth's secret(s). Encrypts tenant private keys (Phase 2). */
    keyEncryptionSecret?: string,
    /** Phase 3; startup error unless keys === "per-tenant". */
    delegation?: { roles: string[]; userFields?: string[]; allowMetadataUrl?: boolean },
    /** Rotation guard, default 86400. */
    minPublishedSeconds?: number,
    /** Freshness of tenant rows and keys across isolates; default registry.cacheSeconds ?? 60. */
    cacheSeconds?: number,
  },
});
```

- Tenant SPs in code: `serviceProviders[].tenant?: string` (an organization id). They are allowed with `keys: "shared"` or `"per-tenant"`. With `"per-tenant"`, the tenant row must exist when the plugin starts; if it doesn't, the SP is refused at issuance. Code can't read the database at `init`.
- Stored tenant SPs: `tenant` in the JSON config, copied into the `tenantId` column, as `id` and `entityId` are today (sp-directory.ts:582–586 cross-checks).
- **No `resolve` callback in v1** (§2, option C, deferred).
- **No per-tenant `entityId` override in v1.** It's derived from `baseURL` and `tenantKey`. The deferred reason: migrating a customer from another IdP while keeping its old entity ID is the only use case, and it lets a host give two tenants one entity ID. If it's added, it goes in the tenant row with a UNIQUE constraint.
- `baseURL` follows D-040 decision 6. Tenant URLs are `${resolvedBaseURL}/saml2/idp/{sso,slo,metadata}/${tenantKey}`. Without a pinned `baseURL`, tenant entity IDs would follow the Host header, so **`tenants.enabled` requires a pinned `baseURL`** (a startup error) [judgment]. Today there is only a warning (index.ts:92–95). An entity ID that varies with Host is unacceptable once it names a customer.

### Tables (all conditional on `tenants.enabled`)

- **`samlIdpTenant`:**
  - `organizationId` (UNIQUE);
  - `tenantKey` (UNIQUE, immutable, `[A-Za-z0-9_-]{1,64}`, default the org id);
  - `enabled`;
  - `createdAt`, `updatedAt`, `updatedBy`.
- **`samlIdpTenantKey`** (Phase 2):
  - `tenantId`, `kid`;
  - `state` (`next | active | previous | retired`);
  - `stateKey` (UNIQUE hash of `tenantId + state`, for `next` and `active` only; otherwise a random value);
  - `encryptedPrivateKey`, `certificate`, `notAfter`;
  - `createdAt`, `activatedAt`.
- **`samlIdpServiceProvider`:** gains `tenantId` (required, `""` for root, indexed) and `lookupKey` (UNIQUE). §3 covers the `entityId` UNIQUE constraint.
- **`samlIdpAuditEvent`:** gains `tenantId` (indexed), when the audit log is on too.
- The replay, participant and pending tables: **unchanged**.

### Registry API (`/saml-idp/*`, D-040 decision 2)

- **Service providers:**
  - `GET /saml-idp/service-providers?tenantId=` filters the list;
  - records carry `tenantId`;
  - create takes `serviceProvider.tenant`;
  - update refuses a change of tenant.
- **New tenant routes, all under the same manager check, with a new `samlTenant` access-control resource in `samlIdpStatements`:**
  - `GET /saml-idp/tenants`
  - `GET /saml-idp/tenants/get`
  - `POST /saml-idp/tenants/create`
  - `POST /saml-idp/tenants/update` (only `enabled`)
  - `POST /saml-idp/tenants/delete`, which refuses while SPs remain
  - Phase 2: `POST /saml-idp/tenants/keys/rotate`, `…/activate`, `…/retire`, and `GET …/keys` (certificates and states only).
- **Record shape:** one shape, per D-040 decision 5: `TenantRecord { organizationId, tenantKey, entityId, metadataUrl, ssoUrl, sloUrl, enabled, keys: [{ kid, state, certificate, notAfter }], createdAt, updatedAt, updatedBy }`.

### Client plugin

- `authClient.samlIdp.tenants.*` is inferred from the routes (D-040 decision 2).
- `launchUrl` / `launch` are unchanged: `/init?sp=` is by `spId`.
- `logoutUrl` / `signOutEverywhere` are unchanged: one session.

### Metadata endpoints

- `GET /saml2/idp/metadata` stays the root.
- `GET /saml2/idp/metadata/:tenantKey` serves tenant metadata:
  - a samlify IdP per `(tenant, kid-set)`, cached in a bounded LRU;
  - signed with the tenant's key when `signMetadata` is on;
  - `WantAuthnRequestsSigned` false, as with any registry (idp.ts:431–432);
  - `NameIDFormat` from that tenant's code SPs.
- A 404 for an unknown, disabled or keyless tenant: one identical body.
- `Cache-Control` as today (metadata.ts:77–78). The key-rotation `previous` state must stay published for longer than that `max-age`.

### CLI

- `inspect --tenant`, `smoke --tenant`, and `sp-from-metadata --tenant`.
- `keygen` can output a JSON blob ready to upload to a tenant.

---

## 7. Phasing

**Phase 1: tenant identities under a shared key (MVP).** The URLs and entity IDs SPs are configured with are final, so Phase 2 changes only which certificate SPs pin (a normal rotation).
- the `IdpIdentity` refactor (§5.8) and its lint test;
- tenant routes and metadata;
- the `samlIdpTenant` table and tenant API;
- per-tenant SP uniqueness (`tenantId`, `lookupKey`);
- scoped lookup plus the routing rule;
- the implied membership rule;
- tenant-scoped persistent NameIDs;
- SLO identity per participant;
- `tenantId` in events, audit and records;
- the pinned-`baseURL` requirement;
- host-administrator-only management.

**Phase 2: per-tenant keys.**
- the `samlIdpTenantKey` table;
- encrypted storage bound to its row;
- generation on the admin path (verified on workerd);
- the per-isolate key LRU;
- rotate, activate, retire with guards;
- expiry warnings;
- the documented migration path from `"shared"` to `"per-tenant"`, which is exactly the three-step rotation per tenant: publish the next key, wait for the SPs, then activate.

**Phase 3: delegated tenant administration.** Gated on `keys: "per-tenant"`:
- the role-based manager;
- the IDOR checks;
- the field allow-list;
- the `metadata.url` policy;
- a tenant-scoped audit read API.

**Deferred, with reasons:**
- the host callback / KMS for keys (no named host needs it);
- host-based tenants and custom domains (DNS, TLS and cookies);
- custom tenant entity IDs (migration only; needs uniqueness);
- per-tenant IdP sessions (needs Better Auth changes);
- per-tenant `authnContext` levels and login pages: the login page gets `tenant=<tenantKey>` in its query in Phase 1, so it can brand itself (additive to `loginRedirectUrl`, sso.ts:128–139), but nothing more;
- per-tenant back-channel SLO (deferred globally already, D-043).

---

## 8. Test plan

Both runtimes where the database is involved. The adapter matrix covers the new UNIQUE keys.

**Compatibility:**
- tenants off: metadata identical byte for byte to a saved fixture, persistent NameID unchanged, schema without the new tables and columns;
- the root IdP working next to tenants.

**Routing and isolation (the core):**
- the same SP entity ID in tenants A and B gets distinct Responses with the correct Issuer and key each;
- A's SP entity ID at B's route: `UNKNOWN_SERVICE_PROVIDER`;
- a tenant SP at the root route: refused;
- a root SP at a tenant route: refused;
- `Destination` of A's URL sent to B's route: refused;
- replay isolation: the same request ID at A and B both accepted (distinct `spId`), and a replay within A refused;
- resume or continuation whose SP changed tenant: refused.

**Membership:**
- a non-member refused;
- a member with the wrong role refused;
- a slug rule on a tenant SP refused at save time;
- a different-org rule refused;
- organization attributes scoped to the tenant (the user's other orgs absent);
- no organization plugin: startup error.

**NameIDs:** persistent differs across tenants for the same user and SP entity ID; root unchanged.

**SLO:**
- a user with SPs in A, B and root: logout from A reaches B with B's Issuer and a signature under B's key, and root with root's;
- the final LogoutResponse to A under A's identity;
- a participant's answer checked against its own tenant's SLO URL;
- `session.ended` carries `tenantId`.

**Metadata:**
- tenant metadata is XSD-valid, signed and unsigned;
- 404 identical for unknown, disabled and non-tenant organizations (body and status);
- no organization name in the document;
- published certificate sets across the rotation states.

**Keys (Phase 2):**
- round trip;
- **ciphertext swapped between tenant rows is refused** (the envelope binding);
- key-encryption rotation through Better Auth `secrets`;
- a bad key never falls back to the shared key;
- cache invalidation within `cacheSeconds` across two isolates (the D-027 pattern);
- keygen works on workerd;
- CPU measured live for a warm SSO request with a cached tenant key and with a cache miss.

**Admin API:**
- tenant CRUD and 404s;
- `tenantId` immutable;
- Phase 3: IDOR on get, update and delete across tenants, list filtered, root creation refused, disallowed fields refused, `metadata.url` refused, delegation without per-tenant keys a startup error, a demoted organization administrator losing access at once (authoritative read), impersonation refused.

**Structural:** the lint test that `options.entityId` / `options.signing` appear only in `identityFor`.

**Interop, live:**
- two tenants each with its own Salesforce Developer Edition org, or node-saml plus one live SP;
- the cross-tenant forgery attempt from §5.1 at a real SP, with per-tenant keys (must fail) and with a shared key (documents what the SP does).

**Mutation proof,** per the project's habit (D-040 onward), for:
- the scoped lookup;
- the routing rule;
- the implied membership;
- the tenant in the NameID;
- per-participant SLO identity;
- the envelope binding;
- the delegation gate;
- the IDOR checks.

**Effort estimate [judgment], at this project's demonstrated pace, including docs and D-entries:**

| Phase | Estimate |
|---|---|
| Phase 1 | about 4–6 working days. The refactor and SLO threading are most of it. |
| Phase 2 | about 4–6 days. The unknowns are keygen on workerd and the migration docs. |
| Phase 3 | about 3–5 days, plus an external review before release. |
| Total | roughly 2.5–3.5 weeks with reviews. |

The roadmap line says "Designed with a review before it is built" (README.md:87). Run a design review of this document, then a code review after Phase 1, and another after Phase 3.

---

## 9. Open questions for the maintainer

1. Tenant creation: host administrators only (recommended), or automatic for every organization?
2. Membership mandatory for tenant SPs (recommended), or does a real host need tenant SPs open to non-members?
3. `tenantKey`: the org id by default (recommended), or a random key by default to defeat enumeration on serial-id hosts?
4. Is anyone asking for KMS/HSM keys (option C)? If not, leave it deferred.

## Sources

- Okta, Beginner's Guide to SAML: https://support.okta.com/help/s/article/okta-saml?language=en_US
- Okta, Manage signing certificates: https://help.okta.com/en-us/content/topics/apps/manage-signing-certificates.htm
- Auth0, Configure Auth0 as SAML IdP: https://auth0.com/docs/authenticate/protocols/saml/saml-sso-integrations/configure-auth0-saml-identity-provider
- WorkOS, SAML integration: https://workos.com/docs/integrations/saml
- Keycloak Server Administration (realm keys): https://www.keycloak.org/docs/latest/server_admin/index.html
- Keycloak descriptor URL (third-party guide): https://www.itsfullofstars.de/2020/02/keycloak-download-saml-2-0-idp-metadata/
- authentik SAML provider: https://docs.goauthentik.io/add-secure-apps/providers/saml/
- Okta Issuer-mismatch error (SPs checking Issuer): https://support.okta.com/help/s/question/0D51Y00009Y1nyHSAR/

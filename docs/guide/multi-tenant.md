# Multi-tenant IdP

[Guide](README.md) › Multi-tenant IdP

Give each of your customers (a Better Auth organization) its own SAML identity: its own entity ID, metadata, and SSO and SLO URLs, next to the root IdP you already have. Their IT team configures their SPs (AWS, Google Workspace, Salesforce…) with *their* IdP, and only members of *their* organization can sign in through it.

This is [the multi-tenant design](../design/multi-tenant.md), phases 1 to 3 (DECISIONS.md D-052, D-058, D-059):
- per-organization identities;
- tenants sign with your one `signing` key (`keys: "shared"`, the default) or **each with its own key** (`keys: "per-tenant"`, [below](#per-tenant-signing-keys));
- **your** administrators create tenants, and with per-tenant keys, optionally, an **organization's own administrators manage its SPs** (`tenants.delegation`, [below](#delegated-administration)). [Why that needs per-tenant keys](#signing-keys-shared-or-per-tenant).

Tenancy is off unless you turn it on. With `tenants` unset, nothing changes: no tables, no columns, no routes, and every response is byte for byte what it was.

## Requirements

- Better Auth's **organization plugin**: tenants are organizations.
- **`registry.enabled`**: tenants and their SPs live in the database.
- A **pinned base URL**: `samlIdp({ baseURL })` or Better Auth's own `baseURL` (or `BETTER_AUTH_URL`). A tenant's entity ID is built from it and pinned by its SPs, so it must never follow a request's `Host` header.

Each one missing is a startup error (`SamlIdpConfigError`).

## Enable it

```ts
import { organization } from "better-auth/plugins";

betterAuth({
  baseURL: "https://auth.example.com",
  plugins: [
    organization(),
    samlIdp({
      entityId: "https://auth.example.com/api/auth/saml2/idp", // the root IdP, unchanged
      signing: { privateKey, certificate },
      loginPage: "/sign-in",
      serviceProviders: [],
      registry: { enabled: true, canManage: ({ user }) => user.role === "admin" },
      tenants: { enabled: true },
    }),
  ],
});
```

Then create the tables ([Database](#database)).

| `tenants` option | Default | What it does |
|---|---|---|
| `enabled` | **required** | Turns tenancy on. |
| `keys` | `"shared"` | What tenants sign with: `"shared"` (your `signing` key) or `"per-tenant"` (each tenant its own, [below](#per-tenant-signing-keys)). |
| `cacheSeconds` | `registry.cacheSeconds` (60) | How long each isolate caches a tenant, a miss, and a tenant's keys. 0 to 3600. A tenant disabled, or a key rotated, in one isolate is seen everywhere within this time. |
| `keyEncryptionSecret` | Better Auth's `secrets` / `secret` | With per-tenant keys: what seals tenants' private keys. At least 32 characters. |
| `minPublishedSeconds` | `86400` | With per-tenant keys: how long a next key must have been published before `activate` accepts it. 0 to 31536000. |

| `delegation` | off | With per-tenant keys: organizations' own administrators manage their tenant's SPs ([below](#delegated-administration)). A startup error with `keys: "shared"`. |

## Create a tenant

Only organizations you make tenants are tenants; nothing is created automatically. Through the registry API, as a user your `canManage` (or the admin plugin's `samlTenant` permission) allows:

```ts
await authClient.samlIdp.tenants.create({ organizationId: org.id });
// or, with a friendlier key in the URLs:
await authClient.samlIdp.tenants.create({ organizationId: org.id, tenantKey: "acme" });
```

The answer, like every tenant route's, is a `TenantRecord`:

```json
{
  "tenant": {
    "organizationId": "k3n…",
    "tenantKey": "acme",
    "entityId": "https://auth.example.com/api/auth/saml2/idp/metadata/acme",
    "metadataUrl": "https://auth.example.com/api/auth/saml2/idp/metadata/acme",
    "ssoUrl": "https://auth.example.com/api/auth/saml2/idp/sso/acme",
    "sloUrl": "https://auth.example.com/api/auth/saml2/idp/slo/acme",
    "enabled": true,
    "createdAt": "…", "updatedAt": "…", "updatedBy": "…"
  }
}
```

- **`tenantKey`** is the organization's id unless you choose one (1 to 64 of `A–Z a–z 0–9 _ -`, and not another organization's id). It is in the tenant's URLs and entity ID, which its SPs pin, so **it can't change** afterwards, and **it is never used again** once the tenant is deleted ([below](#deleting-tenants-and-organizations)). Never derive it from the organization's slug: slugs change, and a freed slug can be taken by another organization. With `generateId: "serial"`, organization ids are guessable; choose random keys if that matters to you ([Metadata](#metadata)).
- The **entity ID is the metadata URL** (as authentik does): self-describing, and built from nothing that can change.

| Route | What it does |
|---|---|
| `GET /saml-idp/tenants` | List (`authClient.samlIdp.tenants()`). |
| `GET /saml-idp/tenants/get?organizationId=` | One tenant. 404 `TENANT_NOT_FOUND`. |
| `POST /saml-idp/tenants/create` | `{ organizationId, tenantKey?, enabled? }`. 400 `INVALID_TENANT` for an unknown organization, a bad key or another organization's id as the key; 409 `TENANT_EXISTS` when the organization or key is taken; 409 `TENANT_KEY_RETIRED` when the key was a deleted tenant's. |
| `POST /saml-idp/tenants/update` | `{ organizationId, enabled }`: switch it off or on. Nothing else can change. |
| `POST /saml-idp/tenants/delete` | `{ organizationId }`. 409 `TENANT_HAS_SERVICE_PROVIDERS` while it has SPs, in code or stored. The key is retired. |

The routes are mounted with the SP registry API, under the same checks: a signed-in, non-impersonated user, re-read from the database, that `canManage` approves, and with `registry.permissions`, one whose role grants the action on **`samlTenant`** (add it to your access controller next to `samlServiceProvider`: [permissions](users-and-access.md#registry-permissions)). An organization's own owners and admins get nothing here.

A **disabled** tenant answers exactly like one that doesn't exist: its metadata is 404, its URLs find no SPs, and its SPs can't be signed in to by any route (IdP-initiated SSO included). They are skipped by Single Logout (reported `PartialLogout`). Nothing is ever issued for them under another identity.

### Deleting tenants and organizations

- **A deleted tenant's key is retired.** Its SPs may still trust its entity ID (the customer's IT team configured them), so no tenant, for any organization, may ever have that key again, not even the same organization's: create it again under a new key. Retired keys are kept in `samlIdpRetiredTenantKey` (409 `TENANT_KEY_RETIRED`). Two customers called Acme get `acme` and `acme-2`.
- **A tenant belongs to the organization it was made for**, not just to an organization id: it stores the organization's `createdAt`. When that organization is gone, or its id now belongs to another organization (with `generateId: "serial"`, SQLite and D1 give a freed id to the next row), the tenant answers like a disabled one, whatever its `enabled`, even if the organization was deleted straight from the database.
- **Deleting an organization through Better Auth** (`/organization/delete`) also disables its tenant, so the tenant list shows it. Its SPs and key stay until you remove them. To stop organization owners deleting an organization that is a tenant, refuse it in the organization plugin's `organizationHooks.beforeDeleteOrganization`.

## Add SPs to a tenant

An SP joins a tenant with `tenant`: the organization id.

```ts
// In code (the tenant must exist in the database for it to be used):
serviceProviders: [{ id: "acme-aws", entityId: "urn:amazon:webservices", acsUrls: ["https://signin.aws.amazon.com/saml"], tenant: acmeOrgId }],

// Or stored:
await authClient.samlIdp.serviceProviders.create({
  serviceProvider: { id: "acme-salesforce", entityId: "https://acme.my.salesforce.com", acsUrls: ["https://acme.my.salesforce.com"], tenant: acmeOrgId },
});
```

- The SP is found **only through its tenant's URLs**, and gets the tenant's identity in everything it's sent: the `Issuer`, the `Destination` it must use, the metadata.
- `spId` stays unique across all tenants; an **entity ID is unique per tenant**, so the same SP can be registered in several (AWS IAM's SAML federation uses `urn:amazon:webservices` for every customer; [see below](#the-same-sp-in-several-tenants)).
- A stored SP's `tenant` **can't change** (as its `id` can't): delete and re-create it. Creating one in an organization that isn't a tenant is refused.
- `GET /saml-idp/service-providers?tenantId=<organization id>` lists one tenant's SPs (`?tenantId=` alone: the root's). With tenants on, every record has `tenantId` (`null` for the root IdP).
- SPs without `tenant` belong to the root IdP, as before, and are found only through the root URLs.

### Only the organization's members

A tenant SP is for its organization's members, always: membership is implied, and can't be turned off. `organization` may only narrow it by role, and must name the same organization by id:

```ts
{ id: "acme-admin-console", …, tenant: acmeOrgId, organization: { id: acmeOrgId, roles: ["owner", "admin"] } }
```

A slug, or another organization, is refused at startup or when saving. `authorize` (and `registry.authorize`) can narrow further; they receive `serviceProvider.tenantId`.

Organization [attributes](users-and-access.md#attributes) without `only` cover the tenant's organization only, so a tenant's SP never learns about the user's other organizations.

## URLs

| | Root IdP | Tenant |
|---|---|---|
| Entity ID | your `entityId` | `<base>/saml2/idp/metadata/<tenantKey>` |
| Metadata | `<base>/saml2/idp/metadata` | `<base>/saml2/idp/metadata/<tenantKey>` |
| SSO (Redirect and POST) | `<base>/saml2/idp/sso` | `<base>/saml2/idp/sso/<tenantKey>` |
| SLO (with `singleLogout`) | `<base>/saml2/idp/slo` | `<base>/saml2/idp/slo/<tenantKey>` |
| IdP-initiated SSO | `<base>/saml2/idp/init?sp=<id>` | the same URL: the Response comes from the SP's tenant |

`<base>` is your pinned base URL (`https://auth.example.com/api/auth`). When a signed-out user is sent to your login page for a tenant's SP, the URL also carries `tenant=<tenantKey>`, so the page can show the organization's branding. It's informational: the tenant is bound to the stored request, not to that parameter.

## How tenants are kept apart

**The URL decides the identity.** A request at tenant B's SSO URL is looked up among tenant B's SPs only, whatever `Issuer` it names; the root URL finds root SPs only. So a request naming tenant A's SP at B's URL is `UNKNOWN_SERVICE_PROVIDER`, and nothing is issued under the wrong identity even for an SP that doesn't check the assertion's Issuer. In more detail:
- a stored SP is found by a key that hashes its tenant and entity ID, and the row found must belong to the URL's tenant;
- a request carries the tenant of the URL it came to, and issuance refuses it if the SP's tenant differs (an SP moved by editing the database, for example);
- a request's `Destination` must be the URL it arrived at, so one signed for tenant A's URL can't be replayed to B's;
- replay protection, SessionIndexes, logout participants and pending requests are keyed by the SP's id, which is unique across tenants.

## Signing keys: shared or per tenant

With `keys: "shared"` every tenant signs with your `signing` key. A tenant's SPs pin that certificate; what tells tenant A's assertions from tenant B's is only the `Issuer`.

That's why only **your** administrators manage tenant SPs. Suppose tenant B's administrator could register, in B, an SP with tenant A's Salesforce entity ID and ACS URL, mapping a constant attribute to a victim's email. The IdP would then issue, under B's identity, an assertion addressed to A's Salesforce. Salesforce checks the Issuer and refuses it; not every SP does. With a key per tenant, A's SP trusts only A's certificate, and B's assertion fails everywhere signatures are checked at all. So delegation needs per-tenant keys.

Your own administrators are warned when this situation arises by accident: an SP with the **same entity ID and an ACS URL** as an SP in another tenant (or the root) gets a warning in its registry record and the log, and code SPs one at startup. For SPs like AWS that's expected: check that the SP compares the assertion's Issuer with the IdP it was configured with, before relying on it.

## Per-tenant signing keys

```ts
samlIdp({
  // ...
  tenants: { enabled: true, keys: "per-tenant" },
});
```

Each tenant then signs its assertions, logout messages and (with `signMetadata`) its metadata with a key of its own, and its metadata publishes that key's certificate. The root IdP keeps your `signing` key.

- **A new tenant gets a key when it's created**: RSA 3072, with a two-year self-signed certificate named `saml-idp tenant <tenantKey>`. No SP trusts the tenant yet, so the key is active at once. The tenant record says `signing: "own"` and lists its keys.
- **A tenant made before** (with `keys: "shared"`) **keeps signing with the shared key** until you rotate its first own key in, as below. Its record says `signing: "shared"`. Its SPs keep working throughout: to them it's an ordinary certificate rotation.
- **Once a tenant has had a key of its own, nothing else ever signs for it.** A key that can't be loaded (a missing secret version, a damaged row, an activation cut short) makes its sign-ins fail with `INTERNAL_ERROR` and its metadata answer 500, and it is logged. It never falls back to the shared key.

### Rotating a tenant's key

The three steps of [key rotation](../key-rotation.md), per tenant, through the registry API (the manager, with `update` on `samlTenant`):

| Route | What it does |
|---|---|
| `GET /saml-idp/tenants/keys?organizationId=` | The tenant record with its keys: `kid`, `state`, `certificate`, `notAfter`, and for a next key `activatableAt`. Never private keys. |
| `POST /saml-idp/tenants/keys/rotate` | `{ organizationId, privateKey?, certificate? }`: a **next** key, generated or uploaded (an RSA key of at least 2048 bits and its certificate, e.g. from `npx better-auth-saml-idp keygen`). The tenant's metadata publishes it next to the active one. 409 `TENANT_SIGNING_KEY_EXISTS` while it has a next key already. |
| `POST /saml-idp/tenants/keys/activate` | `{ organizationId, force? }`: the next key signs from now on; the active one (for a tenant's first own key, the shared one) stays published as **previous**; an older previous is retired. 409 `TENANT_SIGNING_KEY_TOO_NEW` (with `activatableAt`) until the next key has been published for `minPublishedSeconds`. |
| `POST /saml-idp/tenants/keys/retire` | `{ organizationId }`: the previous key's certificate leaves the metadata, and its private key is erased. |

1. **Rotate.** Wait until the tenant's SPs have fetched the new metadata. SPs that refresh it (Cloudflare Access, Salesforce with a metadata URL) do it themselves; for the others the tenant's IT team uploads the new certificate. The wait defaults to 24 hours.
2. **Activate.** SPs that verify with either published certificate keep working.
3. **Retire** once no SP needs the old certificate any more.

`activate` with `force: true` skips the wait: for a key that has leaked. It's recorded as forced. Deleting a tenant deletes its keys.

Every change to a tenant or its keys is a `tenant.changed` event (`events.onTenantChanged`, and a row in the audit log with `auditLog.enabled`): `action` is `created`, `enabled`, `disabled`, `deleted`, `key.rotated`, `key.activated` (with `forced`) or `key.retired`, with the acting `userId` and, for keys, the `kid`.

### How keys are stored

In `samlIdpTenantKey`, one row per key, **encrypted** with Better Auth's secret (its versioned `secrets`, else `secret`) or `tenants.keyEncryptionSecret`, with XChaCha20-Poly1305 (Better Auth's `symmetricEncrypt`). The sealed text names its purpose, its tenant and its key id, and they must match the row: a key copied into another tenant's row, or anything else Better Auth encrypts with the same secret, is refused.

- **What it protects:** backups, dumps, read replicas and read-only database leaks. **Not** a compromised Worker or server: the secret is there too. It isn't an HSM.
- **Rotating the secret:** add a new version to Better Auth's `secrets` and keep the old ones. New keys are sealed with the current version; existing keys still open with theirs. Rotate each tenant's key to reseal it, then drop the old version. A tenant whose key's version is gone refuses to sign.
- **Caching:** each isolate keeps a tenant's keys for `cacheSeconds`, and a decrypted key by row. A rotation in one isolate is seen in the others within that time.
- **CPU:** generating a key (on `create` and `rotate` only, never on a sign-in) takes a few hundred milliseconds of CPU, more than the Workers Free plan allows a request; the [Workers guide](cloudflare-workers.md) already recommends Paid.

## Delegated administration

With per-tenant keys, you can let each customer's own administrators manage their tenant's SPs through the same registry API, without you:

```ts
tenants: {
  enabled: true,
  keys: "per-tenant",
  delegation: {}, // or { roles: ["owner", "admin"], userFields: ["email", "name", "id"], allowMetadataUrl: false }
},
```

| `delegation` option | Default | What it does |
|---|---|---|
| `roles` | `["owner", "admin"]` | The organization roles that manage the tenant's SPs. Better Auth's comma-separated multiple roles count. |
| `userFields` | `["email", "name", "id"]` | The only user fields a delegated SP may send, as attributes or as its NameID. Constants and organization attributes are fine. |
| `allowMetadataUrl` | `false` | Whether delegated SPs may use `metadata.url`: it makes your server fetch that URL. |

**Who counts.** A user who holds one of `roles` in an **enabled tenant's** organization. It's decided on every request from the database: the membership table (not the session's active organization), the user row (a ban counts) and the session (an impersonated one is refused). A demoted administrator loses access at the next request. Your own managers (`canManage`, `permissions`) are unaffected and still manage everything. With delegation alone (no `canManage`, no `permissions`) the registry API is mounted for tenants' administrators only.

**What a tenant's administrator can do**, through the [registry API](service-providers.md#registry-api):

| Route | For a tenant's administrator |
|---|---|
| `GET /saml-idp/service-providers` | Its tenant's SPs, filtered in the query. With several tenants, `?tenantId=` is required. Another tenant's, or the root's: 403. |
| `…/get`, `…/update`, `…/delete` | Its tenant's SPs only. Another tenant's SP, or the root's, is **404**, as if it didn't exist (`id` is global, so this is what stops one tenant reaching another's). |
| `…/create` | Only with `serviceProvider.tenant` one of its tenants (403 otherwise), and only allowed user fields and, unless allowed, no `metadata.url` (400 `INVALID_SERVICE_PROVIDER`, `issues` says which). An SP's tenant can't change afterwards, for anyone. |
| `GET /saml-idp/tenants/get`, `GET /saml-idp/tenants/keys` | Its own tenant only: URLs and certificates, never private keys. |
| `GET /saml-idp/audit` | Its tenant's events ([below](#events-and-the-audit-log)). |
| Everything else under `/saml-idp/tenants` | 403: creating, disabling and deleting tenants and managing their keys stay with you. |

**Why those limits.**
- **User fields:** without them, a tenant's administrator could map any column of your user table (your `role`, a ban reason, an internal flag) into an SP of theirs and read it for their members.
- **`metadata.url`:** your server fetches it (the certificate refresh), so it would let them make your server request URLs of their choosing.
- **Warnings:** a record shown to a tenant's administrator carries no warning about another tenant's SP. Your managers still see the [overlap warning](#signing-keys-shared-or-per-tenant).
- **An SP's `id` is global:** creating one with an `id` another tenant uses answers `SERVICE_PROVIDER_EXISTS`. That tells them the `id` is taken, and nothing about the SP.

Every change a tenant's administrator makes is a `service-provider.changed` event with `delegated: true`, in the audit log and `events.onServiceProviderChanged`.

## The same SP in several tenants

Entity IDs are unique per tenant, so AWS or Google Workspace can be registered once per customer. Each tenant's copy is a separate SP (its own `id`), gets its own tenant's identity, and each is found only through its own tenant's URLs.

**Databases that had the registry before tenants** keep the old `UNIQUE(entityId)`: Better Auth's migrator adds columns but never drops a constraint. That is the safe direction: registering an entity ID a second time, in any tenant, is refused (`409 SERVICE_PROVIDER_EXISTS`). To allow it, drop that constraint by hand (checked on Postgres 17, MySQL 8.4 and D1; the names are the ones Better Auth's migrator gives them):

```sql
-- Postgres
ALTER TABLE "samlIdpServiceProvider" DROP CONSTRAINT "samlIdpServiceProvider_entityId_key";
DROP INDEX saml_idp_service_provider_entity_id_unique;

-- MySQL
ALTER TABLE samlIdpServiceProvider DROP INDEX entityId, DROP INDEX saml_idp_service_provider_entity_id_unique;
```

```js
// MongoDB
db.samlIdpServiceProvider.dropIndex("saml_idp_service_provider_entity_id_unique");
```

SQLite and D1 can't drop a constraint: rebuild the table (after the [backfill](#database), since `lookup_key` becomes NOT NULL). With the example's column names:

```sql
CREATE TABLE saml_idp_service_providers_new (
  id TEXT PRIMARY KEY NOT NULL, sp_id TEXT NOT NULL UNIQUE, entity_id TEXT NOT NULL, config TEXT NOT NULL,
  enabled INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT,
  tenant_id TEXT NOT NULL DEFAULT '', lookup_key TEXT NOT NULL UNIQUE);
INSERT INTO saml_idp_service_providers_new (id, sp_id, entity_id, config, enabled, created_at, updated_at, updated_by, tenant_id, lookup_key)
  SELECT id, sp_id, entity_id, config, enabled, created_at, updated_at, updated_by, tenant_id, lookup_key FROM saml_idp_service_providers;
DROP TABLE saml_idp_service_providers;
ALTER TABLE saml_idp_service_providers_new RENAME TO saml_idp_service_providers;
CREATE INDEX saml_idp_service_providers_entity_idx ON saml_idp_service_providers (entity_id);
CREATE INDEX saml_idp_service_providers_tenant_idx ON saml_idp_service_providers (tenant_id);
```

New installs that enable tenants get the table without `UNIQUE(entityId)`.

## NameIDs

- **Persistent** NameIDs of tenant SPs include the tenant: a user who is a member of two tenants gets a different NameID at the same SP (AWS) in each, so the two customers can't link the person. Root SPs keep their derivation, so their existing NameIDs don't change.
- **Email** NameIDs are the email address, the same in every tenant by nature. Use persistent NameIDs where that matters.

## Single Logout across tenants

There is one IdP session per user, whatever the tenant: signing out from any SP ends it and reaches the SPs of every tenant the user signed in to in that session. Each SP is sent its LogoutRequest from **its own tenant's identity** (the one it got its assertion from), the originating SP is answered from its own, and a participant's LogoutResponse must be addressed to its own tenant's SLO URL (it may arrive at any SLO URL: the hop is found by its RelayState). A participant whose tenant was disabled since is skipped and the logout reported `PartialLogout`.

The chain is browser redirects: each SP sees only its own tenant's messages. What an SP could observe is timing, nothing else. A participant's answer is matched to the chain by its RelayState wherever it arrives, even at a tenant URL disabled since the chain started, so the rest of the chain goes on.

## Metadata

Each tenant's metadata is at its metadata URL: its entity ID, its SSO and SLO URLs, your signing certificate (and `additionalCertificates`), the NameID formats of its SPs in code, and `WantAuthnRequestsSigned="false"` (as with any registry). With `signMetadata`, it's signed with your key.

Metadata is public by design. What a stranger can learn from tenant URLs is which organizations have a tenant. To keep that small:
- an unknown key, a disabled tenant and an organization that isn't a tenant all get the **same 404** (same status, headers and body);
- the document carries **no organization name or slug**;
- choose random `tenantKey`s if your organization ids are sequential;
- Better Auth's rate limiter, when on, covers the route like any other.

A cached tenant answers slightly faster than a database miss; that timing difference remains.

## Events and the audit log

`assertion.issued`, `denied` and `logout` events carry `tenantId` when the SP belongs to a tenant (every refusal that names a tenant's SP), and so does each participant in `session.ended` (root IdP: absent, so root events are unchanged). The audit log gets a `tenantId` column (null for the root IdP), for filtering in SQL.

Changes are events too, in the audit log with who made them: `tenant.changed` (a tenant created, enabled, disabled or deleted, and its keys rotated, activated or retired) and `service-provider.changed` (a stored SP created, updated, enabled, disabled or deleted, `delegated` when a tenant's administrator did it).

`GET /saml-idp/audit?tenantId=` reads one tenant's events, filtered in the query. Your managers can read any tenant's, or the root's (`tenantId=`). A tenant's administrator can read only its own; the `tenantId` can be left out when it administers one tenant.

## Database

With `tenants.enabled` ([schema](schema.md#samlidptenant-with-tenantsenabled)):
- new tables, `samlIdpTenant` and `samlIdpRetiredTenantKey`, and with `keys: "per-tenant"` `samlIdpTenantKey` (its `stateKey` UNIQUE: at most one next and one active key per tenant);
- `samlIdpServiceProvider` gains `tenantId` (`""` for the root IdP, never NULL) and `lookupKey` (UNIQUE: a hash of tenant and entity ID), and its `entityId` is no longer UNIQUE on new installs;
- `samlIdpAuditEvent` gains `tenantId`, with `auditLog.enabled`.

**A new install**, or a registry with no rows yet: run your migration as usual (`npx auth migrate`, or your ORM's). On D1, see the example's migrations `0008_tenants.sql` and, for per-tenant keys, `0009_tenant_keys.sql`. Turning on per-tenant keys later only adds `samlIdpTenantKey`: run the migration again.

**A registry that already has rows** needs four steps, because `lookupKey` is required (so its UNIQUE index exists on every database, MongoDB included) and existing rows have none yet:

1. Add the column **nullable**, by hand. Better Auth's migrator refuses to add a required column to a table with rows.
   ```sql
   ALTER TABLE "samlIdpServiceProvider" ADD COLUMN "lookupKey" text;             -- Postgres
   ALTER TABLE samlIdpServiceProvider ADD COLUMN lookupKey varchar(255) NULL;   -- MySQL
   ALTER TABLE samlIdpServiceProvider ADD COLUMN lookupKey TEXT;                -- SQLite
   ```
2. Run the migration (with `tenants.enabled`). It adds `tenantId` (default `""`), the UNIQUE index on `lookupKey`, the tenant table and the audit column.
3. Fill in the keys, once, from your server (a script or a deploy step; the endpoint has no URL):
   ```ts
   const { updated, skipped } = await auth.api.samlIdpBackfillServiceProviderKeys();
   ```
   Each row's key is computed from its own config. `skipped` lists rows whose config isn't readable JSON, and `failed` rows whose write failed (logged; the other rows are still done): check both are empty. Running it again changes nothing.
4. Make it NOT NULL (Postgres: `ALTER TABLE "samlIdpServiceProvider" ALTER COLUMN "lookupKey" SET NOT NULL`; MySQL: `ALTER TABLE samlIdpServiceProvider MODIFY lookupKey varchar(255) NOT NULL`). SQLite can't; Better Auth then logs that the column "stays nullable", which is harmless once every row has a key.

Until step 3, **existing stored SPs aren't found** (sign-in to them fails with `UNKNOWN_SERVICE_PROVIDER`), and their registry records say "no lookupKey yet". Do steps 1 to 3 in one go. The key can't be computed in SQL: it's a SHA-256 over text containing a NUL separator, which Postgres text can't hold and SQLite can't hash. To let one entity ID into several tenants, drop the old `UNIQUE(entityId)` ([above](#the-same-sp-in-several-tenants)) **after** step 3, not before: until then, an SP created at the root with an old SP's entity ID would take the key that old row needs, and its backfill would fail.

**MongoDB** has no column to add (step 1) or constrain (step 4), and step 3 is different. Better Auth's MongoDB adapter builds a collection's indexes before its first write, and the UNIQUE index on `lookupKey` can't be built while two or more documents lack the key; so the endpoint above can't write there. Instead, **before** turning tenants on, run once with the `Db` you give `mongodbAdapter`:

```ts
import { backfillMongoServiceProviderKeys } from "better-auth-saml-idp";

const { updated, skipped, failed } = await backfillMongoServiceProviderKeys(db);
// with usePlural or a renamed model: backfillMongoServiceProviderKeys(db, { collection: "samlIdpServiceProviders" })
```

It writes the same keys through the driver. Then turn tenants on: the index is built on the first write. If tenants are already on, run it anyway (restart afterwards, or wait `registry.cacheSeconds`): the index is built on the next write, and `samlIdpBackfillServiceProviderKeys()` reports the rows it couldn't write in `failed` until then. The whole path, with two stored SPs, is checked on MongoDB 8.2 in CI.

**Turning tenants off again** isn't supported once tenant SPs exist: with tenants off, a stored lookup goes by entity ID alone and can land on a tenant's row, which is then refused (its `tenant` needs tenants on), so a root SP with the same entity ID stops working. It fails closed.

## Not in this version

| | Why not yet |
|---|---|
| Tenant keys held outside the database (a KMS, an HSM, Secrets Store) | Deferred until a host needs it: a callback that returns a tenant's signing configuration. |
| A tenant entity ID of your choosing | Only useful to migrate a customer from another IdP; it would need its own uniqueness guarantees. |
| Tenants by host name (`acme.idp.example.com`) | DNS, TLS and cookies per host. |
| A separate IdP session per tenant | Better Auth sessions are per user. |

# Multi-tenant IdP

[Guide](README.md) › Multi-tenant IdP

Give each of your customers (a Better Auth organization) its own SAML identity: its own entity ID, metadata, and SSO and SLO URLs, next to the root IdP you already have. Their IT team configures their SPs (AWS, Google Workspace, Salesforce…) with *their* IdP, and only members of *their* organization can sign in through it.

This is **phase 1** of the design in [multi-tenant-design.md](../review/multi-tenant-design.md) (DECISIONS.md D-052):
- **In this version:** per-organization identities; **every tenant signs with your one `signing` key**; only **your** administrators create tenants and manage their SPs.
- **Not yet:** a signing key per tenant (phase 2), and letting an organization's own administrators manage their SPs (phase 3, which needs per-tenant keys). [Why the order matters](#the-shared-signing-key).

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
| `keys` | `"shared"` | What tenants sign with. Only `"shared"` exists in this version. `"per-tenant"` is a startup error until phase 2. |
| `cacheSeconds` | `registry.cacheSeconds` (60) | How long each isolate caches a tenant, and a miss. 0 to 3600. A tenant disabled in one isolate is disabled everywhere within this time. |

`tenants.delegation` (organization administrators managing their own SPs) is refused at startup: it needs per-tenant keys.

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

- **`tenantKey`** is the organization's id unless you choose one (1 to 64 of `A–Z a–z 0–9 _ -`). It is in the tenant's URLs and entity ID, which its SPs pin, so **it can't change** afterwards. Never derive it from the organization's slug: slugs change, and a freed slug can be taken by another organization. With `generateId: "serial"`, organization ids are guessable; choose random keys if that matters to you ([Metadata](#metadata)).
- The **entity ID is the metadata URL** (as authentik does): self-describing, and built from nothing that can change.

| Route | What it does |
|---|---|
| `GET /saml-idp/tenants` | List (`authClient.samlIdp.tenants()`). |
| `GET /saml-idp/tenants/get?organizationId=` | One tenant. 404 `TENANT_NOT_FOUND`. |
| `POST /saml-idp/tenants/create` | `{ organizationId, tenantKey?, enabled? }`. 400 `INVALID_TENANT` for an unknown organization or a bad key; 409 `TENANT_EXISTS` when the organization or key is taken. |
| `POST /saml-idp/tenants/update` | `{ organizationId, enabled }`: switch it off or on. Nothing else can change. |
| `POST /saml-idp/tenants/delete` | `{ organizationId }`. 409 `TENANT_HAS_SERVICE_PROVIDERS` while it has SPs, in code or stored. |

The routes are mounted with the SP registry API, under the same checks: a signed-in, non-impersonated user, re-read from the database, that `canManage` approves, and with `registry.permissions`, one whose role grants the action on **`samlTenant`** (add it to your access controller next to `samlServiceProvider`: [permissions](users-and-access.md#registry-permissions)). An organization's own owners and admins get nothing here.

A **disabled** tenant answers exactly like one that doesn't exist: its metadata is 404, its URLs find no SPs, and its SPs can't be signed in to by any route (IdP-initiated SSO included). They are skipped by Single Logout (reported `PartialLogout`). Nothing is ever issued for them under another identity.

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
- `spId` stays unique across all tenants; an **entity ID is unique per tenant**, so the same SP can be registered in several (AWS uses `urn:amazon:webservices` for every customer; [see below](#the-same-sp-in-several-tenants)).
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

## The shared signing key

In this version every tenant signs with your `signing` key. A tenant's SPs pin that certificate; what tells tenant A's assertions from tenant B's is only the `Issuer`.

That's why only **your** administrators manage tenant SPs for now. Suppose tenant B's administrator could register, in B, an SP with tenant A's Salesforce entity ID and ACS URL, mapping a constant attribute to a victim's email. The IdP would then issue, under B's identity, an assertion addressed to A's Salesforce. Salesforce checks the Issuer and refuses it; not every SP does. With a key per tenant (phase 2), A's SP trusts only A's certificate, and B's assertion fails everywhere signatures are checked at all. So delegation waits for per-tenant keys, and `tenants.delegation` is a startup error until then.

Your own administrators are warned when this situation arises by accident: an SP with the **same entity ID and an ACS URL** as an SP in another tenant (or the root) gets a warning in its registry record and the log, and code SPs one at startup. For SPs like AWS that's expected: check that the SP compares the assertion's Issuer with the IdP it was configured with, before relying on it.

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

The chain is browser redirects: each SP sees only its own tenant's messages. What an SP could observe is timing, nothing else.

## Metadata

Each tenant's metadata is at its metadata URL: its entity ID, its SSO and SLO URLs, your signing certificate (and `additionalCertificates`), the NameID formats of its SPs in code, and `WantAuthnRequestsSigned="false"` (as with any registry). With `signMetadata`, it's signed with your key.

Metadata is public by design. What a stranger can learn from tenant URLs is which organizations have a tenant. To keep that small:
- an unknown key, a disabled tenant and an organization that isn't a tenant all get the **same 404** (same status, headers and body);
- the document carries **no organization name or slug**;
- choose random `tenantKey`s if your organization ids are sequential;
- Better Auth's rate limiter, when on, covers the route like any other.

A cached tenant answers slightly faster than a database miss; that timing difference remains.

## Events and the audit log

`assertion.issued`, `denied` and `logout` events carry `tenantId` when the SP belongs to a tenant, and so does each participant in `session.ended` (root IdP: absent, so root events are unchanged). The audit log gets a `tenantId` column (null for the root IdP), for filtering in SQL.

## Database

With `tenants.enabled` ([schema](schema.md#samlidptenant-with-tenantsenabled)):
- a new table, `samlIdpTenant`;
- `samlIdpServiceProvider` gains `tenantId` (`""` for the root IdP, never NULL) and `lookupKey` (UNIQUE: a hash of tenant and entity ID), and its `entityId` is no longer UNIQUE on new installs;
- `samlIdpAuditEvent` gains `tenantId`, with `auditLog.enabled`.

**A new install**, or a registry with no rows yet: run your migration as usual (`npx auth migrate`, or your ORM's). On D1, see the example's migration `0008_tenants.sql`.

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
   Each row's key is computed from its own config. `skipped` lists rows whose config isn't readable JSON. Running it again changes nothing.
4. Make it NOT NULL (Postgres: `ALTER TABLE "samlIdpServiceProvider" ALTER COLUMN "lookupKey" SET NOT NULL`; MySQL: `ALTER TABLE samlIdpServiceProvider MODIFY lookupKey varchar(255) NOT NULL`). SQLite can't; Better Auth then logs that the column "stays nullable", which is harmless once every row has a key.

Until step 3, **existing stored SPs aren't found** (sign-in to them fails with `UNKNOWN_SERVICE_PROVIDER`), and their registry records say "no lookupKey yet". Do steps 1 to 3 in one go. The key can't be computed in SQL: it's a SHA-256 over text containing a NUL separator, which Postgres text can't hold and SQLite can't hash.

On MongoDB there is no column to add (step 1) or constrain (step 4); run step 3 before the UNIQUE index on `lookupKey` is created, since a unique index can't be built while several documents lack the key. (The upgrade steps were checked on Postgres 17, MySQL 8.4 and SQLite, not on a populated MongoDB collection.)

## Not in this version

| | Why not yet |
|---|---|
| A signing key per tenant | Phase 2: encrypted keys in the database, rotated per tenant. SPs keep their URLs and entity IDs: moving to it is an ordinary key rotation for them. |
| Organization administrators managing their SPs | Phase 3; needs per-tenant keys ([above](#the-shared-signing-key)). |
| `--tenant` in the CLI (`inspect`, `smoke`, `sp-from-metadata`) | Not built yet. |
| A tenant entity ID of your choosing | Only useful to migrate a customer from another IdP; it would need its own uniqueness guarantees. |
| Tenants by host name (`acme.idp.example.com`) | DNS, TLS and cookies per host. |
| A separate IdP session per tenant | Better Auth sessions are per user. |

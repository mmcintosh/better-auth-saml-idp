-- Multi-tenant IdP (tenants.enabled; DECISIONS.md D-052, docs/guide/multi-tenant.md). Additive:
-- with tenants off (this example's default) the plugin ignores these, and nothing changes.
-- Turning tenants on also needs Better Auth's organization plugin and its tables, which this
-- example doesn't use.

-- Tenants: organizations with their own IdP identity.
CREATE TABLE IF NOT EXISTS saml_idp_tenants (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL UNIQUE,
  tenant_key TEXT NOT NULL UNIQUE,
  -- The organization's created_at when the tenant was made: binds the tenant to that organization,
  -- not just to an id that may be handed out again (DECISIONS.md D-053).
  organization_created_at INTEGER NOT NULL,
  enabled INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT
);

-- Keys of deleted tenants, never used again: SPs set up for a deleted tenant still trust its
-- entity ID (DECISIONS.md D-053).
CREATE TABLE IF NOT EXISTS saml_idp_retired_tenant_keys (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_key TEXT NOT NULL UNIQUE,
  organization_id TEXT NOT NULL,
  retired_at INTEGER NOT NULL,
  retired_by TEXT
);

-- Stored SPs: their tenant ('' for the root IdP) and the per-tenant UNIQUE lookup key. Rows saved
-- before have no key: once tenants are on, call auth.api.samlIdpBackfillServiceProviderKeys()
-- once, or they aren't found. entity_id keeps its UNIQUE constraint (one entity ID in one tenant
-- only: the safe direction); the guide has the table rebuild that drops it.
ALTER TABLE saml_idp_service_providers ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE saml_idp_service_providers ADD COLUMN lookup_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS saml_idp_service_providers_lookup_key_uq ON saml_idp_service_providers (lookup_key);
CREATE INDEX IF NOT EXISTS saml_idp_service_providers_tenant_idx ON saml_idp_service_providers (tenant_id);

-- The audit log: each event's tenant (NULL for the root IdP).
ALTER TABLE saml_idp_audit_events ADD COLUMN tenant_id TEXT;
CREATE INDEX IF NOT EXISTS saml_idp_audit_events_tenant_idx ON saml_idp_audit_events (tenant_id);

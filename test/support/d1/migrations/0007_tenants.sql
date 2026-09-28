-- Multi-tenant IdP (tenants.enabled; DECISIONS.md D-052). Additive: nothing here changes what the
-- plugin does with tenants off.
--
-- The organization plugin's tables, so tenant tests run on workerd too (tenants are organizations).
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  logo TEXT,
  created_at INTEGER NOT NULL,
  metadata TEXT
);
CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS members_organization_idx ON members (organization_id);
CREATE INDEX IF NOT EXISTS members_user_idx ON members (user_id);
CREATE TABLE IF NOT EXISTS invitations (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT,
  status TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  inviter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
ALTER TABLE sessions ADD COLUMN active_organization_id TEXT;

-- Tenants: organizations with their own IdP identity.
CREATE TABLE IF NOT EXISTS saml_idp_tenants (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL UNIQUE,
  tenant_key TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT
);

-- Stored SPs: their tenant ('' for the root IdP) and the per-tenant UNIQUE lookup key. The key is
-- NULL on rows saved before; auth.api.samlIdpBackfillServiceProviderKeys() fills it in.
-- entity_id keeps its UNIQUE constraint here (the tenants-off tests rely on it), so one entity ID
-- can't be in two tenants in this database: the safe direction. tenants-shared-entity.test.ts
-- applies the guide's table rebuild to drop it.
ALTER TABLE saml_idp_service_providers ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE saml_idp_service_providers ADD COLUMN lookup_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS saml_idp_service_providers_lookup_key_uq ON saml_idp_service_providers (lookup_key);
CREATE INDEX IF NOT EXISTS saml_idp_service_providers_tenant_idx ON saml_idp_service_providers (tenant_id);

-- The audit log: each event's tenant (NULL for the root IdP).
ALTER TABLE saml_idp_audit_events ADD COLUMN tenant_id TEXT;
CREATE INDEX IF NOT EXISTS saml_idp_audit_events_tenant_idx ON saml_idp_audit_events (tenant_id);

-- Better Auth's organization plugin (tenants are organizations; docs/guide/multi-tenant.md). This
-- example turns tenants on with per-tenant signing keys (0008, 0009), which need these tables.
--
-- A registry that already has stored SPs from before tenants: run the backfill once after this
-- migration, or those SPs aren't found (README, "Tenants").
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

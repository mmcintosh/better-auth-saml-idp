-- better-auth-scim-provisioning (optional: only needed with a provisioning target configured; see
-- the README's Provisioning section). The outbox (one job per target and user or group), the
-- user links (each user's id at each target) and the group links.
CREATE TABLE IF NOT EXISTS scim_provisioning_jobs (
  id TEXT PRIMARY KEY NOT NULL,
  key TEXT NOT NULL UNIQUE,
  target_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  attempts INTEGER NOT NULL,
  next_attempt_at INTEGER NOT NULL,
  locked_until INTEGER NOT NULL,
  failed INTEGER NOT NULL,
  last_error TEXT,
  last_status INTEGER,
  kind TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scim_provisioning_jobs_user_idx ON scim_provisioning_jobs (user_id);
CREATE INDEX IF NOT EXISTS scim_provisioning_jobs_next_idx ON scim_provisioning_jobs (next_attempt_at);
CREATE TABLE IF NOT EXISTS scim_provisioning_links (
  id TEXT PRIMARY KEY NOT NULL,
  key TEXT NOT NULL UNIQUE,
  target_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  remote_id TEXT NOT NULL,
  user_name TEXT NOT NULL,
  external_id TEXT,
  active INTEGER NOT NULL,
  synced_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scim_provisioning_links_target_idx ON scim_provisioning_links (target_id);
CREATE INDEX IF NOT EXISTS scim_provisioning_links_user_idx ON scim_provisioning_links (user_id);
CREATE INDEX IF NOT EXISTS scim_provisioning_links_remote_idx ON scim_provisioning_links (remote_id);
CREATE TABLE IF NOT EXISTS scim_provisioning_group_links (
  id TEXT PRIMARY KEY NOT NULL,
  key TEXT NOT NULL UNIQUE,
  target_id TEXT NOT NULL,
  organization_id TEXT NOT NULL,
  remote_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  synced_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scim_provisioning_group_links_target_idx ON scim_provisioning_group_links (target_id);
CREATE INDEX IF NOT EXISTS scim_provisioning_group_links_remote_idx ON scim_provisioning_group_links (remote_id);

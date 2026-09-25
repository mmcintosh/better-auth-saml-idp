-- Database-backed SP registry (registry.enabled; DECISIONS.md D-027).
CREATE TABLE IF NOT EXISTS saml_idp_service_providers (
  id TEXT PRIMARY KEY NOT NULL,
  sp_id TEXT NOT NULL UNIQUE,
  entity_id TEXT NOT NULL UNIQUE,
  config TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT
);

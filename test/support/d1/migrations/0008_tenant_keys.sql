-- Per-tenant signing keys (tenants.keys: "per-tenant"; DECISIONS.md D-058). Additive: without
-- per-tenant keys the plugin ignores this table. One row per key; state is next | active |
-- previous | retired. state_key is UNIQUE: a hash of (tenant_id, state) for next and active, so a
-- tenant never has two of either. encrypted_private_key is sealed with Better Auth's secret and
-- bound to its tenant and kid; it is emptied when the key is retired.
CREATE TABLE IF NOT EXISTS saml_idp_tenant_keys (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  kid TEXT NOT NULL,
  state TEXT NOT NULL,
  state_key TEXT NOT NULL UNIQUE,
  encrypted_private_key TEXT NOT NULL,
  certificate TEXT NOT NULL,
  not_after INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  activated_at INTEGER,
  updated_by TEXT
);
CREATE INDEX IF NOT EXISTS saml_idp_tenant_keys_tenant_idx ON saml_idp_tenant_keys (tenant_id);

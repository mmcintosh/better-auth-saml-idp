-- Audit log (auditLog.enabled; DECISIONS.md D-038). Rows expire after auditLog.retentionDays.
CREATE TABLE IF NOT EXISTS saml_idp_audit_events (
  id TEXT PRIMARY KEY NOT NULL,
  type TEXT NOT NULL,
  at INTEGER NOT NULL,
  sp_id TEXT,
  user_id TEXT,
  code TEXT,
  ip_address TEXT,
  user_agent TEXT,
  details TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS saml_idp_audit_events_at_idx ON saml_idp_audit_events (at);
CREATE INDEX IF NOT EXISTS saml_idp_audit_events_type_idx ON saml_idp_audit_events (type);
CREATE INDEX IF NOT EXISTS saml_idp_audit_events_sp_idx ON saml_idp_audit_events (sp_id);
CREATE INDEX IF NOT EXISTS saml_idp_audit_events_user_idx ON saml_idp_audit_events (user_id);
CREATE INDEX IF NOT EXISTS saml_idp_audit_events_expires_idx ON saml_idp_audit_events (expires_at);

-- Single Logout participants (singleLogout.enabled; DECISIONS.md D-028).
CREATE TABLE IF NOT EXISTS saml_idp_session_participants (
  id TEXT PRIMARY KEY NOT NULL,
  key TEXT NOT NULL UNIQUE,
  session_key TEXT NOT NULL,
  sp_id TEXT NOT NULL,
  name_id TEXT NOT NULL,
  name_id_format TEXT NOT NULL,
  session_index TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS saml_idp_session_participants_session_idx ON saml_idp_session_participants (session_key);
CREATE INDEX IF NOT EXISTS saml_idp_session_participants_expires_idx ON saml_idp_session_participants (expires_at);

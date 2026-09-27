-- Session participants gain userId and endedAt (events.onSessionEnded; DECISIONS.md D-043).
-- Existing rows keep NULLs: they were recorded before the upgrade and simply have no user id.
ALTER TABLE saml_idp_session_participants ADD COLUMN user_id TEXT;
ALTER TABLE saml_idp_session_participants ADD COLUMN ended_at INTEGER;
CREATE INDEX IF NOT EXISTS saml_idp_session_participants_user_idx ON saml_idp_session_participants (user_id);

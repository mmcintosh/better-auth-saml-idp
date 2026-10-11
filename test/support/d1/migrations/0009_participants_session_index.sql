-- Logout finds a session by its SessionIndex without its cookie (DECISIONS.md D-076).
CREATE INDEX IF NOT EXISTS saml_idp_session_participants_session_index_idx ON saml_idp_session_participants (session_index);

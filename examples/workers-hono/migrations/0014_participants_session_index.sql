-- Logout finds a session by its SessionIndex when the LogoutRequest comes without the session's
-- cookie, as Microsoft 365's does (from a hidden iframe; DECISIONS.md D-076). Index it.
CREATE INDEX IF NOT EXISTS saml_idp_session_participants_session_index_idx ON saml_idp_session_participants (session_index);

-- saml-idp: replay protection keys on a UNIQUE `key` column (hash of sp_id + request_id)
-- instead of a forced primary key, so it works with any Better Auth `generateId` strategy.
-- The table only holds short-lived replay markers (≈6 min), so it is recreated.
DROP TABLE IF EXISTS saml_idp_seen_requests;
CREATE TABLE saml_idp_seen_requests (
  id TEXT PRIMARY KEY NOT NULL,
  key TEXT NOT NULL UNIQUE,
  sp_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX saml_idp_seen_requests_sp_request_uq ON saml_idp_seen_requests (sp_id, request_id);
CREATE INDEX saml_idp_seen_requests_expires_idx ON saml_idp_seen_requests (expires_at);

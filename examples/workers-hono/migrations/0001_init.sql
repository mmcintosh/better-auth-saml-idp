-- D1 test host schema; must match test/support/d1/schema.ts.
CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  email_verified INTEGER DEFAULT 0 NOT NULL,
  image TEXT,
  created_at INTEGER DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)) NOT NULL,
  updated_at INTEGER DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)) NOT NULL,
  role TEXT,
  banned INTEGER DEFAULT 0,
  ban_reason TEXT,
  ban_expires INTEGER
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY NOT NULL,
  expires_at INTEGER NOT NULL,
  token TEXT NOT NULL UNIQUE,
  created_at INTEGER DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)) NOT NULL,
  updated_at INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  timezone TEXT, city TEXT, country TEXT, region TEXT, region_code TEXT, colo TEXT, latitude TEXT, longitude TEXT,
  impersonated_by TEXT
);
CREATE INDEX sessions_userId_idx ON sessions (user_id);
CREATE TABLE accounts (
  id TEXT PRIMARY KEY NOT NULL,
  account_id TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access_token TEXT, refresh_token TEXT, id_token TEXT,
  access_token_expires_at INTEGER, refresh_token_expires_at INTEGER,
  scope TEXT, password TEXT,
  created_at INTEGER DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)) NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX accounts_userId_idx ON accounts (user_id);
CREATE TABLE verifications (
  id TEXT PRIMARY KEY NOT NULL,
  identifier TEXT NOT NULL,
  value TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)) NOT NULL,
  updated_at INTEGER DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)) NOT NULL
);
CREATE INDEX verifications_identifier_idx ON verifications (identifier);
CREATE TABLE rate_limits (
  id TEXT PRIMARY KEY NOT NULL,
  key TEXT NOT NULL UNIQUE,
  count INTEGER NOT NULL,
  last_request INTEGER NOT NULL
);
CREATE TABLE saml_idp_seen_requests (
  id TEXT PRIMARY KEY NOT NULL,
  sp_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX saml_idp_seen_requests_sp_request_uq ON saml_idp_seen_requests (sp_id, request_id);
CREATE INDEX saml_idp_seen_requests_expires_idx ON saml_idp_seen_requests (expires_at);

-- Two-step sign-in (Better Auth's twoFactor plugin: a password plus an authenticator-app code).
-- A user turns it on from the home page. The IdP then asserts the stronger authentication class
-- for that user's sessions (authnContext in src/auth.ts), which Microsoft 365 reads as MFA.
ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0;
CREATE TABLE IF NOT EXISTS two_factors (
  id TEXT PRIMARY KEY NOT NULL,
  secret TEXT NOT NULL,
  backup_codes TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  verified INTEGER DEFAULT 1,
  failed_verification_count INTEGER DEFAULT 0,
  locked_until INTEGER
);
CREATE INDEX IF NOT EXISTS two_factors_secret_idx ON two_factors (secret);
CREATE INDEX IF NOT EXISTS two_factors_user_id_idx ON two_factors (user_id);

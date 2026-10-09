-- Passkeys (Better Auth's passkey plugin), and how each session was signed in.
-- auth_method is set when a session is created (authMethodOf in src/auth.ts): password, totp,
-- backup-code, passkey or impersonation. The SAML plugin asserts Microsoft's MFA class only for
-- totp, backup-code and passkey sessions; older sessions (NULL) count as password.
ALTER TABLE sessions ADD COLUMN auth_method TEXT;
CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT,
  public_key TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL,
  counter INTEGER NOT NULL,
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL,
  transports TEXT,
  created_at INTEGER,
  aaguid TEXT
);
CREATE INDEX IF NOT EXISTS passkeys_user_id_idx ON passkeys (user_id);
CREATE INDEX IF NOT EXISTS passkeys_credential_id_idx ON passkeys (credential_id);

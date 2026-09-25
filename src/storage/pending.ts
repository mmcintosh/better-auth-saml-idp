
/**
 * Pending AuthnRequests (ADDENDUM-01 R1): Better Auth verification values, written with
 * `createVerificationValue` and read back ONLY through `consumeVerificationValue`, the same
 * single-use path magic links and 2FA use. The plugin never finds-then-deletes itself and
 * never touches secondary storage directly, so it inherits whatever atomic path the host
 * configured (a lock-guarded DELETE ... RETURNING when `verification.storeInDatabase`).
 */
const PREFIX = "saml-idp:pending:";
const RID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface PendingRequest {
  spId: string;
  requestId: string;
  acsUrl: string;
  relayState: string | undefined;
  forceAuthn: boolean;
  /** ms since epoch; ForceAuthn requires a session created after this. */
  createdAt: number;
  /** SHA-256 (base64url) of the browser-binding cookie value. */
  bindingHash: string;
}

type InternalAdapter = {
  createVerificationValue(data: { identifier: string; value: string; expiresAt: Date }): Promise<unknown>;
  consumeVerificationValue(identifier: string): Promise<{ value: string; expiresAt: Date } | null>;
};

export function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 256 random bits, base64url (43 chars). */
export function newOpaqueToken(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function sha256b64url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return base64url(new Uint8Array(digest));
}

export async function storePending(adapter: InternalAdapter, data: PendingRequest, ttlSeconds: number): Promise<string> {
  const rid = newOpaqueToken();
  await adapter.createVerificationValue({
    identifier: PREFIX + rid,
    value: JSON.stringify(data),
    expiresAt: new Date(Date.now() + ttlSeconds * 1000),
  });
  return rid;
}

/** Single use. Returns null for unknown, already-consumed, expired or malformed `rid`s. */
export async function consumePending(adapter: InternalAdapter, rid: string): Promise<PendingRequest | null> {
  if (!RID_PATTERN.test(rid)) return null;
  const row = await adapter.consumeVerificationValue(PREFIX + rid);
  if (!row) return null; // consumeVerificationValue already treats expired rows as consumed
  try {
    const v = JSON.parse(row.value) as PendingRequest;
    return typeof v?.spId === "string" && typeof v.requestId === "string" && typeof v.acsUrl === "string" ? v : null;
  } catch {
    return null;
  }
}

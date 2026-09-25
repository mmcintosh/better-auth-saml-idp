import { sha256b64url } from "./pending";

/**
 * Seen AuthnRequest IDs (ADDENDUM-01 R2). A replay is detected by the INSERT failing on the
 * UNIQUE `key` column (a hash of spId + requestId). The follow-up read only classifies the
 * failure, so adapter-specific error codes need not be parsed. Never uses KV / secondary
 * storage.
 *
 * Requires an adapter that enforces UNIQUE: every real database does; Better Auth's
 * in-memory adapter does not (dev only) — see docs/security.md.
 */
export const SEEN_MODEL = "samlIdpSeenRequest";

type Adapter = {
  create(args: { model: string; data: Record<string, unknown> }): Promise<unknown>;
  findOne(args: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
};

export async function seenRequestKey(spId: string, requestId: string) {
  return sha256b64url(`saml-idp:seen\u0000${spId}\u0000${requestId}`);
}

/** Returns true the first time (spId, requestId) is recorded, false for a replay. */
export async function recordRequestId(adapter: Adapter, spId: string, requestId: string, expiresAt: Date): Promise<boolean> {
  const key = await seenRequestKey(spId, requestId);
  try {
    await adapter.create({ model: SEEN_MODEL, data: { key, spId, requestId, expiresAt } });
    return true;
  } catch (error) {
    if (await adapter.findOne({ model: SEEN_MODEL, where: [{ field: "key", value: key }] })) return false;
    throw error;
  }
}

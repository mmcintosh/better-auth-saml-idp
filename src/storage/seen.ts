import { sha256b64url } from "./pending";

/**
 * Seen AuthnRequest IDs (ADDENDUM-01 R2). A replay is detected by the INSERT failing on the
 * primary key (a deterministic hash of spId + requestId; hosts also get a composite UNIQUE
 * index in the documented schema). The follow-up read only classifies the failure, exactly as
 * Better Auth's own `reserveVerificationValue` does, so adapter-specific error codes need not
 * be parsed. Never uses KV / secondary storage.
 *
 * Requires an adapter that enforces primary keys: every real database does; Better Auth's
 * in-memory adapter does not (dev only) — see docs/security.md.
 */
export const SEEN_MODEL = "samlIdpSeenRequest";

type Adapter = {
  create(args: { model: string; data: Record<string, unknown>; forceAllowId?: boolean }): Promise<unknown>;
  findOne(args: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
  deleteMany(args: { model: string; where: { field: string; value: unknown; operator?: "lt" }[] }): Promise<unknown>;
};

export async function seenRequestKey(spId: string, requestId: string) {
  return sha256b64url(`saml-idp:seen\u0000${spId}\u0000${requestId}`);
}

/** Returns true the first time (spId, requestId) is recorded, false for a replay. */
export async function recordRequestId(
  adapter: Adapter,
  spId: string,
  requestId: string,
  expiresAt: Date,
  onCleanupError: (e: unknown) => void,
): Promise<boolean> {
  const id = await seenRequestKey(spId, requestId);
  // Opportunistic cleanup of expired rows; an indexed range delete. Failure is not fatal.
  await adapter
    .deleteMany({ model: SEEN_MODEL, where: [{ field: "expiresAt", value: new Date(), operator: "lt" }] })
    .catch(onCleanupError);
  try {
    await adapter.create({ model: SEEN_MODEL, data: { id, spId, requestId, expiresAt }, forceAllowId: true });
    return true;
  } catch (error) {
    if (await adapter.findOne({ model: SEEN_MODEL, where: [{ field: "id", value: id }] })) return false;
    throw error;
  }
}

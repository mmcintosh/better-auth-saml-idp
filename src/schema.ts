import type { BetterAuthPluginDBSchema } from "better-auth/db";

/**
 * Seen AuthnRequest IDs, for replay protection (ADDENDUM-01 R2).
 *
 * `key` is a hash of (spId, requestId) with a UNIQUE constraint; a replay is detected by the
 * INSERT failing on it. The row `id` is left entirely to Better Auth (`generateId` may be
 * "serial" or "uuid", which ignore forced ids), so replay protection never depends on it.
 * Hosts' hand-written schemas should also add UNIQUE(spId, requestId) (see README).
 */
export function samlIdpSchema() {
  return {
    samlIdpSeenRequest: {
      fields: {
        key: { type: "string", required: true, unique: true, input: false },
        spId: { type: "string", required: true, input: false },
        requestId: { type: "string", required: true, input: false },
        expiresAt: { type: "date", required: true, input: false, index: true },
      },
    },
  } satisfies BetterAuthPluginDBSchema;
}

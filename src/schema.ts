import type { BetterAuthPluginDBSchema } from "better-auth/db";

/**
 * Seen AuthnRequest IDs, for replay protection (ADDENDUM-01 R2).
 *
 * Uniqueness of (spId, requestId) is enforced by the primary key: `id` is a deterministic
 * hash of the pair, inserted with `forceAllowId`. Every real database rejects a duplicate
 * primary key, so a replay is detected by the INSERT failing, never by a read-then-write.
 * (Better Auth's plugin schema format cannot express a composite UNIQUE; a hashed PK over
 * exactly those two columns is the equivalent constraint. See DECISIONS.md D-011.)
 */
export const samlIdpSchema = {
  samlIdpSeenRequest: {
    fields: {
      spId: { type: "string", required: true, input: false },
      requestId: { type: "string", required: true, input: false },
      expiresAt: { type: "date", required: true, input: false, index: true },
    },
  },
} satisfies BetterAuthPluginDBSchema;

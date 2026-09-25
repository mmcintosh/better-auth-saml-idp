import type { BetterAuthPluginDBSchema } from "better-auth/db";

/**
 * Seen AuthnRequest IDs, for replay protection (ADDENDUM-01 R2).
 *
 * `key` is a hash of (spId, requestId) with a UNIQUE constraint; a replay is detected by the
 * INSERT failing on it. The row `id` is left entirely to Better Auth (`generateId` may be
 * "serial" or "uuid", which ignore forced ids), so replay protection never depends on it.
 * Hosts' hand-written schemas should also add UNIQUE(spId, requestId) (see README).
 */
export function samlIdpSchema(opts: { registry?: boolean; singleLogout?: boolean } = {}) {
  return {
    ...(opts.registry ? registrySchema() : {}),
    ...(opts.singleLogout ? logoutSchema() : {}),
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

/**
 * The database-backed SP registry (D-027); only part of the schema when `registry.enabled`, so
 * hosts without it don't need the table. `config` is the SP's JSON (validated on every write
 * and read); `spId` and `entityId` are copied out of it so they can be unique and looked up.
 */
function registrySchema() {
  return {
    samlIdpServiceProvider: {
      fields: {
        spId: { type: "string", required: true, unique: true, input: false },
        entityId: { type: "string", required: true, unique: true, input: false },
        config: { type: "string", required: true, input: false },
        enabled: { type: "boolean", required: true, input: false },
        createdAt: { type: "date", required: true, input: false },
        updatedAt: { type: "date", required: true, input: false },
        updatedBy: { type: "string", required: false, input: false },
      },
    },
  } satisfies BetterAuthPluginDBSchema;
}

/**
 * Which SPs received an assertion in which IdP session (D-028), so logout can reach them all.
 * `sessionKey` is a hash of the Better Auth session id (never the id or token itself); `key`
 * is hash(sessionKey, spId) and UNIQUE, so each SP appears once per session.
 */
function logoutSchema() {
  return {
    samlIdpSessionParticipant: {
      fields: {
        key: { type: "string", required: true, unique: true, input: false },
        sessionKey: { type: "string", required: true, input: false, index: true },
        spId: { type: "string", required: true, input: false },
        nameId: { type: "string", required: true, input: false },
        nameIdFormat: { type: "string", required: true, input: false },
        sessionIndex: { type: "string", required: true, input: false },
        expiresAt: { type: "date", required: true, input: false, index: true },
      },
    },
  } satisfies BetterAuthPluginDBSchema;
}


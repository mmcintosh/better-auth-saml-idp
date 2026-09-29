import type { BetterAuthPluginDBSchema } from "better-auth/db";

/**
 * Seen AuthnRequest IDs, for replay protection (ADDENDUM-01 R2).
 *
 * `key` is a hash of (spId, requestId) with a UNIQUE constraint; a replay is detected by the
 * INSERT failing on it. The row `id` is left entirely to Better Auth (`generateId` may be
 * "serial" or "uuid", which ignore forced ids), so replay protection never depends on it.
 * Hosts' hand-written schemas should also add UNIQUE(spId, requestId) (see README).
 */
export function samlIdpSchema(opts: { registry?: boolean; sessionTracking?: boolean; auditLog?: boolean; tenants?: boolean; tenantKeys?: boolean } = {}) {
  return {
    ...(opts.registry ? (opts.tenants ? tenantRegistrySchema() : registrySchema()) : {}),
    ...(opts.tenants ? tenantSchema() : {}),
    ...(opts.tenants && opts.tenantKeys ? tenantKeySchema() : {}),
    ...(opts.auditLog ? auditSchema(opts.tenants === true) : {}),
    ...(opts.sessionTracking ? logoutSchema() : {}),
    samlIdpSeenRequest: {
      fields: {
        key: { type: "string", required: true, unique: true, input: false },
        spId: { type: "string", required: true, input: false },
        requestId: { type: "string", required: true, input: false },
        expiresAt: { type: "date", required: true, input: false, index: true },
      },
      // Also declared as a table-level index: Better Auth 1.7's MongoDB adapter creates indexes
      // only from `indexes`, ignoring field-level `unique` (the SQL migrators honour both). Without
      // this, replay protection silently did nothing on MongoDB (adapter matrix, D-033).
      indexes: [{ fields: ["key"], unique: true, name: "saml_idp_seen_request_key_unique" }],
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
      indexes: [
        { fields: ["spId"], unique: true, name: "saml_idp_service_provider_sp_id_unique" },
        { fields: ["entityId"], unique: true, name: "saml_idp_service_provider_entity_id_unique" },
      ],
    },
  } satisfies BetterAuthPluginDBSchema;
}

/**
 * The registry with tenants (D-052). Entity IDs are unique per tenant, not globally: the same SP
 * (AWS, Google) can be registered in several. `lookupKey` is a hash of (tenantId, entityId) and
 * UNIQUE, as the replay key is (a composite of a possibly long entity ID doesn't index
 * everywhere). `tenantId` is "" for the root IdP's SPs, never NULL. `lookupKey` is required, so
 * its UNIQUE index can be declared for MongoDB too (Better Auth allows unique indexes on required
 * fields only). A table that already has rows needs it added by hand: nullable, backfilled
 * (`samlIdpBackfillServiceProviderKeys`), then constrained; the multi-tenant guide has the steps.
 * Rows without it are found by no lookup until then.
 */
function tenantRegistrySchema() {
  return {
    samlIdpServiceProvider: {
      fields: {
        spId: { type: "string", required: true, unique: true, input: false },
        entityId: { type: "string", required: true, input: false, index: true },
        config: { type: "string", required: true, input: false },
        enabled: { type: "boolean", required: true, input: false },
        createdAt: { type: "date", required: true, input: false },
        updatedAt: { type: "date", required: true, input: false },
        updatedBy: { type: "string", required: false, input: false },
        tenantId: { type: "string", required: true, defaultValue: "", input: false, index: true },
        lookupKey: { type: "string", required: true, unique: true, input: false },
      },
      indexes: [
        { fields: ["spId"], unique: true, name: "saml_idp_service_provider_sp_id_unique" },
        { fields: ["lookupKey"], unique: true, name: "saml_idp_service_provider_lookup_key_unique" },
      ],
    },
  } satisfies BetterAuthPluginDBSchema;
}

/**
 * Tenants (D-052): which organizations have their own IdP identity. Only organizations with a
 * row are tenants; the host's administrators create them. `tenantKey` names the tenant in its
 * URLs and entity ID, so it never changes once set. `organizationCreatedAt` is the organization's
 * `createdAt` when the tenant was made: it binds the tenant to that organization, not just to an
 * id that a database may hand out again after a delete (review 6 R6-1, D-053).
 *
 * `samlIdpRetiredTenantKey`: the key of every deleted tenant, so it is never used again. SPs
 * configured for a deleted tenant still trust its entity ID (review 6 R6-2, D-053).
 */
function tenantSchema() {
  return {
    samlIdpTenant: {
      fields: {
        organizationId: { type: "string", required: true, unique: true, input: false },
        tenantKey: { type: "string", required: true, unique: true, input: false },
        organizationCreatedAt: { type: "date", required: true, input: false },
        enabled: { type: "boolean", required: true, input: false },
        createdAt: { type: "date", required: true, input: false },
        updatedAt: { type: "date", required: true, input: false },
        updatedBy: { type: "string", required: false, input: false },
      },
      indexes: [
        { fields: ["organizationId"], unique: true, name: "saml_idp_tenant_organization_id_unique" },
        { fields: ["tenantKey"], unique: true, name: "saml_idp_tenant_tenant_key_unique" },
      ],
    },
    samlIdpRetiredTenantKey: {
      fields: {
        tenantKey: { type: "string", required: true, unique: true, input: false },
        organizationId: { type: "string", required: true, input: false },
        retiredAt: { type: "date", required: true, input: false },
        retiredBy: { type: "string", required: false, input: false },
      },
      indexes: [{ fields: ["tenantKey"], unique: true, name: "saml_idp_retired_tenant_key_unique" }],
    },
  } satisfies BetterAuthPluginDBSchema;
}

/**
 * Per-tenant signing keys (`tenants.keys: "per-tenant"`, D-058): one row per key. `state` is
 * next | active | previous | retired; `stateKey` is UNIQUE, a hash of (tenantId, state) for next
 * and active, so a tenant never has two of either. `encryptedPrivateKey` is sealed with Better
 * Auth's secret and bound to its tenant and kid; it is emptied when the key is retired.
 */
function tenantKeySchema() {
  return {
    samlIdpTenantKey: {
      fields: {
        tenantId: { type: "string", required: true, input: false, index: true },
        kid: { type: "string", required: true, input: false },
        state: { type: "string", required: true, input: false },
        stateKey: { type: "string", required: true, unique: true, input: false },
        encryptedPrivateKey: { type: "string", required: true, input: false },
        certificate: { type: "string", required: true, input: false },
        notAfter: { type: "date", required: true, input: false },
        createdAt: { type: "date", required: true, input: false },
        activatedAt: { type: "date", required: false, input: false },
        updatedBy: { type: "string", required: false, input: false },
      },
      indexes: [{ fields: ["stateKey"], unique: true, name: "saml_idp_tenant_key_state_key_unique" }],
    },
  } satisfies BetterAuthPluginDBSchema;
}

/**
 * The audit log (D-038): one row per event, with the fields worth querying as columns and the
 * whole event as JSON in `details`. Rows expire after `auditLog.retentionDays`. With tenants
 * (D-052), the event's tenant is a column too (null for the root IdP).
 */
function auditSchema(tenants: boolean) {
  return {
    samlIdpAuditEvent: {
      fields: {
        type: { type: "string", required: true, input: false, index: true },
        at: { type: "date", required: true, input: false, index: true },
        spId: { type: "string", required: false, input: false, index: true },
        userId: { type: "string", required: false, input: false, index: true },
        code: { type: "string", required: false, input: false },
        ipAddress: { type: "string", required: false, input: false },
        userAgent: { type: "string", required: false, input: false },
        details: { type: "string", required: true, input: false },
        expiresAt: { type: "date", required: true, input: false, index: true },
        ...(tenants ? { tenantId: { type: "string", required: false, input: false, index: true } } : {}),
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
        // D-043: find a user's SPs after the session is gone; set when the session ended
        // without Single Logout. Optional so rows from before the upgrade stay valid.
        userId: { type: "string", required: false, input: false, index: true },
        endedAt: { type: "date", required: false, input: false },
        spId: { type: "string", required: true, input: false },
        nameId: { type: "string", required: true, input: false },
        nameIdFormat: { type: "string", required: true, input: false },
        sessionIndex: { type: "string", required: true, input: false },
        expiresAt: { type: "date", required: true, input: false, index: true },
      },
      indexes: [{ fields: ["key"], unique: true, name: "saml_idp_session_participant_key_unique" }],
    },
  } satisfies BetterAuthPluginDBSchema;
}


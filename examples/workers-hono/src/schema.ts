// Drizzle schema for the example: better-auth core + better-auth-cloudflare geolocation + admin
// and organization plugins + saml-idp. Field maps use Drizzle property keys (usePlural, snake_case columns).
import { sql } from "drizzle-orm";
import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

const now = sql`(cast(unixepoch('subsecond') * 1000 as integer))`;

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).default(false).notNull(),
  image: text("image"),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).default(now).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).default(now).$onUpdate(() => new Date()).notNull(),
  // admin plugin
  role: text("role"),
  banned: integer("banned", { mode: "boolean" }).default(false),
  banReason: text("ban_reason"),
  banExpires: integer("ban_expires", { mode: "timestamp_ms" }),
  // twoFactor plugin (migration 0012)
  twoFactorEnabled: integer("two_factor_enabled", { mode: "boolean" }).default(false),
});

// twoFactor plugin (migration 0012): one row per user with an authenticator app.
export const twoFactors = sqliteTable(
  "two_factors",
  {
    id: text("id").primaryKey(),
    secret: text("secret").notNull(),
    backupCodes: text("backup_codes").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    verified: integer("verified", { mode: "boolean" }).default(true),
    failedVerificationCount: integer("failed_verification_count").default(0),
    lockedUntil: integer("locked_until", { mode: "timestamp_ms" }),
  },
  (t) => [index("two_factors_secret_idx").on(t.secret), index("two_factors_user_id_idx").on(t.userId)],
);

export const sessions = sqliteTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
    token: text("token").notNull().unique(),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).default(now).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).$onUpdate(() => new Date()).notNull(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    // better-auth-cloudflare geolocation
    timezone: text("timezone"),
    city: text("city"),
    country: text("country"),
    region: text("region"),
    regionCode: text("region_code"),
    colo: text("colo"),
    latitude: text("latitude"),
    longitude: text("longitude"),
    // admin plugin
    impersonatedBy: text("impersonated_by"),
    // organization plugin (migration 0010)
    activeOrganizationId: text("active_organization_id"),
  },
  (t) => [index("sessions_userId_idx").on(t.userId)],
);

export const accounts = sqliteTable(
  "accounts",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    idToken: text("id_token"),
    accessTokenExpiresAt: integer("access_token_expires_at", { mode: "timestamp_ms" }),
    refreshTokenExpiresAt: integer("refresh_token_expires_at", { mode: "timestamp_ms" }),
    scope: text("scope"),
    password: text("password"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).default(now).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).$onUpdate(() => new Date()).notNull(),
  },
  (t) => [index("accounts_userId_idx").on(t.userId)],
);

export const verifications = sqliteTable(
  "verifications",
  {
    id: text("id").primaryKey(),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).default(now).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).default(now).$onUpdate(() => new Date()).notNull(),
  },
  (t) => [index("verifications_identifier_idx").on(t.identifier)],
);

export const rateLimits = sqliteTable("rate_limits", {
  id: text("id").primaryKey(),
  key: text("key").notNull().unique(),
  count: integer("count").notNull(),
  lastRequest: integer("last_request").notNull(),
});

// saml-idp (ADDENDUM-01 R2)
export const samlIdpSeenRequests = sqliteTable(
  "saml_idp_seen_requests",
  {
    id: text("id").primaryKey(),
    key: text("key").notNull().unique(),
    spId: text("sp_id").notNull(),
    requestId: text("request_id").notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [
    uniqueIndex("saml_idp_seen_requests_sp_request_uq").on(t.spId, t.requestId),
    index("saml_idp_seen_requests_expires_idx").on(t.expiresAt),
  ],
);

/** Database-backed SP registry (only needed with `registry.enabled`; D-027). */
export const samlIdpServiceProviders = sqliteTable("saml_idp_service_providers", {
  id: text("id").primaryKey(),
  spId: text("sp_id").notNull().unique(),
  entityId: text("entity_id").notNull().unique(),
  config: text("config").notNull(),
  enabled: integer("enabled", { mode: "boolean" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
  updatedBy: text("updated_by"),
  // Tenants (D-052, migration 0008): "" for the root IdP; lookupKey is UNIQUE (NULL until backfilled).
  tenantId: text("tenant_id").notNull().default(""),
  lookupKey: text("lookup_key").unique(),
});

/** Tenants (only needed with `tenants.enabled`; D-052, migration 0008). */
export const samlIdpTenants = sqliteTable("saml_idp_tenants", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull().unique(),
  tenantKey: text("tenant_key").notNull().unique(),
  organizationCreatedAt: integer("organization_created_at", { mode: "timestamp_ms" }).notNull(),
  enabled: integer("enabled", { mode: "boolean" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
  updatedBy: text("updated_by"),
});

/** Keys of deleted tenants, never used again (D-053). */
export const samlIdpRetiredTenantKeys = sqliteTable("saml_idp_retired_tenant_keys", {
  id: text("id").primaryKey(),
  tenantKey: text("tenant_key").notNull().unique(),
  organizationId: text("organization_id").notNull(),
  retiredAt: integer("retired_at", { mode: "timestamp_ms" }).notNull(),
  retiredBy: text("retired_by"),
});

/** Per-tenant signing keys (only needed with `tenants.keys: "per-tenant"`; D-058). */
export const samlIdpTenantKeys = sqliteTable("saml_idp_tenant_keys", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  kid: text("kid").notNull(),
  state: text("state").notNull(),
  stateKey: text("state_key").notNull().unique(),
  encryptedPrivateKey: text("encrypted_private_key").notNull(),
  certificate: text("certificate").notNull(),
  notAfter: integer("not_after", { mode: "timestamp_ms" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  activatedAt: integer("activated_at", { mode: "timestamp_ms" }),
  updatedBy: text("updated_by"),
});


// organization plugin (migration 0010): tenants are organizations.
export const organizations = sqliteTable("organizations", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  logo: text("logo"),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  metadata: text("metadata"),
});

export const members = sqliteTable(
  "members",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    role: text("role").notNull(),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [index("members_organization_idx").on(t.organizationId), index("members_user_idx").on(t.userId)],
);

export const invitations = sqliteTable("invitations", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  email: text("email").notNull(),
  role: text("role"),
  status: text("status").notNull(),
  expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  inviterId: text("inviter_id").notNull().references(() => users.id, { onDelete: "cascade" }),
});

/** Which SPs got assertions in which session: for Single Logout (D-028) and `events.onSessionEnded` (D-043). */
export const samlIdpSessionParticipants = sqliteTable(
  "saml_idp_session_participants",
  {
    id: text("id").primaryKey(),
    key: text("key").notNull().unique(), // hash(sessionKey, spId)
    sessionKey: text("session_key").notNull(),
    userId: text("user_id"), // D-043, migration 0007
    endedAt: integer("ended_at", { mode: "timestamp_ms" }),
    spId: text("sp_id").notNull(),
    nameId: text("name_id").notNull(),
    nameIdFormat: text("name_id_format").notNull(),
    sessionIndex: text("session_index").notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [
    index("saml_idp_session_participants_session_idx").on(t.sessionKey),
    index("saml_idp_session_participants_expires_idx").on(t.expiresAt),
    index("saml_idp_session_participants_user_idx").on(t.userId),
  ],
);

/** Audit log (only needed with `auditLog.enabled`; D-038). */
export const samlIdpAuditEvents = sqliteTable(
  "saml_idp_audit_events",
  {
    id: text("id").primaryKey(),
    type: text("type").notNull(),
    at: integer("at", { mode: "timestamp_ms" }).notNull(),
    spId: text("sp_id"),
    userId: text("user_id"),
    code: text("code"),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    details: text("details").notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
    tenantId: text("tenant_id"), // D-052, migration 0008
  },
  (t) => [
    index("saml_idp_audit_events_at_idx").on(t.at),
    index("saml_idp_audit_events_type_idx").on(t.type),
    index("saml_idp_audit_events_sp_idx").on(t.spId),
    index("saml_idp_audit_events_user_idx").on(t.userId),
    index("saml_idp_audit_events_expires_idx").on(t.expiresAt),
  ],
);

/** better-auth-scim-provisioning (migration 0011; only with a provisioning target): the outbox and the links. */
export const scimProvisioningJobs = sqliteTable(
  "scim_provisioning_jobs",
  {
    id: text("id").primaryKey(),
    key: text("key").notNull().unique(),
    targetId: text("target_id").notNull(),
    userId: text("user_id").notNull(),
    version: integer("version").notNull(),
    attempts: integer("attempts").notNull(),
    nextAttemptAt: integer("next_attempt_at", { mode: "timestamp_ms" }).notNull(),
    lockedUntil: integer("locked_until", { mode: "timestamp_ms" }).notNull(),
    failed: integer("failed", { mode: "boolean" }).notNull(),
    lastError: text("last_error"),
    lastStatus: integer("last_status"),
    kind: text("kind"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [index("scim_provisioning_jobs_user_idx").on(t.userId), index("scim_provisioning_jobs_next_idx").on(t.nextAttemptAt)],
);

export const scimProvisioningLinks = sqliteTable(
  "scim_provisioning_links",
  {
    id: text("id").primaryKey(),
    key: text("key").notNull().unique(),
    targetId: text("target_id").notNull(),
    userId: text("user_id").notNull(),
    remoteId: text("remote_id").notNull(),
    userName: text("user_name").notNull(),
    externalId: text("external_id"),
    active: integer("active", { mode: "boolean" }).notNull(),
    syncedAt: integer("synced_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [
    index("scim_provisioning_links_target_idx").on(t.targetId),
    index("scim_provisioning_links_user_idx").on(t.userId),
    index("scim_provisioning_links_remote_idx").on(t.remoteId),
  ],
);

export const scimProvisioningGroupLinks = sqliteTable(
  "scim_provisioning_group_links",
  {
    id: text("id").primaryKey(),
    key: text("key").notNull().unique(),
    targetId: text("target_id").notNull(),
    organizationId: text("organization_id").notNull(),
    remoteId: text("remote_id").notNull(),
    displayName: text("display_name").notNull(),
    syncedAt: integer("synced_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [index("scim_provisioning_group_links_target_idx").on(t.targetId), index("scim_provisioning_group_links_remote_idx").on(t.remoteId)],
);

export const schema = { scimProvisioningJobs, scimProvisioningLinks, scimProvisioningGroupLinks, users, twoFactors, sessions, accounts, verifications, rateLimits, organizations, members, invitations, samlIdpSeenRequests, samlIdpServiceProviders, samlIdpSessionParticipants, samlIdpAuditEvents, samlIdpTenants, samlIdpRetiredTenantKeys, samlIdpTenantKeys };

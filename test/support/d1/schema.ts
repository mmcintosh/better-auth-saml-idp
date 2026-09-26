// Drizzle schema for the D1 test host: better-auth core + better-auth-cloudflare geolocation
// + admin plugin + saml-idp. Mirrors better-auth-cloudflare's examples/hono conventions
// (usePlural, snake_case columns). Field maps use Drizzle property keys (ADDENDUM-01 R5).
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
});

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
});

/** Single Logout participants (only needed with `singleLogout.enabled`; D-028). */
export const samlIdpSessionParticipants = sqliteTable(
  "saml_idp_session_participants",
  {
    id: text("id").primaryKey(),
    key: text("key").notNull().unique(), // hash(sessionKey, spId)
    sessionKey: text("session_key").notNull(),
    spId: text("sp_id").notNull(),
    nameId: text("name_id").notNull(),
    nameIdFormat: text("name_id_format").notNull(),
    sessionIndex: text("session_index").notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [index("saml_idp_session_participants_session_idx").on(t.sessionKey), index("saml_idp_session_participants_expires_idx").on(t.expiresAt)],
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
  },
  (t) => [
    index("saml_idp_audit_events_at_idx").on(t.at),
    index("saml_idp_audit_events_type_idx").on(t.type),
    index("saml_idp_audit_events_sp_idx").on(t.spId),
    index("saml_idp_audit_events_user_idx").on(t.userId),
    index("saml_idp_audit_events_expires_idx").on(t.expiresAt),
  ],
);

export const schema = { users, sessions, accounts, verifications, rateLimits, samlIdpSeenRequests, samlIdpServiceProviders, samlIdpSessionParticipants, samlIdpAuditEvents };

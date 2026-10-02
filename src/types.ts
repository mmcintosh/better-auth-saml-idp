import type { Session, User } from "better-auth";
import type { SchemaValidator } from "./saml/validator";

export type { SchemaKind, SchemaValidationResult, SchemaValidator } from "./saml/validator";

export type SignatureAlgorithm = "rsa-sha256" | "rsa-sha512" | "rsa-sha1";
export type DigestAlgorithm = "sha256" | "sha512" | "sha1";

/** A Better Auth user, including any additional fields configured on the user table. */
export type SamlIdpUser = User & Record<string, unknown>;

export type SamlAttributeValue = string | string[];

/** A user's membership in a Better Auth organization (organization plugin; D-031). */
export interface OrganizationMembership {
  id: string;
  slug: string;
  name: string;
  /** The member's roles in this organization (Better Auth stores them comma-separated). */
  roles: string[];
}

/** Extra context for attribute functions and maps. */
export interface AttributeContext {
  /** The user's organization memberships; empty without the organization plugin. */
  organizations: OrganizationMembership[];
  /** The membership matching the SP's `organization` rule, when it has one. */
  organization: OrganizationMembership | undefined;
}

/**
 * What callbacks see of a service provider: a stable, read-only view. The plugin's own resolved
 * form holds internals (functions, parsed keys, cache settings) that may change in any release.
 */
export interface ServiceProviderInfo {
  readonly id: string;
  readonly entityId: string;
  readonly acsUrls: readonly string[];
  readonly nameIdFormat: string;
  /** The SP's organization rule, if it has one. */
  readonly organization: Readonly<{ slug?: string | undefined; id?: string | undefined; roles?: readonly string[] | undefined }> | undefined;
  /** The SP's tenant (an organization id, D-052), or null for an SP of the root IdP. */
  readonly tenantId: string | null;
}

/**
 * One SP as the registry API returns it (API decision 5): every route uses this shape, for SPs
 * in code and in the database alike.
 */
export interface ServiceProviderRecord {
  id: string;
  entityId: string;
  /** `"code"`: from `serviceProviders` (read-only here). `"database"`: managed by this API. */
  source: "code" | "database";
  enabled: boolean;
  /** Used for sign-in. False when `issues` is non-empty. Always true for code SPs (checked at startup). */
  valid: boolean;
  /** Why a stored SP isn't used for sign-in. */
  issues: string[];
  /** Accepted but worth a look (e.g. unpinned metadata). Code SPs' warnings are logged at startup instead. */
  warnings: string[];
  /** The stored JSON as saved (for SPs that aren't `valid`, possibly not a valid config). `null` for code SPs, which may hold functions. */
  config: Record<string, unknown> | null;
  /** Database SPs only; `null` for code SPs. */
  createdAt: Date | null;
  updatedAt: Date | null;
  /** The user who last saved it. */
  updatedBy: string | null;
  /**
   * Only with `tenants.enabled` (D-052): the SP's tenant (an organization id), or null for an SP
   * of the root IdP. Absent otherwise, so records are unchanged without tenants.
   */
  tenantId?: string | null | undefined;
}

/**
 * A tenant (D-052) as the registry API returns it: an organization with its own IdP identity.
 * The URLs are what the tenant's SPs are configured with; the entity ID is the metadata URL.
 */
export interface TenantRecord {
  organizationId: string;
  /** In the tenant's URLs. The organization id unless another was chosen at creation; never changes. */
  tenantKey: string;
  entityId: string;
  metadataUrl: string;
  ssoUrl: string;
  /** Null without `singleLogout`. */
  sloUrl: string | null;
  /** A disabled tenant's URLs answer as if it didn't exist, and its SPs can't sign in. */
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
  /** The user who last saved it. */
  updatedBy: string | null;
  /**
   * With `tenants.keys: "per-tenant"` (D-058): `"own"` once the tenant signs with its own key,
   * `"shared"` before (a tenant made before per-tenant keys, until its first key is activated).
   */
  signing?: "shared" | "own" | undefined;
  /** With `tenants.keys: "per-tenant"`: its keys, without private material, newest first. */
  keys?: TenantSigningKeyInfo[] | undefined;
  /** With `tenants.keys: "per-tenant"`: its own keys' certificates that expire within 30 days, or have. */
  warnings?: string[] | undefined;
}

/** See `TenantOptions.delegation`. */
export interface TenantDelegationOptions {
  /** Organization roles that manage the tenant's SPs. Default `["owner", "admin"]`. */
  roles?: string[] | undefined;
  /**
   * User fields a delegated SP may send, as attributes or as its NameID. Default `["email",
   * "name", "id"]`. Anything else in your user table (a role, a ban reason, an internal flag) could
   * otherwise be mapped out to an SP by a tenant's administrator.
   */
  userFields?: string[] | undefined;
  /**
   * Whether delegated SPs may use `metadata.url`, which makes your server fetch that URL (the
   * certificate refresh, D-026). Default false: a tenant's administrator would choose what it fetches.
   */
  allowMetadataUrl?: boolean | undefined;
}

/** A tenant's signing key as the API shows it (D-058). */
export interface TenantSigningKeyInfo {
  kid: string;
  /** `next`: published, not signing yet. `active`: signs. `previous`: replaced, still published. `retired`: neither. */
  state: "next" | "active" | "previous" | "retired";
  /** PEM. The shared key's certificate for the `previous` row a tenant's first own key leaves (kid "shared"). */
  certificate: string;
  notAfter: Date;
  createdAt: Date;
  activatedAt: Date | null;
  /** When `activate` accepts a `next` key without `force`. */
  activatableAt?: Date | undefined;
}

/** See `SamlIdpOptions.tenants`. */
export interface TenantOptions {
  enabled: boolean;
  /**
   * What tenants sign with (D-058). `"shared"` (default): every tenant signs with `signing`.
   * `"per-tenant"`: each tenant gets its own key, stored encrypted in `samlIdpTenantKey`. A new
   * tenant gets one at creation; a tenant made before signs with `signing` until its first key
   * is rotated in (`/saml-idp/tenants/keys/rotate`, then `/activate`). Once a tenant has its own
   * key, nothing else signs for it.
   */
  keys?: "shared" | "per-tenant" | undefined;
  /**
   * With `keys: "per-tenant"`: the secret that encrypts tenants' private keys. Default: Better
   * Auth's (`secrets`, else `secret`), whose versions also rotate it. Keep every version that
   * encrypted a stored key until those keys are rotated.
   */
  keyEncryptionSecret?: string | undefined;
  /**
   * With `keys: "per-tenant"`: how long a tenant's next key must have been published in its
   * metadata before `activate` accepts it, so SPs can fetch the new certificate. Default 86400
   * (24 hours); 0 to 31536000. `activate` with `force: true` skips it (audited; for a leaked key).
   */
  minPublishedSeconds?: number | undefined;
  /**
   * Phase 3 (D-059), with `keys: "per-tenant"` only: an organization's own administrators manage
   * their tenant's SPs through the registry API. Membership is read from the database on every
   * request, never from the session's active organization, so a demotion takes effect at once.
   */
  delegation?: TenantDelegationOptions | undefined;
  /** How long an isolate caches a tenant, and a miss. Default `registry.cacheSeconds` (60 s); 0 to 3600. */
  cacheSeconds?: number | undefined;
}

/**
 * What `authorize` returns. `true` or `{ allow: true }` issues the assertion; anything else denies.
 * - `reason` (log-safe text) goes into the `denied` event's `detail` and the log, never to the user.
 * - `reauthenticate: true` sends the user back to your login page (`prompt=login`) to sign in
 *   again, then asks `authorize` once more with the new session, e.g. when your policy needs a
 *   recent MFA. If the SP asked for no interaction (IsPassive), the SP gets `NoPassive`
 *   instead; if the user already signed in again for this request, it's a plain denial (no loop).
 */
export type AuthorizeResult = boolean | { allow: true } | { allow: false; reason?: string; reauthenticate?: boolean };

export interface AuthorizeContext {
  user: SamlIdpUser;
  session: Session;
  serviceProvider: ServiceProviderInfo;
  /** The user's organization memberships (organization plugin); empty without it. */
  organizations: OrganizationMembership[];
}

export const NAMEID_FORMAT = {
  emailAddress: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
} as const;

/**
 * Where a mapped attribute's value comes from:
 * - `"email"`: a user field (core or additional, e.g. `"role"`);
 * - `{ field, split?, part? }`: a field, split into several values (`split: ","`) and/or reduced to
 *   the first word or the rest (`part: "first" | "last"`, for first/last name from `name`);
 * - `{ value }`: a constant.
 * Missing, null and empty values are left out; dates become ISO 8601; arrays are multi-valued.
 */
export type AttributeSource =
  | string
  | { field: string; split?: string; part?: "first" | "last" }
  | { value: string | string[] }
  /**
   * From the organization plugin: the user's organizations (slugs, names or ids), or their roles.
   * Which organizations: those in `only` (ids or slugs) when set; otherwise the SP's own
   * `organization` when it has a rule; otherwise all of the user's (roles then as "slug:role").
   * Users can create organizations by default and name them anything ("Administrators"), so
   * without a rule, set `only` (review 4, R4-1).
   */
  | { organization: "slugs" | "names" | "ids" | "roles"; only?: string[] };
export type AttributeMap = Record<string, AttributeSource>;

export interface ServiceProviderConfig {
  /** Stable identifier used in logs and in `/saml2/idp/init?sp=<id>` (IdP-initiated SSO). */
  id: string;
  /** The SP's entity ID; matched exactly against the AuthnRequest `<Issuer>`. */
  entityId: string;
  /**
   * Allow-list of Assertion Consumer Service URLs. A requested ACS URL must match one
   * of these exactly; with no requested URL, the first entry is used.
   */
  acsUrls: [string, ...string[]];
  /** Defaults to `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`. */
  nameIdFormat?: string | undefined;
  /**
   * Value of `<NameID>`. Default depends on `nameIdFormat`:
   * - emailAddress / unspecified: the user's (verified) email;
   * - persistent: an opaque, stable, per-SP identifier (HMAC of the user id, keyed with the
   *   Better Auth secret) that is never re-assigned to another user;
   * - transient: a new random identifier for every assertion.
   *
   * Or `{ field }` (also for stored SPs): the value of a user field, e.g. an employee number.
   * Only fields users can't set themselves: `"id"`, `"email"`, or an additional (or plugin)
   * field with `input: false`. Anything else is refused, since the NameID is the user's identity
   * at the SP. A user with no value in the field is denied.
   */
  nameId?: (((user: SamlIdpUser) => string) | NameIdSource) | undefined;
  /**
   * Attributes to include in the `<AttributeStatement>`: a function, or a declarative map from
   * attribute name to source (usable from JSON configuration), e.g.
   * `{ email: "email", groups: { field: "role", split: "," }, firstName: { field: "name", part: "first" } }`.
   */
  attributes?: (((user: SamlIdpUser, context: AttributeContext) => Record<string, SamlAttributeValue>) | AttributeMap) | undefined;
  /**
   * Only members of this Better Auth organization (organization plugin) may use this SP, and, with
   * `roles`, only members holding one of them. Give `slug` or `id`. Evaluated before `authorize`.
   */
  organization?: { slug?: string | undefined; id?: string | undefined; roles?: string[] | undefined } | undefined;
  /**
   * What to do with signatures on this SP's requests (see {@link RequestSignaturePolicy}).
   * Default: `"verify-if-signed"` when `spCertificates` or `metadata` is set, else `"ignore"`.
   */
  requestSignatures?: RequestSignaturePolicy | undefined;
  /**
   * PEM X.509 certificate(s) the SP signs its requests with: one, or several during the SP's
   * key rotation (e.g. Cloudflare Access publishes two); a signature from any of them is accepted.
   */
  spCertificates?: string | string[] | undefined;
  /**
   * Allow IdP-initiated (unsolicited) SSO to this SP via `GET /saml2/idp/init?sp=<id>`.
   * Default false. The Response carries no `InResponseTo`, so the SP must accept unsolicited
   * Responses and track assertion IDs itself (docs/security.md).
   */
  allowIdpInitiated?: boolean | undefined;
  /**
   * RelayState sent with IdP-initiated Responses when the caller supplies none, or one that is
   * not in `allowedRelayStates` (commonly the SP-side landing URL). Requires `allowIdpInitiated`.
   */
  idpInitiatedRelayState?: string | undefined;
  /**
   * Caller-supplied `RelayState` values accepted on `/saml2/idp/init`, matched exactly. Any
   * other value is ignored (the default above is used): an IdP-initiated RelayState is usually
   * a redirect target at the SP, so accepting arbitrary values would make the IdP an
   * open-redirect launcher for the SP. Requires `allowIdpInitiated`.
   */
  allowedRelayStates?: string[] | undefined;
  /** Decide whether this user may use this SP. Denial issues no assertion. */
  authorize?: ((ctx: AuthorizeContext) => AuthorizeResult | Promise<AuthorizeResult>) | undefined;
  /**
   * Keep this SP's certificates current from its metadata URL (D-026). Only certificates are
   * taken from it: signing certificates (added to `spCertificates`) and, when `encryption` is on,
   * the encryption certificate (replacing `encryption.certificate`). The entity ID and ACS URLs
   * stay as configured here, so the metadata can never redirect assertions.
   */
  metadata?: {
    /** https only. Fetched with a 5 s timeout, redirects not followed, at most 1 MiB. */
    url: string;
    /** Default 86400 (a day); 300 to 604800. */
    refreshSeconds?: number | undefined;
    /**
     * Pin the metadata's own signature (recommended; required by federations). When set,
     * unsigned or wrongly signed metadata is rejected and the last good copy is kept.
     */
    signingCertificates?: string | string[] | undefined;
  };
  /**
   * Where this SP receives SAML Single Logout messages (its SingleLogoutService). Needed for the
   * SP to take part in logout (D-028). Default binding: HTTP-Redirect.
   */
  singleLogoutService?: { url: string; binding?: "redirect" | "post"; /** Where LogoutResponses go, if not `url` (metadata ResponseLocation). */ responseUrl?: string } | undefined;
  /** Override the global `signing.sign` for this SP. */
  sign?: SignedParts | undefined;
  /**
   * Encrypt the assertion to this SP (`<saml:EncryptedAssertion>`, XML Encryption 1.1).
   * The assertion is signed first, then encrypted, then the Response is signed
   * ("sign-then-encrypt"), as `sign` says. Omit to send plaintext assertions.
   */
  encryption?: ServiceProviderEncryptionConfig | undefined;
  /** Override the global `sessionNotOnOrAfter` for this SP. */
  sessionNotOnOrAfter?: SessionLimit | undefined;
  /**
   * With `tenants.enabled` (D-052): the organization id of the tenant this SP belongs to. The SP
   * then sees the tenant's IdP identity (entity ID, SSO and SLO URLs), is found only through the
   * tenant's URLs, and only members of that organization may sign in to it. `organization` may
   * only narrow that with `roles` (`{ id: <this tenant>, roles }`). Omit for the root IdP.
   */
  tenant?: string | undefined;
}

export interface ServiceProviderEncryptionConfig {
  /** The SP's PEM X.509 encryption certificate (RSA ≥ 2048 bits). */
  certificate: string;
  /** Content encryption. Default `aes256-gcm`. `aes256-cbc` also needs `allowInsecureCbc: true`. */
  dataAlgorithm?: "aes256-gcm" | "aes128-gcm" | "aes256-cbc" | undefined;
  /**
   * Key transport. Default `rsa-oaep` (`xmlenc#rsa-oaep-mgf1p`, SHA-1/MGF1-SHA1, the most widely
   * supported). `rsa-oaep-sha256` is `xmlenc11#rsa-oaep` with SHA-256 and MGF1-SHA256.
   * RSA PKCS#1 v1.5 is not available.
   */
  keyAlgorithm?: "rsa-oaep" | "rsa-oaep-sha256" | undefined;
  /** Explicit opt-in to AES-CBC for SPs without GCM (padding-oracle history). Logs a warning. */
  allowInsecureCbc?: boolean | undefined;
}

export interface SigningConfig {
  /** PEM private key (PKCS#1 or PKCS#8, unencrypted, RSA ≥ 2048 bits). */
  privateKey: string;
  /** PEM X.509 certificate matching `privateKey`. */
  certificate: string;
  /** Extra certificates published in metadata, e.g. the next key during rotation. */
  additionalCertificates?: string[] | undefined;
  /** Default `rsa-sha256`. `rsa-sha1` also needs `allowInsecureSha1: true`. */
  signatureAlgorithm?: SignatureAlgorithm | undefined;
  /** Default `sha256`. `sha1` also needs `allowInsecureSha1: true`. */
  digestAlgorithm?: DigestAlgorithm | undefined;
  /** Explicit opt-in to SHA-1 for legacy SPs. Logs a warning at startup. */
  allowInsecureSha1?: boolean | undefined;
  /** Which parts of the SAML Response to sign. Default `"both"`. */
  sign?: SignedParts | undefined;
}

/** See `SamlIdpOptions.authnContext`. */
export interface AuthnContextOptions {
  /** AuthnContextClassRef URIs your sign-in can deliver, weakest first (1 to 10, unique). */
  levels: string[];
  /** The class this session achieved: one of `levels`. Runs on the user and session as re-read just before signing. */
  current: (ctx: { user: SamlIdpUser; session: Session }) => string | Promise<string>;
}

/** See `SamlIdpOptions.sessionNotOnOrAfter`. */
export type SessionLimit = false | "idp-session" | { maxSeconds: number };

/** NameID from a user field; see `ServiceProviderConfig.nameId`. */
export interface NameIdSource {
  field: string;
}

/** Sign the whole `<Response>`, only the `<Assertion>` inside it, or both (the default). */
export type SignedParts = "both" | "response" | "assertion";

/**
 * Signatures on an SP's AuthnRequests and LogoutRequests:
 * - `"require"`: every request must be signed by one of the SP's certificates.
 * - `"verify-if-signed"`: an unsigned AuthnRequest is accepted, a signed one must verify.
 *   LogoutRequests (and LogoutResponses) must always be signed, since logout is unauthenticated otherwise.
 * - `"ignore"`: signatures are not checked. For SPs whose certificate you don't have.
 * With certificates only from `metadata`, a signature that can't be checked yet (metadata
 * not loaded) is rejected, never accepted unverified.
 */
export type RequestSignaturePolicy = "require" | "verify-if-signed" | "ignore";

export interface SamlIdpOptions {
  /** The IdP entity ID, usually `https://<host>/<basePath>/saml2/idp`. */
  entityId: string;
  /**
   * Where the IdP's own URLs (SSO endpoint in metadata, resume URL, expected `Destination`)
   * come from. Same value and rule as Better Auth's `baseURL`: a bare origin
   * (`https://auth.example.com`) gets `basePath` added; a URL with a path is used as it is.
   * Default: Better Auth's base URL. Pin this or Better Auth's, or URLs follow the Host header.
   */
  baseURL?: string | undefined;
  /** Where unauthenticated users are sent. Path on this origin, or an absolute URL. */
  loginPage: string;
  signing: SigningConfig;
  /** Assertion validity window. Default 300 s. */
  assertionLifetimeSeconds?: number | undefined;
  /** Tolerance applied to `NotBefore` and request `IssueInstant`. Default 60 s. */
  clockSkewSeconds?: number | undefined;
  /** How long a stored AuthnRequest waits for the user to sign in. Default 600 s. */
  pendingRequestTtlSeconds?: number | undefined;
  /**
   * Maximum RelayState size in bytes. Default (and hard cap) 4096. SAML Bindings §3.4.3 says
   * 80, but real SPs send far more: Cloudflare Access sends over 1000 (DECISIONS.md D-016,
   * D-062). Set 80 for strict spec behaviour. RelayState is opaque to the IdP and always HTML-escaped.
   */
  relayStateMaxBytes?: number | undefined;
  /**
   * The `AuthnContextClassRef` asserted, and matched against an SP's
   * `RequestedAuthnContext`. Default `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`.
   * Set it to what your sign-in actually guarantees, e.g. `...:PasswordProtectedTransport`.
   */
  authnContextClassRef?: string | undefined;
  /**
   * Step-up authentication (D-047), instead of a fixed `authnContextClassRef`: the classes your
   * sign-in can deliver, weakest first, and which one the current session achieved. An SP's
   * `RequestedAuthnContext` (exact, minimum, better or maximum) is judged against `levels`:
   * - already met: the assertion states the achieved class;
   * - reachable but not met: the user goes back to `loginPage` with `prompt=login` and
   *   `acr_values=<the weakest class that would do>`, and is judged again on the new session;
   * - still not met after that, or not reachable at all: the SP gets `NoAuthnContext`
   *   (`NoPassive` for IsPassive requests).
   */
  authnContext?: AuthnContextOptions | undefined;
  /**
   * Who may receive assertions. Defaults are strict: an IdP vouches for identities.
   */
  accountPolicy?: {
    /** Refuse users whose email is not verified. Default true. */
    requireEmailVerified?: boolean | undefined;
    /** Allow sessions created by admin impersonation (`impersonatedBy`). Default false. */
    allowImpersonatedSessions?: boolean | undefined;
    /** Allow anonymous-plugin users (`isAnonymous`). Default false. */
    allowAnonymousUsers?: boolean | undefined;
  };
  serviceProviders: ServiceProviderConfig[];
  /**
   * Rename the plugin's table or columns, as with other Better Auth plugins.
   * Field maps use schema property keys (e.g. Drizzle keys), not raw column names.
   */
  schema?: {
    samlIdpSeenRequest?: {
      modelName?: string | undefined;
      fields?: Partial<Record<"key" | "spId" | "requestId" | "expiresAt", string>> | undefined;
    };
    samlIdpSessionParticipant?: {
      modelName?: string | undefined;
      fields?: Partial<Record<"key" | "sessionKey" | "spId" | "nameId" | "nameIdFormat" | "sessionIndex" | "expiresAt", string>> | undefined;
    };
    samlIdpServiceProvider?: {
      modelName?: string | undefined;
      fields?: Partial<Record<"spId" | "entityId" | "config" | "enabled" | "createdAt" | "updatedAt" | "updatedBy" | "tenantId" | "lookupKey", string>> | undefined;
    };
    samlIdpAuditEvent?: {
      modelName?: string | undefined;
      fields?: Partial<Record<"type" | "at" | "spId" | "userId" | "code" | "ipAddress" | "userAgent" | "details" | "expiresAt" | "tenantId", string>> | undefined;
    };
    samlIdpTenant?: {
      modelName?: string | undefined;
      fields?: Partial<Record<"organizationId" | "tenantKey" | "organizationCreatedAt" | "enabled" | "createdAt" | "updatedAt" | "updatedBy", string>> | undefined;
    };
    samlIdpRetiredTenantKey?: {
      modelName?: string | undefined;
      fields?: Partial<Record<"tenantKey" | "organizationId" | "retiredAt" | "retiredBy", string>> | undefined;
    };
    samlIdpTenantKey?: {
      modelName?: string | undefined;
      fields?:
        | Partial<Record<"tenantId" | "kid" | "state" | "stateKey" | "encryptedPrivateKey" | "certificate" | "notAfter" | "createdAt" | "activatedAt" | "updatedBy", string>>
        | undefined;
    };
  };
  /**
   * SAML Single Logout (D-028): SP- and IdP-initiated logout, front-channel, propagated to every
   * SP that received an assertion in the IdP session and has a `singleLogoutService`. Adds the
   * `samlIdpSessionParticipant` table and the `/saml2/idp/slo` and `/saml2/idp/logout` endpoints.
   */
  singleLogout?: { enabled: boolean } | undefined;
  /**
   * Observability (D-038): called after an assertion is issued, a request is refused, or an IdP
   * session is ended by Single Logout. Handlers run in the background and can't affect the flow;
   * a throw is logged. For audit trails, SIEM forwarding and metrics.
   */
  events?: import("./events").SamlIdpEventHandlers | undefined;
  /**
   * Also record those events in the `samlIdpAuditEvent` table (D-038), kept `retentionDays`
   * (default 90) and then swept. Refusals without a signed-in user are not stored (anyone can
   * generate them); they still reach `events.onDenied`.
   */
  auditLog?: import("./events").AuditLogOptions | undefined;
  /**
   * Database-backed SP registry (D-027): SPs stored in the `samlIdpServiceProvider` table, in
   * addition to `serviceProviders`, managed at runtime without a redeploy. Stored SPs are plain
   * JSON (no functions; `attributes` must be a map). SPs in code always win: the registry can't
   * add an SP whose id or entity ID is already defined in code.
   */
  registry?: {
    enabled: boolean;
    /**
     * Who may manage stored SPs through the HTTP API (`/saml-idp/service-providers/*`). The API
     * is only mounted when this is set; it requires a signed-in user and keeps Better Auth's
     * origin checks. E.g. `({ user }) => user.role === "admin"`.
     */
    canManage?: ((ctx: { user: SamlIdpUser; session: Session }) => boolean | Promise<boolean>) | undefined;
    /**
     * Use Better Auth's admin-plugin access control: each API action (list, read, create, update,
     * delete on `samlServiceProvider`) must be granted to one of the user's roles; see
     * `samlIdpStatements`. With `canManage` too, both must allow. Mounts the API.
     */
    permissions?: boolean | undefined;
    /** How long an isolate caches a stored SP, and a miss. Default 60 s; 0 to 3600. */
    cacheSeconds?: number | undefined;
    /** `authorize` for stored SPs (functions can't be stored). Default: allow. */
    authorize?: ((ctx: AuthorizeContext) => AuthorizeResult | Promise<AuthorizeResult>) | undefined;
  };
  /**
   * Sign the IdP metadata document (enveloped XML signature with the active signing key).
   * Default false. Useful for SPs and federations that verify metadata signatures.
   */
  signMetadata?: boolean | undefined;
  /**
   * Tell SPs when to end their own session: `SessionNotOnOrAfter` on the AuthnStatement (Core
   * §2.7.2), a bound for when the IdP session ends without the SP being told (D-043). `false`
   * (default): not sent. `"idp-session"`: the IdP session's expiry. `{ maxSeconds }`: that long
   * after issuance, but never past the IdP session's expiry. SPs that honour it (Shibboleth,
   * SimpleSAMLphp) sign the user out then; many SaaS SPs ignore it. Each SP can override it.
   */
  sessionNotOnOrAfter?: SessionLimit | undefined;
  /** Validator run on every inbound SAML message. Default: `libxml2Validator()`. */
  schemaValidator?: SchemaValidator | undefined;
  /**
   * Multi-tenant IdP (D-052), off by default: an IdP identity per Better Auth organization, next
   * to the root one. A tenant has its own entity ID, metadata, and SSO and SLO URLs
   * (`/saml2/idp/{metadata,sso,slo}/<tenantKey>`); in this version all tenants sign with
   * `signing`. The host's administrators create tenants through the registry API; SPs join one
   * with `tenant`, and only the organization's members may sign in to them. Needs the
   * organization plugin, `registry.enabled` and a pinned `baseURL`. Adds the `samlIdpTenant`
   * table and columns to `samlIdpServiceProvider` (and `samlIdpAuditEvent`); see the
   * multi-tenant guide.
   */
  tenants?: TenantOptions | undefined;
}

/** A service provider after option validation, with defaults applied. */
/** `Required<T>` that also removes the `undefined` an optional field may be given explicitly. */
type Defined<T> = { [K in keyof T]-?: Exclude<T[K], undefined> };

export interface ResolvedServiceProvider {
  id: string;
  entityId: string;
  acsUrls: [string, ...string[]];
  nameIdFormat: string;
  /** Host-supplied NameID function; undefined means "use the format's default". */
  nameId: ((user: SamlIdpUser) => string) | undefined;
  /** With `nameId: { field }`: the field, re-checked at issuance (it must not be user-writable). */
  nameIdField: string | undefined;
  attributes: (user: SamlIdpUser, context: AttributeContext, onMissingField?: (field: string) => void) => Record<string, SamlAttributeValue>;
  organization: { slug?: string | undefined; id?: string | undefined; roles?: string[] | undefined } | undefined;
  singleLogoutService: { url: string; binding: "redirect" | "post"; responseUrl?: string } | undefined;
  /** Metadata refresh (D-026); certificates are normalised to a list. */
  metadata: { url: string; refreshSeconds: number; signingCertificates: string[] } | undefined;
  /** The declarative map, when one was configured (for diagnostics). */
  attributeMap: AttributeMap | undefined;
  requestSignatures: RequestSignaturePolicy;
  /** Normalised to a list; empty when none configured. */
  spCertificates: string[];
  allowIdpInitiated: boolean;
  idpInitiatedRelayState: string | undefined;
  allowedRelayStates: string[];
  authorize: (ctx: AuthorizeContext) => AuthorizeResult | Promise<AuthorizeResult>;
  /** Effective signing for this SP (per-SP override, else the global setting). */
  sign: SignedParts;
  /** Present when assertions to this SP are encrypted; the certificate is parsed at startup. */
  encryption?: import("./saml/encrypt").AssertionEncryption | undefined;
  /** Effective `sessionNotOnOrAfter` (per-SP override, else the global setting). */
  sessionNotOnOrAfter: SessionLimit;
  /** The tenant's organization id (D-052); undefined for an SP of the root IdP. */
  tenantId: string | undefined;
}

export interface ResolvedSamlIdpOptions {
  entityId: string;
  baseURL: string | undefined;
  loginPage: string;
  signing: Defined<Omit<SigningConfig, "allowInsecureSha1">> & {
    allowInsecureSha1: boolean;
    /** Parsed once at startup. */
    keyObject: import("node:crypto").KeyObject;
  };
  assertionLifetimeSeconds: number;
  clockSkewSeconds: number;
  pendingRequestTtlSeconds: number;
  relayStateMaxBytes: number;
  authnContextClassRef: string;
  authnContext: AuthnContextOptions | undefined;
  accountPolicy: Defined<NonNullable<SamlIdpOptions["accountPolicy"]>>;
  serviceProviders: ResolvedServiceProvider[];
  schemaValidator: SchemaValidator;
  schema: SamlIdpOptions["schema"];
  signMetadata: boolean;
  singleLogout: boolean;
  sessionNotOnOrAfter: SessionLimit;
  /** Record which SPs got assertions in which session: with Single Logout, or for `onSessionEnded` (D-043). */
  sessionTracking: boolean;
  events: import("./events").SamlIdpEventHandlers | undefined;
  auditLog: { retentionDays: number } | undefined;
  registry: { canManage: NonNullable<SamlIdpOptions["registry"]>["canManage"]; permissions: boolean; cacheMs: number; authorize: ResolvedServiceProvider["authorize"] | undefined } | undefined;
  /** Multi-tenant IdP (D-052); undefined when off. */
  tenants:
    | {
        cacheMs: number;
        perTenantKeys: boolean;
        keyEncryptionSecret: string | undefined;
        minPublishedMs: number;
        /** Phase 3 (D-059): delegated SP management; undefined when off. */
        delegation: { roles: string[]; userFields: string[]; allowMetadataUrl: boolean } | undefined;
      }
    | undefined;
  /** Non-fatal configuration warnings, logged once at startup. */
  warnings: string[];
}

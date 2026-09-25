import type { Session, User } from "better-auth";
import type { SchemaValidator } from "./saml/validator";

export type { SchemaKind, SchemaValidationResult, SchemaValidator } from "./saml/validator";

export type SignatureAlgorithm = "rsa-sha256" | "rsa-sha512" | "rsa-sha1";
export type DigestAlgorithm = "sha256" | "sha512" | "sha1";

/** A Better Auth user, including any additional fields configured on the user table. */
export type SamlIdpUser = User & Record<string, unknown>;

export type SamlAttributeValue = string | string[];

export interface AuthorizeContext {
  user: SamlIdpUser;
  session: Session;
  serviceProvider: ResolvedServiceProvider;
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
export type AttributeSource = string | { field: string; split?: string; part?: "first" | "last" } | { value: string | string[] };
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
  nameIdFormat?: string;
  /**
   * Value of `<NameID>`. Default depends on `nameIdFormat`:
   * - emailAddress / unspecified: the user's (verified) email;
   * - persistent: an opaque, stable, per-SP identifier (HMAC of the user id, keyed with the
   *   Better Auth secret) that is never re-assigned to another user;
   * - transient: a new random identifier for every assertion.
   */
  nameId?: (user: SamlIdpUser) => string;
  /**
   * Attributes to include in the `<AttributeStatement>`: a function, or a declarative map from
   * attribute name to source (usable from JSON configuration), e.g.
   * `{ email: "email", groups: { field: "role", split: "," }, firstName: { field: "name", part: "first" } }`.
   */
  attributes?: ((user: SamlIdpUser) => Record<string, SamlAttributeValue>) | AttributeMap;
  /** Reject unsigned AuthnRequests from this SP. Requires `spCertificate`. */
  requireSignedAuthnRequests?: boolean;
  /**
   * PEM X.509 certificate(s) the SP signs AuthnRequests with. Pass several during the SP's key
   * rotation (e.g. Cloudflare Access publishes two); a signature from any of them is accepted.
   */
  spCertificate?: string | string[];
  /**
   * Allow IdP-initiated (unsolicited) SSO to this SP via `GET /saml2/idp/init?sp=<id>`.
   * Default false. The Response carries no `InResponseTo`, so the SP must accept unsolicited
   * Responses and track assertion IDs itself (docs/security.md).
   */
  allowIdpInitiated?: boolean;
  /**
   * RelayState sent with IdP-initiated Responses when the caller supplies none, or one that is
   * not in `allowedRelayStates` (commonly the SP-side landing URL). Requires `allowIdpInitiated`.
   */
  idpInitiatedRelayState?: string;
  /**
   * Caller-supplied `RelayState` values accepted on `/saml2/idp/init`, matched exactly. Any
   * other value is ignored (the default above is used): an IdP-initiated RelayState is usually
   * a redirect target at the SP, so accepting arbitrary values would make the IdP an
   * open-redirect launcher for the SP. Requires `allowIdpInitiated`.
   */
  allowedRelayStates?: string[];
  /** Decide whether this user may use this SP. Denial issues no assertion. */
  authorize?: (ctx: AuthorizeContext) => boolean | Promise<boolean>;
  /**
   * Keep this SP's certificates current from its metadata URL (D-026). Only certificates are
   * taken from it: signing certificates (added to `spCertificate`) and, when `encryption` is on,
   * the encryption certificate (replacing `encryption.certificate`). The entity ID and ACS URLs
   * stay as configured here, so the metadata can never redirect assertions.
   */
  metadata?: {
    /** https only. Fetched with a 5 s timeout, redirects not followed, at most 1 MiB. */
    url: string;
    /** Default 86400 (a day); 300 to 604800. */
    refreshSeconds?: number;
    /**
     * Pin the metadata's own signature (recommended; required by federations). When set,
     * unsigned or wrongly signed metadata is rejected and the last good copy is kept.
     */
    signingCertificate?: string | string[];
  };
  /** Override the global `signing.signResponse` for this SP. */
  signResponse?: boolean;
  /** Override the global `signing.signAssertion` for this SP. At least one must stay on. */
  signAssertion?: boolean;
  /**
   * Encrypt the assertion to this SP (`<saml:EncryptedAssertion>`, XML Encryption 1.1).
   * The assertion is signed first, then encrypted, then the Response is signed
   * ("sign-then-encrypt"); with encryption on, the assertion is always signed when
   * `signResponse` is false. Omit to send plaintext assertions.
   */
  encryption?: ServiceProviderEncryptionConfig;
}

export interface ServiceProviderEncryptionConfig {
  /** The SP's PEM X.509 encryption certificate (RSA ≥ 2048 bits). */
  certificate: string;
  /** Content encryption. Default `aes256-gcm`. `aes256-cbc` also needs `allowInsecureCbc: true`. */
  dataAlgorithm?: "aes256-gcm" | "aes128-gcm" | "aes256-cbc";
  /**
   * Key transport. Default `rsa-oaep` (`xmlenc#rsa-oaep-mgf1p`, SHA-1/MGF1-SHA1, the most widely
   * supported). `rsa-oaep-sha256` is `xmlenc11#rsa-oaep` with SHA-256 and MGF1-SHA256.
   * RSA PKCS#1 v1.5 is not available.
   */
  keyAlgorithm?: "rsa-oaep" | "rsa-oaep-sha256";
  /** Explicit opt-in to AES-CBC for SPs without GCM (padding-oracle history). Logs a warning. */
  allowInsecureCbc?: boolean;
}

export interface SigningConfig {
  /** PEM private key (PKCS#1 or PKCS#8, unencrypted, RSA ≥ 2048 bits). */
  privateKey: string;
  /** PEM X.509 certificate matching `privateKey`. */
  certificate: string;
  /** Extra certificates published in metadata, e.g. the next key during rotation. */
  additionalCertificates?: string[];
  /** Default `rsa-sha256`. `rsa-sha1` also needs `allowInsecureSha1: true`. */
  signatureAlgorithm?: SignatureAlgorithm;
  /** Default `sha256`. `sha1` also needs `allowInsecureSha1: true`. */
  digestAlgorithm?: DigestAlgorithm;
  /** Explicit opt-in to SHA-1 for legacy SPs. Logs a warning at startup. */
  allowInsecureSha1?: boolean;
  /** Sign the `<Response>`. Default true. */
  signResponse?: boolean;
  /** Sign the `<Assertion>`. Default true. */
  signAssertion?: boolean;
}

export interface SamlIdpOptions {
  /** The IdP entity ID, usually `https://<host>/<basePath>/saml2/idp`. */
  entityId: string;
  /**
   * The Better Auth base URL the IdP's own URLs (SSO endpoint in metadata, resume URL,
   * expected `Destination`) are built from, e.g. `https://auth.example.com/api/auth`.
   * Strongly recommended: without it they follow the request's Host header.
   */
  baseURL?: string;
  /** Where unauthenticated users are sent. Path on this origin, or an absolute URL. */
  loginPage: string;
  signing: SigningConfig;
  /** Assertion validity window. Default 300 s. */
  assertionLifetimeSeconds?: number;
  /** Tolerance applied to `NotBefore` and request `IssueInstant`. Default 60 s. */
  clockSkewSeconds?: number;
  /** How long a stored AuthnRequest waits for the user to sign in. Default 600 s. */
  pendingRequestTtlSeconds?: number;
  /**
   * Maximum RelayState size in bytes. Default (and hard cap) 1024. SAML Bindings §3.4.3 says
   * 80, but real SPs send more — Cloudflare Access does (DECISIONS.md D-016). Set 80 for
   * strict spec behaviour. RelayState is opaque to the IdP and always HTML-escaped.
   */
  relayStateMaxBytes?: number;
  /**
   * The `AuthnContextClassRef` asserted, and matched against an SP's
   * `RequestedAuthnContext`. Default `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`.
   * Set it to what your sign-in actually guarantees, e.g. `...:PasswordProtectedTransport`.
   */
  authnContextClassRef?: string;
  /**
   * Who may receive assertions. Defaults are strict: an IdP vouches for identities.
   */
  accountPolicy?: {
    /** Refuse users whose email is not verified. Default true. */
    requireEmailVerified?: boolean;
    /** Allow sessions created by admin impersonation (`impersonatedBy`). Default false. */
    allowImpersonatedSessions?: boolean;
    /** Allow anonymous-plugin users (`isAnonymous`). Default false. */
    allowAnonymousUsers?: boolean;
  };
  serviceProviders: ServiceProviderConfig[];
  /**
   * Rename the plugin's table or columns, as with other Better Auth plugins.
   * Field maps use schema property keys (e.g. Drizzle keys), not raw column names.
   */
  schema?: {
    samlIdpSeenRequest?: {
      modelName?: string;
      fields?: Partial<Record<"key" | "spId" | "requestId" | "expiresAt", string>>;
    };
  };
  /**
   * Sign the IdP metadata document (enveloped XML signature with the active signing key).
   * Default false. Useful for SPs and federations that verify metadata signatures.
   */
  signMetadata?: boolean;
  /** Validator run on every inbound SAML message. Default: `libxml2Validator()`. */
  schemaValidator?: SchemaValidator;
}

/** A service provider after option validation, with defaults applied. */
export interface ResolvedServiceProvider {
  id: string;
  entityId: string;
  acsUrls: [string, ...string[]];
  nameIdFormat: string;
  /** Host-supplied NameID function; undefined means "use the format's default". */
  nameId: ((user: SamlIdpUser) => string) | undefined;
  attributes: (user: SamlIdpUser, onMissingField?: (field: string) => void) => Record<string, SamlAttributeValue>;
  /** Metadata refresh (D-026); certificates are normalised to a list. */
  metadata: { url: string; refreshSeconds: number; signingCertificates: string[] } | undefined;
  /** The declarative map, when one was configured (for diagnostics). */
  attributeMap: AttributeMap | undefined;
  requireSignedAuthnRequests: boolean;
  /** Normalised to a list; empty when none configured. */
  spCertificates: string[];
  allowIdpInitiated: boolean;
  idpInitiatedRelayState: string | undefined;
  allowedRelayStates: string[];
  authorize: (ctx: AuthorizeContext) => boolean | Promise<boolean>;
  /** Effective signing for this SP (per-SP override, else the global setting). */
  signResponse: boolean;
  signAssertion: boolean;
  /** Present when assertions to this SP are encrypted; the certificate is parsed at startup. */
  encryption?: import("./saml/encrypt").AssertionEncryption;
}

export interface ResolvedSamlIdpOptions {
  entityId: string;
  baseURL: string | undefined;
  loginPage: string;
  signing: Required<Omit<SigningConfig, "allowInsecureSha1">> & {
    allowInsecureSha1: boolean;
    /** Parsed once at startup. */
    keyObject: import("node:crypto").KeyObject;
  };
  assertionLifetimeSeconds: number;
  clockSkewSeconds: number;
  pendingRequestTtlSeconds: number;
  relayStateMaxBytes: number;
  authnContextClassRef: string;
  accountPolicy: Required<NonNullable<SamlIdpOptions["accountPolicy"]>>;
  serviceProviders: ResolvedServiceProvider[];
  schemaValidator: SchemaValidator;
  schema: SamlIdpOptions["schema"];
  signMetadata: boolean;
  /** Non-fatal configuration warnings, logged once at startup. */
  warnings: string[];
}

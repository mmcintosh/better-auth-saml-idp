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

export interface ServiceProviderConfig {
  /** Stable identifier used in logs and in `/saml2/idp/init?sp=` (stretch goal). */
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
  /** Value of `<NameID>`. Defaults to `user.email`. */
  nameId?: (user: SamlIdpUser) => string;
  /** Attributes to include in the `<AttributeStatement>`. */
  attributes?: (user: SamlIdpUser) => Record<string, SamlAttributeValue>;
  /** Reject unsigned AuthnRequests from this SP. Requires `spCertificate`. */
  requireSignedAuthnRequests?: boolean;
  /** PEM X.509 certificate the SP signs AuthnRequests with. */
  spCertificate?: string;
  /** IdP-initiated SSO. Not implemented in v1; must be false. */
  allowIdpInitiated?: boolean;
  /** Decide whether this user may use this SP. Denial issues no assertion. */
  authorize?: (ctx: AuthorizeContext) => boolean | Promise<boolean>;
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
   * Maximum RelayState size in bytes. The SAML bindings spec says 80; some SPs send
   * more. Default 80, hard cap 1024.
   */
  relayStateMaxBytes?: number;
  serviceProviders: ServiceProviderConfig[];
  /**
   * Rename the plugin's table or columns, as with other Better Auth plugins.
   * Field maps use schema property keys (e.g. Drizzle keys), not raw column names.
   */
  schema?: {
    samlIdpSeenRequest?: {
      modelName?: string;
      fields?: Partial<Record<"spId" | "requestId" | "expiresAt", string>>;
    };
  };
  /** Validator run on every inbound SAML message. Default: `libxml2Validator()`. */
  schemaValidator?: SchemaValidator;
}

/** A service provider after option validation, with defaults applied. */
export interface ResolvedServiceProvider {
  id: string;
  entityId: string;
  acsUrls: [string, ...string[]];
  nameIdFormat: string;
  nameId: (user: SamlIdpUser) => string;
  attributes: (user: SamlIdpUser) => Record<string, SamlAttributeValue>;
  requireSignedAuthnRequests: boolean;
  spCertificate: string | undefined;
  allowIdpInitiated: boolean;
  authorize: (ctx: AuthorizeContext) => boolean | Promise<boolean>;
}

export interface ResolvedSamlIdpOptions {
  entityId: string;
  loginPage: string;
  signing: Required<Omit<SigningConfig, "allowInsecureSha1">> & { allowInsecureSha1: boolean };
  assertionLifetimeSeconds: number;
  clockSkewSeconds: number;
  pendingRequestTtlSeconds: number;
  relayStateMaxBytes: number;
  serviceProviders: ResolvedServiceProvider[];
  schemaValidator: SchemaValidator;
  schema: SamlIdpOptions["schema"];
  /** Non-fatal configuration warnings, logged once at startup. */
  warnings: string[];
}

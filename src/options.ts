import { compileAttributeMap } from "./attributes";
import { nameIdFromField } from "./nameid";
import { type KeyObject, X509Certificate, createPrivateKey, createPublicKey } from "node:crypto";
import * as z from "zod";
import type { AssertionEncryption } from "./saml/encrypt";
import { defaultSchemaValidator } from "./saml/validator";
import type {
  ResolvedSamlIdpOptions,
  ResolvedServiceProvider,
  SamlIdpOptions,
  SamlIdpUser,
  AttributeSource,
  SignedParts,
  SessionLimit,
} from "./types";

export const NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
export const AUTHN_CONTEXT_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
export const RELAY_STATE_HARD_CAP = 1024;

export class SamlIdpConfigError extends Error {
  constructor(readonly issues: string[]) {
    super(`Invalid samlIdp options:\n${issues.map((i) => `  - ${i}`).join("\n")}`);
    this.name = "SamlIdpConfigError";
  }
}

const fn = <T extends (...args: any[]) => any>() =>
  z.custom<T>((v) => typeof v === "function", { message: "must be a function" });

const pem = (label: string) =>
  z
    .string()
    .refine((v) => new RegExp(`-----BEGIN ${label}-----[\\s\\S]+-----END ${label}-----`).test(v), {
      message: `must be a PEM ${label}`,
    });

const privateKeyPem = z
  .string()
  .refine((v) => !/ENCRYPTED PRIVATE KEY/.test(v), { message: "encrypted private keys are not supported" })
  .refine((v) => /-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]+-----END (RSA )?PRIVATE KEY-----/.test(v), {
    message: "must be a PEM private key (PKCS#1 or PKCS#8)",
  });

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

const acsUrl = z.string().superRefine((v, ctx) => {
  let url: URL;
  try {
    url = new URL(v);
  } catch {
    ctx.addIssue({ code: "custom", message: `"${v}" is not an absolute URL` });
    return;
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname)))
    ctx.addIssue({ code: "custom", message: `"${v}" must use https (http is allowed only for localhost)` });
  if (url.hash) ctx.addIssue({ code: "custom", message: `"${v}" must not contain a fragment` });
  if (url.username || url.password) ctx.addIssue({ code: "custom", message: `"${v}" must not contain credentials` });
});

const FIELD_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const FIELD_MESSAGE = "must be a user field name (letters, digits, _), e.g. \"email\" or \"role\"";
/** One map entry; checked by hand so a mistake gets a specific message rather than "Invalid input". */
const attributeSource = z.custom<AttributeSource>(() => true).superRefine((v, ctx) => {
  const issue = (message: string, path: (string | number)[] = []) => ctx.addIssue({ code: "custom", message, path });
  if (typeof v === "string") {
    if (!FIELD_NAME.test(v)) issue(FIELD_MESSAGE);
    return;
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return issue('must be a field name, { field, split?, part? }, { value } or { organization }');
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  if ("organization" in o) {
    for (const k of keys) if (k !== "organization" && k !== "only") issue(`unknown key "${k}" (expected organization, only)`);
    if (!["slugs", "names", "ids", "roles"].includes(o.organization as string)) issue('must be "slugs", "names", "ids" or "roles"', ["organization"]);
    if (o.only !== undefined && !(Array.isArray(o.only) && o.only.length > 0 && o.only.length <= 100 && o.only.every((x) => typeof x === "string" && x.length > 0)))
      issue("must be a non-empty array of organization ids or slugs (at most 100)", ["only"]);
    return;
  }
  if ("value" in o) {
    if (keys.length !== 1) issue("{ value } takes no other keys");
    const ok = typeof o.value === "string" || (Array.isArray(o.value) && o.value.length > 0 && o.value.every((x) => typeof x === "string"));
    if (!ok) issue("must be a string or a non-empty array of strings", ["value"]);
    return;
  }
  for (const k of keys) if (!["field", "split", "part"].includes(k)) issue(`unknown key "${k}" (expected field, split, part)`);
  if (typeof o.field !== "string" || !FIELD_NAME.test(o.field)) issue(FIELD_MESSAGE, ["field"]);
  if (o.split !== undefined && (typeof o.split !== "string" || o.split.length < 1 || o.split.length > 8)) issue("must be a 1-8 character separator", ["split"]);
  if (o.part !== undefined && o.part !== "first" && o.part !== "last") issue('must be "first" or "last"', ["part"]);
});
const nameIdSourceSchema = z.object({ field: z.string().regex(FIELD_NAME, FIELD_MESSAGE) }).strict();
const attributeMapSchema = z.record(z.string().min(1, "attribute names can't be empty").max(256), attributeSource);

const serviceProviderShape = z.object({
    id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/, "must be 1-64 characters of A-Z a-z 0-9 _ -"),
    entityId: z.string().min(1).max(1024),
    acsUrls: z.array(acsUrl).min(1, "must list at least one ACS URL"),
    nameIdFormat: z.string().min(1).optional(),
    nameId: z.union([fn<(user: SamlIdpUser) => string>(), nameIdSourceSchema]).optional(),
    attributes: z.union([fn<(user: SamlIdpUser) => Record<string, string | string[]>>(), attributeMapSchema]).optional(),
    requestSignatures: z.enum(["require", "verify-if-signed", "ignore"]).optional(),
    spCertificates: z.union([pem("CERTIFICATE"), z.array(pem("CERTIFICATE")).min(1)]).optional(),
    allowIdpInitiated: z.boolean().optional(),
    idpInitiatedRelayState: z.string().min(1).optional(),
    allowedRelayStates: z.array(z.string().min(1)).optional(),
    authorize: fn<ResolvedServiceProvider["authorize"]>().optional(),
    sign: z.enum(["both", "response", "assertion"]).optional(),
    organization: z
      .object({ slug: z.string().min(1).max(256).optional(), id: z.string().min(1).max(256).optional(), roles: z.array(z.string().min(1).max(128)).min(1).optional() })
      .strict()
      .refine((o) => (o.slug === undefined) !== (o.id === undefined), { message: "give exactly one of slug and id" })
      .optional(),
    singleLogoutService: z.object({ url: acsUrl, binding: z.enum(["redirect", "post"]).optional(), responseUrl: acsUrl.optional() }).strict().optional(),
    metadata: z
      .object({
        url: z.url({ protocol: /^https$/, error: "must be an https:// URL" }),
        refreshSeconds: z.number().int().min(300).max(7 * 86400).optional(),
        signingCertificates: z.union([pem("CERTIFICATE"), z.array(pem("CERTIFICATE")).min(1)]).optional(),
      })
      .strict()
      .optional(),
    sessionNotOnOrAfter: z.union([z.literal(false), z.literal("idp-session"), z.object({ maxSeconds: z.number().int().min(60).max(30 * 86400) }).strict()]).optional(),
    encryption: z
      .object({
        certificate: pem("CERTIFICATE"),
        dataAlgorithm: z.enum(["aes256-gcm", "aes128-gcm", "aes256-cbc"]).optional(),
        // No "rsa-1_5": PKCS#1 v1.5 key transport is not offered at all.
        keyAlgorithm: z.enum(["rsa-oaep", "rsa-oaep-sha256"]).optional(),
        allowInsecureCbc: z.boolean().optional(),
      })
      .strict()
      .optional(),
    tenant: z.string().min(1).max(256).optional(),
});

type SpRefinable = Pick<
  z.infer<typeof serviceProviderShape>,
  "requestSignatures" | "spCertificates" | "metadata" | "allowIdpInitiated" | "idpInitiatedRelayState" | "allowedRelayStates" | "encryption"
>;

function refineServiceProvider(sp: SpRefinable, ctx: z.RefinementCtx) {
    const hasCerts = sp.spCertificates !== undefined || sp.metadata !== undefined;
    if ((sp.requestSignatures === "require" || sp.requestSignatures === "verify-if-signed") && !hasCerts)
      ctx.addIssue({ code: "custom", path: ["spCertificates"], message: `is required when requestSignatures is "${sp.requestSignatures}" (or set metadata.url)` });
    // "ignore" means the certificates are never used: almost certainly not what was meant.
    if (sp.requestSignatures === "ignore" && sp.spCertificates !== undefined)
      ctx.addIssue({ code: "custom", path: ["requestSignatures"], message: 'is "ignore", so spCertificates would never be checked; remove one of them' });
    // RelayState settings only apply to IdP-initiated SSO; setting them without the opt-in is
    // almost certainly a mistake (the host believes IdP-initiated SSO is on).
    for (const key of ["idpInitiatedRelayState", "allowedRelayStates"] as const)
      if (sp[key] !== undefined && !sp.allowIdpInitiated)
        ctx.addIssue({ code: "custom", path: [key], message: "requires allowIdpInitiated: true" });
    if (sp.encryption?.dataAlgorithm === "aes256-cbc" && !sp.encryption.allowInsecureCbc)
      ctx.addIssue({
        code: "custom",
        path: ["encryption", "dataAlgorithm"],
        message:
          "AES-CBC is vulnerable to padding-oracle attacks; use aes256-gcm, or set encryption.allowInsecureCbc: true for an SP that cannot do GCM",
      });
}

const serviceProviderSchema = serviceProviderShape.strict().superRefine(refineServiceProvider);

/**
 * An SP stored in the database registry (D-027): the same options minus functions, so it is
 * plain JSON. `attributes` is a declarative map only.
 */
export const storedServiceProviderSchema = serviceProviderShape
  .omit({ nameId: true, authorize: true })
  .extend({ attributes: attributeMapSchema.optional(), nameId: nameIdSourceSchema.optional() })
  .strict()
  .superRefine(refineServiceProvider);
export type StoredServiceProviderConfig = z.infer<typeof storedServiceProviderSchema>;

const optionsSchema = z
  .object({
    entityId: z.string().min(1).max(1024),
    baseURL: z
      .string()
      .refine((v) => /^https?:\/\/[^/?#\s\\]+(\/[^?#\s\\]*)?$/.test(v), { message: "must be an absolute http(s) URL without query or fragment" })
      .optional(),
    loginPage: z
      .string()
      // Browsers treat "\" like "/" in URLs ("/\\evil.example" → "//evil.example"), so reject it
      // along with control characters and whitespace.
      // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
      .refine((v) => !/[\\\s\u0000-\u001f\u007f]/.test(v), { message: "must not contain backslashes, whitespace or control characters" })
      .refine((v) => (v.startsWith("/") && !v.startsWith("//")) || /^https?:\/\//.test(v), {
        message: "must be a path starting with / or an absolute http(s) URL",
      }),
    signing: z
      .object({
        privateKey: privateKeyPem,
        certificate: pem("CERTIFICATE"),
        additionalCertificates: z.array(pem("CERTIFICATE")).optional(),
        signatureAlgorithm: z.enum(["rsa-sha256", "rsa-sha512", "rsa-sha1"]).optional(),
        digestAlgorithm: z.enum(["sha256", "sha512", "sha1"]).optional(),
        allowInsecureSha1: z.boolean().optional(),
        sign: z.enum(["both", "response", "assertion"]).optional(),
      })
      .strict(),
    assertionLifetimeSeconds: z.number().int().min(30).max(3600).optional(),
    clockSkewSeconds: z.number().int().min(0).max(300).optional(),
    pendingRequestTtlSeconds: z.number().int().min(60).max(3600).optional(),
    relayStateMaxBytes: z.number().int().min(80).max(RELAY_STATE_HARD_CAP).optional(),
    authnContextClassRef: z.string().min(1).max(1024).optional(),
    authnContext: z
      .object({
        levels: z
          .array(z.string().min(1).max(1024))
          .min(1)
          .max(10)
          .refine((l) => new Set(l).size === l.length, { message: "levels must be unique" }),
        current: fn<(ctx: { user: SamlIdpUser; session: any }) => string | Promise<string>>(),
      })
      .strict()
      .optional(),
    accountPolicy: z
      .object({
        requireEmailVerified: z.boolean().optional(),
        allowImpersonatedSessions: z.boolean().optional(),
        allowAnonymousUsers: z.boolean().optional(),
      })
      .strict()
      .optional(),
    serviceProviders: z.array(serviceProviderSchema),
    schema: z
      .object({
        samlIdpSeenRequest: z
          .object({
            modelName: z.string().min(1).optional(),
            fields: z
              .object({ key: z.string().min(1), spId: z.string().min(1), requestId: z.string().min(1), expiresAt: z.string().min(1) })
              .partial()
              .strict()
              .optional(),
          })
          .strict()
          .optional(),
        samlIdpSessionParticipant: z
          .object({
            modelName: z.string().min(1).optional(),
            fields: z
              .object({
                key: z.string().min(1),
                sessionKey: z.string().min(1),
                spId: z.string().min(1),
                nameId: z.string().min(1),
                nameIdFormat: z.string().min(1),
                sessionIndex: z.string().min(1),
                expiresAt: z.string().min(1),
              })
              .partial()
              .strict()
              .optional(),
          })
          .strict()
          .optional(),
        samlIdpServiceProvider: z
          .object({
            modelName: z.string().min(1).optional(),
            fields: z
              .object({
                spId: z.string().min(1),
                entityId: z.string().min(1),
                config: z.string().min(1),
                enabled: z.string().min(1),
                createdAt: z.string().min(1),
                updatedAt: z.string().min(1),
                updatedBy: z.string().min(1),
                tenantId: z.string().min(1),
                lookupKey: z.string().min(1),
              })
              .partial()
              .strict()
              .optional(),
          })
          .strict()
          .optional(),
        samlIdpAuditEvent: z
          .object({
            modelName: z.string().min(1).optional(),
            fields: z
              .object(Object.fromEntries(["type", "at", "spId", "userId", "code", "ipAddress", "userAgent", "details", "expiresAt", "tenantId"].map((f) => [f, z.string().min(1)])))
              .partial()
              .strict()
              .optional(),
          })
          .strict()
          .optional(),
        samlIdpTenant: z
          .object({
            modelName: z.string().min(1).optional(),
            fields: z
              .object(Object.fromEntries(["organizationId", "tenantKey", "organizationCreatedAt", "enabled", "createdAt", "updatedAt", "updatedBy"].map((f) => [f, z.string().min(1)])))
              .partial()
              .strict()
              .optional(),
          })
          .strict()
          .optional(),
        samlIdpRetiredTenantKey: z
          .object({
            modelName: z.string().min(1).optional(),
            fields: z
              .object(Object.fromEntries(["tenantKey", "organizationId", "retiredAt", "retiredBy"].map((f) => [f, z.string().min(1)])))
              .partial()
              .strict()
              .optional(),
          })
          .strict()
          .optional(),
        samlIdpTenantKey: z
          .object({
            modelName: z.string().min(1).optional(),
            fields: z
              .object(
                Object.fromEntries(
                  ["tenantId", "kid", "state", "stateKey", "encryptedPrivateKey", "certificate", "notAfter", "createdAt", "activatedAt", "updatedBy"].map((f) => [f, z.string().min(1)]),
                ),
              )
              .partial()
              .strict()
              .optional(),
          })
          .strict()
          .optional(),
      })
      .strict()
      .optional(),
    signMetadata: z.boolean().optional(),
    sessionNotOnOrAfter: z.union([z.literal(false), z.literal("idp-session"), z.object({ maxSeconds: z.number().int().min(60).max(30 * 86400) }).strict()]).optional(),
    singleLogout: z.object({ enabled: z.boolean() }).strict().optional(),
    events: z
      .object({
        onAssertionIssued: fn<NonNullable<NonNullable<SamlIdpOptions["events"]>["onAssertionIssued"]>>().optional(),
        onDenied: fn<NonNullable<NonNullable<SamlIdpOptions["events"]>["onDenied"]>>().optional(),
        onLogout: fn<NonNullable<NonNullable<SamlIdpOptions["events"]>["onLogout"]>>().optional(),
        onSessionEnded: fn<NonNullable<NonNullable<SamlIdpOptions["events"]>["onSessionEnded"]>>().optional(),
        onTenantChanged: fn<NonNullable<NonNullable<SamlIdpOptions["events"]>["onTenantChanged"]>>().optional(),
        onServiceProviderChanged: fn<NonNullable<NonNullable<SamlIdpOptions["events"]>["onServiceProviderChanged"]>>().optional(),
      })
      .strict()
      .optional(),
    auditLog: z.object({ enabled: z.boolean(), retentionDays: z.number().int().min(1).max(3650).optional() }).strict().optional(),
    registry: z
      .object({
        enabled: z.boolean(),
        canManage: fn<NonNullable<NonNullable<SamlIdpOptions["registry"]>["canManage"]>>().optional(),
        permissions: z.boolean().optional(),
        cacheSeconds: z.number().int().min(0).max(3600).optional(),
        authorize: fn<ResolvedServiceProvider["authorize"]>().optional(),
      })
      .strict()
      .optional(),
    tenants: z
      .object({
        enabled: z.boolean(),
        keys: z.enum(["shared", "per-tenant"]).optional(),
        keyEncryptionSecret: z.string().min(32).optional(),
        minPublishedSeconds: z.number().int().min(0).max(31_536_000).optional(),
        delegation: z
          .object({
            roles: z.array(z.string().min(1).max(64)).min(1).max(20).optional(),
            userFields: z.array(z.string().min(1).max(64)).max(100).optional(),
            allowMetadataUrl: z.boolean().optional(),
          })
          .strict()
          .optional(),
        cacheSeconds: z.number().int().min(0).max(3600).optional(),
      })
      .strict()
      .optional(),
    schemaValidator: z
      .custom<ResolvedSamlIdpOptions["schemaValidator"]>(
        (v) => typeof v === "object" && v !== null && typeof (v as any).validate === "function",
        { message: "must be an object with a validate(xml, kind) method" },
      )
      .optional(),
  })
  .strict();

function formatIssues(error: z.ZodError): string[] {
  return error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
}

const EXPIRY_WARNING_DAYS = 30;

/**
 * Checks that need crypto: key type/size and that the key matches the certificate.
 * Expiry only warns: failing here would take every Better Auth route down the moment a
 * (possibly publish-only rotation) certificate expires.
 */
function checkKeyMaterial(o: SamlIdpOptions, warnings: string[]): { issues: string[]; key?: KeyObject } {
  const issues: string[] = [];
  let publicFromKey: string;
  let key: KeyObject;
  try {
    key = createPrivateKey(o.signing.privateKey);
    if (key.asymmetricKeyType !== "rsa") issues.push(`signing.privateKey: must be an RSA key, got ${key.asymmetricKeyType}`);
    const bits = key.asymmetricKeyDetails?.modulusLength;
    if (bits !== undefined && bits < 2048) issues.push(`signing.privateKey: RSA key must be at least 2048 bits, got ${bits}`);
    publicFromKey = createPublicKey(key).export({ type: "spki", format: "pem" }).toString();
  } catch (e) {
    return { issues: [`signing.privateKey: could not be parsed (${(e as Error).message})`] };
  }
  const certs: [string, string][] = [
    ["signing.certificate", o.signing.certificate],
    ...(o.signing.additionalCertificates ?? []).map((c, i): [string, string] => [`signing.additionalCertificates.${i}`, c]),
  ];
  for (const [path, pemText] of certs) {
    try {
      const cert = new X509Certificate(pemText);
      if (path === "signing.certificate") {
        const publicFromCert = cert.publicKey.export({ type: "spki", format: "pem" }).toString();
        if (publicFromCert !== publicFromKey) issues.push(`${path}: does not match signing.privateKey`);
      }
      const validTo = new Date(cert.validTo).getTime();
      if (validTo < Date.now()) warnings.push(`${path}: EXPIRED on ${cert.validTo}; SPs that check validity will reject it`);
      else if (validTo < Date.now() + EXPIRY_WARNING_DAYS * 86_400_000)
        warnings.push(`${path}: expires on ${cert.validTo} (within ${EXPIRY_WARNING_DAYS} days); plan a rotation`);
    } catch (e) {
      issues.push(`${path}: could not be parsed (${(e as Error).message})`);
    }
  }
  return { issues, key };
}

/**
 * An SP's encryption certificate: parse it, require RSA ≥ 2048 bits (OAEP key transport),
 * and warn (not fail) on expiry, as for signing certificates.
 */
export function checkEncryptionCertificate(
  path: string,
  pemText: string,
  issues: string[],
  warnings: string[],
): Pick<AssertionEncryption, "publicKeyPem" | "certificateBase64"> | undefined {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pemText);
  } catch (e) {
    issues.push(`${path}: could not be parsed (${(e as Error).message})`);
    return undefined;
  }
  const publicKey = cert.publicKey;
  if (publicKey.asymmetricKeyType !== "rsa") {
    issues.push(`${path}: must be an RSA certificate, got ${publicKey.asymmetricKeyType}`);
    return undefined;
  }
  const bits = publicKey.asymmetricKeyDetails?.modulusLength;
  if (bits !== undefined && bits < 2048) {
    issues.push(`${path}: RSA key must be at least 2048 bits, got ${bits}`);
    return undefined;
  }
  const validTo = new Date(cert.validTo).getTime();
  if (validTo < Date.now()) warnings.push(`${path}: EXPIRED on ${cert.validTo}; the SP may no longer hold its key`);
  else if (validTo < Date.now() + EXPIRY_WARNING_DAYS * 86_400_000)
    warnings.push(`${path}: expires on ${cert.validTo} (within ${EXPIRY_WARNING_DAYS} days); ask the SP for its next certificate`);
  const der = new Uint8Array(cert.raw);
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  // Kept as SPKI PEM: on workerd, publicEncrypt() rejects KeyObjects ("Received an instance of
  // PublicKeyObject"). Round-tripping through createPublicKey proves the PEM parses.
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  createPublicKey(publicKeyPem);
  return { publicKeyPem, certificateBase64: btoa(bin) };
}

type ParsedServiceProvider = z.infer<typeof serviceProviderSchema> | StoredServiceProviderConfig;

interface SpDefaults {
  sign: SignedParts;
  sessionNotOnOrAfter: SessionLimit;
  relayStateMaxBytes: number;
  authorize?: ResolvedServiceProvider["authorize"] | undefined;
  /** `tenants.enabled` (D-052). */
  tenants: boolean;
}

/**
 * A tenant SP's organization rule (D-052): membership of the tenant's organization is implied
 * and can't be turned off; an explicit rule may only name the same organization by id, to add
 * `roles`. A slug could name another organization later (slugs change), so it is refused.
 */
function tenantOrganization(sp: ParsedServiceProvider, path: string, d: SpDefaults, issues: string[]): ResolvedServiceProvider["organization"] {
  if (sp.tenant === undefined) return sp.organization;
  if (!d.tenants) issues.push(`${path}.tenant: requires tenants.enabled`);
  const rule = sp.organization;
  if (rule && (rule.slug !== undefined || rule.id !== sp.tenant))
    issues.push(`${path}.organization: a tenant SP's members are its tenant's; give { id: "${sp.tenant}", roles } to narrow by role, or leave it out`);
  return { id: sp.tenant, ...(rule?.roles ? { roles: rule.roles } : {}) };
}

/** Per-SP checks and defaults, shared by code SPs and database-registry SPs. */
function resolveServiceProvider(sp: ParsedServiceProvider, path: string, d: SpDefaults, issues: string[], warnings: string[]): ResolvedServiceProvider {
  // "ignore" + metadata: the metadata's signing certificates are never used, so logout requests
  // are authenticated by SessionIndex alone (pre-release review L-2). Legitimate when metadata is
  // only for the encryption certificate; say so.
  if (sp.requestSignatures === "ignore" && sp.metadata)
    warnings.push(`${path}: requestSignatures is "ignore", so the signing certificates from metadata are never checked and LogoutRequests are authenticated by SessionIndex alone`);
  if (sp.metadata && sp.metadata.signingCertificates === undefined)
    warnings.push(`${path}.metadata: the metadata's signature isn't pinned (signingCertificates); its certificates are trusted on TLS alone`);

  const relayValues: [string, string][] = [
    ...(sp.idpInitiatedRelayState !== undefined ? [["idpInitiatedRelayState", sp.idpInitiatedRelayState] as [string, string]] : []),
    ...(sp.allowedRelayStates ?? []).map((v, j): [string, string] => [`allowedRelayStates.${j}`, v]),
  ];
  for (const [p, v] of relayValues)
    if (new TextEncoder().encode(v).byteLength > d.relayStateMaxBytes) issues.push(`${path}.${p}: exceeds relayStateMaxBytes (${d.relayStateMaxBytes})`);

  // Parse every SP certificate now: a garbage PEM would otherwise only show up as failed
  // signature checks at request time.
  const spCerts: [string, string][] = [
    ...[sp.spCertificates ?? []].flat().map((c, j): [string, string] => [`${path}.spCertificates${Array.isArray(sp.spCertificates) ? `.${j}` : ""}`, c]),
    ...[sp.metadata?.signingCertificates ?? []].flat().map((c, j): [string, string] => [`${path}.metadata.signingCertificates${Array.isArray(sp.metadata?.signingCertificates) ? `.${j}` : ""}`, c]),
  ];
  for (const [p, c] of spCerts) {
    try {
      const cert = new X509Certificate(c);
      if (cert.publicKey.asymmetricKeyType !== "rsa") issues.push(`${p}: must be an RSA certificate, got ${cert.publicKey.asymmetricKeyType}`);
      if (new Date(cert.validTo).getTime() < Date.now()) warnings.push(`${p}: EXPIRED on ${cert.validTo}`);
    } catch (e) {
      issues.push(`${p}: could not be parsed (${(e as Error).message})`);
    }
  }

  let encryption: AssertionEncryption | undefined;
  if (sp.encryption) {
    const cert = checkEncryptionCertificate(`${path}.encryption.certificate`, sp.encryption.certificate, issues, warnings);
    if (cert) {
      const dataAlgorithm = sp.encryption.dataAlgorithm ?? "aes256-gcm";
      if (dataAlgorithm === "aes256-cbc")
        warnings.push(`${path}.encryption: AES-CBC is enabled (allowInsecureCbc). Only use this for SPs that cannot do AES-GCM.`);
      encryption = { ...cert, dataAlgorithm, keyAlgorithm: sp.encryption.keyAlgorithm ?? "rsa-oaep", recipient: sp.entityId };
    }
  }

  const attributes = sp.attributes;
  return {
    id: sp.id,
    entityId: sp.entityId,
    acsUrls: sp.acsUrls as [string, ...string[]],
    nameIdFormat: sp.nameIdFormat ?? NAMEID_EMAIL,
    nameId:
      typeof sp.nameId === "function"
        ? sp.nameId
        : sp.nameId
          ? ((field) => (user: SamlIdpUser) => nameIdFromField(user, field))(sp.nameId.field)
          : undefined,
    nameIdField: typeof sp.nameId === "object" ? sp.nameId.field : undefined,
    attributes: typeof attributes === "function" ? attributes : compileAttributeMap(attributes ?? {}),
    attributeMap: typeof attributes === "function" ? undefined : attributes,
    metadata: sp.metadata
      ? {
          url: sp.metadata.url,
          refreshSeconds: sp.metadata.refreshSeconds ?? 86400,
          signingCertificates: sp.metadata.signingCertificates === undefined ? [] : [sp.metadata.signingCertificates].flat(),
        }
      : undefined,
    requestSignatures: sp.requestSignatures ?? (sp.spCertificates !== undefined || sp.metadata !== undefined ? "verify-if-signed" : "ignore"),
    organization: tenantOrganization(sp, path, d, issues),
    singleLogoutService: sp.singleLogoutService
      ? {
          url: sp.singleLogoutService.url,
          binding: sp.singleLogoutService.binding ?? "redirect",
          ...(sp.singleLogoutService.responseUrl ? { responseUrl: sp.singleLogoutService.responseUrl } : {}),
        }
      : undefined,
    spCertificates: sp.spCertificates === undefined ? [] : [sp.spCertificates].flat(),
    allowIdpInitiated: sp.allowIdpInitiated ?? false,
    idpInitiatedRelayState: sp.idpInitiatedRelayState,
    allowedRelayStates: sp.allowedRelayStates ?? [],
    authorize: ("authorize" in sp ? sp.authorize : undefined) ?? d.authorize ?? (() => true),
    sign: sp.sign ?? d.sign,
    sessionNotOnOrAfter: sp.sessionNotOnOrAfter ?? d.sessionNotOnOrAfter,
    ...(encryption ? { encryption } : {}),
    tenantId: sp.tenant,
  };
}

/**
 * Validate and resolve a database-registry SP against the plugin's resolved options. Returns
 * the issues instead of throwing, so the API can report them.
 */
export function resolveStoredServiceProvider(
  input: unknown,
  options: ResolvedSamlIdpOptions,
  authorize?: ResolvedServiceProvider["authorize"],
): { serviceProvider?: ResolvedServiceProvider; config?: StoredServiceProviderConfig; issues: string[]; warnings: string[] } {
  const parsed = storedServiceProviderSchema.safeParse(input);
  if (!parsed.success) return { issues: formatIssues(parsed.error), warnings: [] };
  const issues: string[] = [];
  const warnings: string[] = [];
  const serviceProvider = resolveServiceProvider(
    parsed.data,
    "serviceProvider",
    { sign: options.signing.sign, sessionNotOnOrAfter: options.sessionNotOnOrAfter, relayStateMaxBytes: options.relayStateMaxBytes, authorize, tenants: options.tenants !== undefined },
    issues,
    warnings,
  );
  return issues.length ? { issues, warnings } : { serviceProvider, config: parsed.data, issues, warnings };
}

export function resolveOptions(input: SamlIdpOptions): ResolvedSamlIdpOptions {
  const parsed = optionsSchema.safeParse(input);
  if (!parsed.success) throw new SamlIdpConfigError(formatIssues(parsed.error));
  const o = parsed.data;

  const issues: string[] = [];
  const warnings: string[] = [];

  const sigAlg = o.signing.signatureAlgorithm ?? "rsa-sha256";
  const digestAlg = o.signing.digestAlgorithm ?? "sha256";
  const usesSha1 = sigAlg === "rsa-sha1" || digestAlg === "sha1";
  if (usesSha1 && !o.signing.allowInsecureSha1)
    issues.push("signing: SHA-1 is insecure; set signing.allowInsecureSha1: true to use it anyway");
  if (usesSha1 && o.signing.allowInsecureSha1)
    warnings.push("signing: SHA-1 is enabled (allowInsecureSha1). Only use this for SPs that cannot do SHA-256.");

  // One source of truth for the asserted class: a fixed one, or step-up levels (D-047).
  if (o.authnContext && o.authnContextClassRef !== undefined)
    issues.push("authnContextClassRef: set either authnContextClassRef or authnContext, not both");

  const lifetime = o.assertionLifetimeSeconds ?? 300;
  if (lifetime > 300) warnings.push(`assertionLifetimeSeconds is ${lifetime}; the recommended maximum is 300`);

  // Ids are global (every stored row and replay key is per spId); entity IDs are unique per
  // tenant, since one SP (AWS, Google) can be registered in several (D-052).
  const ids = new Set<string>();
  const entityIds = new Set<string>();
  for (const [i, sp] of o.serviceProviders.entries()) {
    const scoped = `${sp.tenant ?? ""}\u0000${sp.entityId}`;
    if (ids.has(sp.id)) issues.push(`serviceProviders.${i}.id: duplicate id "${sp.id}"`);
    if (entityIds.has(scoped)) issues.push(`serviceProviders.${i}.entityId: duplicate entityId "${sp.entityId}"${sp.tenant === undefined ? "" : ` in tenant "${sp.tenant}"`}`);
    ids.add(sp.id);
    entityIds.add(scoped);
  }

  const tenants = o.tenants?.enabled ? o.tenants : undefined;
  if (tenants) {
    // Multi-tenant design §5.1: under one shared key, only the Issuer string tells tenants apart,
    // so an organization's own administrators must not manage its SPs until each tenant has its key.
    if (tenants.delegation !== undefined && tenants.keys !== "per-tenant")
      issues.push('tenants.delegation: requires tenants.keys: "per-tenant"; with a shared signing key only the host\'s administrators may manage tenant SPs');
    if (!o.registry?.enabled) issues.push("tenants.enabled: requires registry.enabled (tenants and their SPs are stored in the database)");
  }

  const spDefaults: SpDefaults = {
    sign: o.signing.sign ?? "both",
    sessionNotOnOrAfter: o.sessionNotOnOrAfter ?? false,
    relayStateMaxBytes: o.relayStateMaxBytes ?? RELAY_STATE_HARD_CAP,
    tenants: tenants !== undefined,
  };
  const serviceProviders = o.serviceProviders.map((sp, i) => resolveServiceProvider(sp, `serviceProviders.${i}`, spDefaults, issues, warnings));
  for (const [i, sp] of serviceProviders.entries()) {
    const other = serviceProviders.slice(0, i).find((o2) => overlaps(o2, sp));
    if (other) warnings.push(`serviceProviders.${i}: ${overlapWarning(other)}`);
  }

  if (o.serviceProviders.length === 0 && !o.registry?.enabled)
    warnings.push("serviceProviders is empty: every AuthnRequest will be rejected");

  const keyCheck = checkKeyMaterial(o as SamlIdpOptions, warnings);
  issues.push(...keyCheck.issues);
  if (issues.length || !keyCheck.key) throw new SamlIdpConfigError(issues);

  return {
    entityId: o.entityId,
    baseURL: o.baseURL?.replace(/\/+$/, ""),
    loginPage: o.loginPage,
    signing: {
      privateKey: o.signing.privateKey,
      certificate: o.signing.certificate,
      additionalCertificates: o.signing.additionalCertificates ?? [],
      signatureAlgorithm: sigAlg,
      digestAlgorithm: digestAlg,
      allowInsecureSha1: o.signing.allowInsecureSha1 ?? false,
      sign: o.signing.sign ?? "both",
      keyObject: keyCheck.key,
    },
    assertionLifetimeSeconds: lifetime,
    clockSkewSeconds: o.clockSkewSeconds ?? 60,
    pendingRequestTtlSeconds: o.pendingRequestTtlSeconds ?? 600,
    relayStateMaxBytes: o.relayStateMaxBytes ?? RELAY_STATE_HARD_CAP,
    authnContextClassRef: o.authnContextClassRef ?? AUTHN_CONTEXT_UNSPECIFIED,
    authnContext: o.authnContext,
    accountPolicy: {
      requireEmailVerified: o.accountPolicy?.requireEmailVerified ?? true,
      allowImpersonatedSessions: o.accountPolicy?.allowImpersonatedSessions ?? false,
      allowAnonymousUsers: o.accountPolicy?.allowAnonymousUsers ?? false,
    },
    serviceProviders,
    schemaValidator: o.schemaValidator ?? defaultSchemaValidator(),
    // Validated above; Zod types unset keys as `| undefined`, which this nested type leaves out.
    schema: o.schema as SamlIdpOptions["schema"],
    signMetadata: o.signMetadata ?? false,
    sessionNotOnOrAfter: o.sessionNotOnOrAfter ?? false,
    singleLogout: o.singleLogout?.enabled ?? false,
    sessionTracking: (o.singleLogout?.enabled ?? false) || o.events?.onSessionEnded !== undefined,
    events: o.events,
    auditLog: o.auditLog?.enabled ? { retentionDays: o.auditLog.retentionDays ?? 90 } : undefined,
    registry: o.registry?.enabled
      ? { canManage: o.registry.canManage, permissions: o.registry.permissions ?? false, cacheMs: (o.registry.cacheSeconds ?? 60) * 1000, authorize: o.registry.authorize }
      : undefined,
    tenants: tenants
      ? {
          cacheMs: (tenants.cacheSeconds ?? o.registry?.cacheSeconds ?? 60) * 1000,
          perTenantKeys: tenants.keys === "per-tenant",
          keyEncryptionSecret: tenants.keyEncryptionSecret,
          minPublishedMs: (tenants.minPublishedSeconds ?? 86_400) * 1000,
          delegation: tenants.delegation
            ? {
                roles: tenants.delegation.roles ?? ["owner", "admin"],
                userFields: tenants.delegation.userFields ?? ["email", "name", "id"],
                allowMetadataUrl: tenants.delegation.allowMetadataUrl ?? false,
              }
            : undefined,
        }
      : undefined,
    warnings,
  };
}

/**
 * Two SPs in different tenants (or a tenant and the root) with the same entity ID and an ACS URL
 * in common: an assertion one identity issues is addressed exactly as one the other would be.
 * Under the shared key only the SP's check of the Issuer tells them apart (multi-tenant design
 * §5.1). Legitimate for SPs such as AWS, which use one entity ID for every customer; worth a
 * warning either way.
 */
export function overlaps(a: Pick<ResolvedServiceProvider, "entityId" | "acsUrls" | "tenantId">, b: Pick<ResolvedServiceProvider, "entityId" | "acsUrls" | "tenantId">): boolean {
  return (a.tenantId ?? "") !== (b.tenantId ?? "") && a.entityId === b.entityId && a.acsUrls.some((u) => b.acsUrls.includes(u));
}

export function overlapWarning(other: Pick<ResolvedServiceProvider, "id" | "tenantId">): string {
  const where = other.tenantId === undefined ? "the root IdP" : `tenant ${other.tenantId}`;
  return `same entity ID and an ACS URL as SP ${other.id} in ${where}. Tenants share one signing key, so only the SP's check of the assertion's Issuer keeps one tenant's assertions out of the other's account: make sure it checks it, or keep the SP in one tenant`;
}

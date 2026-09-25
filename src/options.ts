import { type KeyObject, X509Certificate, createPrivateKey, createPublicKey } from "node:crypto";
import * as z from "zod";
import { defaultSchemaValidator } from "./saml/validator";
import type {
  ResolvedSamlIdpOptions,
  ResolvedServiceProvider,
  SamlIdpOptions,
  SamlIdpUser,
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

const serviceProviderSchema = z
  .object({
    id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/, "must be 1-64 characters of A-Z a-z 0-9 _ -"),
    entityId: z.string().min(1).max(1024),
    acsUrls: z.array(acsUrl).min(1, "must list at least one ACS URL"),
    nameIdFormat: z.string().min(1).optional(),
    nameId: fn<(user: SamlIdpUser) => string>().optional(),
    attributes: fn<(user: SamlIdpUser) => Record<string, string | string[]>>().optional(),
    requireSignedAuthnRequests: z.boolean().optional(),
    spCertificate: pem("CERTIFICATE").optional(),
    allowIdpInitiated: z.boolean().optional(),
    authorize: fn<ResolvedServiceProvider["authorize"]>().optional(),
  })
  .strict()
  .superRefine((sp, ctx) => {
    if (sp.requireSignedAuthnRequests && !sp.spCertificate)
      ctx.addIssue({ code: "custom", path: ["spCertificate"], message: "is required when requireSignedAuthnRequests is true" });
    if (sp.allowIdpInitiated)
      ctx.addIssue({ code: "custom", path: ["allowIdpInitiated"], message: "IdP-initiated SSO is not supported in this version" });
  });

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
        signResponse: z.boolean().optional(),
        signAssertion: z.boolean().optional(),
      })
      .strict(),
    assertionLifetimeSeconds: z.number().int().min(30).max(3600).optional(),
    clockSkewSeconds: z.number().int().min(0).max(300).optional(),
    pendingRequestTtlSeconds: z.number().int().min(60).max(3600).optional(),
    relayStateMaxBytes: z.number().int().min(80).max(RELAY_STATE_HARD_CAP).optional(),
    authnContextClassRef: z.string().min(1).max(1024).optional(),
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
  if (o.signing.signResponse === false && o.signing.signAssertion === false)
    issues.push("signing: at least one of signResponse and signAssertion must be true");

  const lifetime = o.assertionLifetimeSeconds ?? 300;
  if (lifetime > 300) warnings.push(`assertionLifetimeSeconds is ${lifetime}; the recommended maximum is 300`);

  const ids = new Set<string>();
  const entityIds = new Set<string>();
  for (const [i, sp] of o.serviceProviders.entries()) {
    if (ids.has(sp.id)) issues.push(`serviceProviders.${i}.id: duplicate id "${sp.id}"`);
    if (entityIds.has(sp.entityId)) issues.push(`serviceProviders.${i}.entityId: duplicate entityId "${sp.entityId}"`);
    ids.add(sp.id);
    entityIds.add(sp.entityId);
  }

  if (o.serviceProviders.length === 0) warnings.push("serviceProviders is empty: every AuthnRequest will be rejected");

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
      signResponse: o.signing.signResponse ?? true,
      signAssertion: o.signing.signAssertion ?? true,
      keyObject: keyCheck.key,
    },
    assertionLifetimeSeconds: lifetime,
    clockSkewSeconds: o.clockSkewSeconds ?? 60,
    pendingRequestTtlSeconds: o.pendingRequestTtlSeconds ?? 600,
    relayStateMaxBytes: o.relayStateMaxBytes ?? 80,
    authnContextClassRef: o.authnContextClassRef ?? AUTHN_CONTEXT_UNSPECIFIED,
    accountPolicy: {
      requireEmailVerified: o.accountPolicy?.requireEmailVerified ?? true,
      allowImpersonatedSessions: o.accountPolicy?.allowImpersonatedSessions ?? false,
      allowAnonymousUsers: o.accountPolicy?.allowAnonymousUsers ?? false,
    },
    serviceProviders: o.serviceProviders.map(
      (sp): ResolvedServiceProvider => ({
        id: sp.id,
        entityId: sp.entityId,
        acsUrls: sp.acsUrls as [string, ...string[]],
        nameIdFormat: sp.nameIdFormat ?? NAMEID_EMAIL,
        nameId: sp.nameId,
        attributes: sp.attributes ?? (() => ({})),
        requireSignedAuthnRequests: sp.requireSignedAuthnRequests ?? false,
        spCertificate: sp.spCertificate,
        allowIdpInitiated: false,
        authorize: sp.authorize ?? (() => true),
      }),
    ),
    schemaValidator: o.schemaValidator ?? defaultSchemaValidator(),
    schema: o.schema,
    warnings,
  };
}

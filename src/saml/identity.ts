// Which IdP speaks (D-052): the root IdP, or a tenant's. Everything the IdP signs or advertises
// (Issuer, signing key, SSO and SLO URLs, metadata) comes from an IdpIdentity, and this is the
// one module that reads `options.entityId` and the signing key for that purpose; a unit test
// fails if another source file does (multi-tenant design §5.8). A hard-wired use elsewhere
// would issue one tenant's messages under another identity.
import type { ResolvedSamlIdpOptions, ResolvedServiceProvider, ResolvedSigning, ResolvedSigningSettings } from "../types";
import { idpBaseURL, METADATA_PATH, SSO_PATH } from "./idp";
import { SLO_PATH } from "./logout";
import type { Tenant, TenantDirectory } from "./tenant-directory";
import { type KeySecret, ROOT_KEY_OWNER, rootCommonName, type TenantKeyStore, type WritableKeyAdapter } from "./tenant-keys";
import { trimSlashes } from "../url";

export interface IdpIdentity {
  /** The tenant's organization id; null for the root IdP. */
  tenantId: string | null;
  /** The tenant's key in its URLs; null for the root IdP. */
  tenantKey: string | null;
  /** The Issuer of everything this identity sends. */
  entityId: string;
  /** Signs this identity's messages and metadata: the root key, or with per-tenant keys the tenant's (D-058). */
  signing: ResolvedSigning;
  /** Also the `Destination` an AuthnRequest to this identity must carry. */
  ssoUrl: string;
  /** Also the `Destination` a logout message to this identity must carry. */
  sloUrl: string;
  metadataUrl: string;
}


/** The algorithms and signed parts of `signing`, whatever holds the key. */
export function signingSettings(options: ResolvedSamlIdpOptions): ResolvedSigningSettings {
  const { signatureAlgorithm, digestAlgorithm, allowInsecureSha1, sign } = options.signing;
  return { signatureAlgorithm, digestAlgorithm, allowInsecureSha1, sign };
}

/** The key given in the options; undefined when it's managed (D-080) and must be loaded. */
function configuredKey(options: ResolvedSamlIdpOptions): ResolvedSigning | undefined {
  const s = options.signing;
  if (s.managed) return undefined;
  return { ...signingSettings(options), privateKey: s.privateKey, certificate: s.certificate, additionalCertificates: s.additionalCertificates, keyObject: s.keyObject };
}

/**
 * The root IdP: `options.entityId`, and the URLs it has always had. With a managed key (D-080),
 * `signing` must be the loaded key (`rootSigning`): there's nothing else to sign with.
 */
export function rootIdentity(options: ResolvedSamlIdpOptions, baseURL: string, signing: ResolvedSigning | undefined = configuredKey(options)): IdpIdentity {
  if (!signing) throw new Error("[saml-idp] the managed signing key must be loaded first (rootSigning)");
  const base = trimSlashes(baseURL);
  return {
    tenantId: null,
    tenantKey: null,
    entityId: options.entityId,
    signing,
    ssoUrl: `${base}${SSO_PATH}`,
    sloUrl: `${base}${SLO_PATH}`,
    metadataUrl: `${base}${METADATA_PATH}`,
  };
}

/**
 * A tenant's names and URLs: `${baseURL}/saml2/idp/{sso,slo,metadata}/<tenantKey>`, and the
 * metadata URL as the entity ID (the authentik convention: self-describing, and derived from
 * nothing that can change). `baseURL` is pinned whenever tenants are on, so these never follow a
 * Host header.
 */
export function tenantUrls(baseURL: string, tenant: Tenant): Omit<IdpIdentity, "signing"> {
  const base = trimSlashes(baseURL);
  const metadataUrl = `${base}${METADATA_PATH}/${tenant.tenantKey}`;
  return {
    tenantId: tenant.organizationId,
    tenantKey: tenant.tenantKey,
    entityId: metadataUrl,
    ssoUrl: `${base}${SSO_PATH}/${tenant.tenantKey}`,
    sloUrl: `${base}${SLO_PATH}/${tenant.tenantKey}`,
    metadataUrl,
  };
}

/** A tenant, signing with the shared key, or with per-tenant keys what its key rows give (TenantKeyStore.signing). */
export function tenantIdentity(options: ResolvedSamlIdpOptions, baseURL: string, tenant: Tenant, signing: ResolvedSigning | undefined = configuredKey(options)): IdpIdentity {
  if (!signing) throw new Error("[saml-idp] the managed signing key must be loaded first (rootSigning)");
  return { ...tenantUrls(baseURL, tenant), signing };
}

type IdentityState = { options: ResolvedSamlIdpOptions; tenants: TenantDirectory | undefined; tenantKeys: TenantKeyStore | undefined; rootKeys: TenantKeyStore | undefined };
type Adapter = Parameters<TenantDirectory["byOrganization"]>[0] & WritableKeyAdapter;
/** What encrypts stored keys: the root's managed key, and tenants' keys (each may have its own secret). */
export interface KeySecrets {
  root: KeySecret;
  tenant: KeySecret;
}

/**
 * The managed key's policy (D-080): how long a next key waits, and what the first key is (the
 * initial key brought along, else a generated one named after the IdP's host). Undefined when the
 * key is given in the options.
 */
export function managedKeyPolicy(
  options: ResolvedSamlIdpOptions,
): { minPublishedMs: number; first: { commonName: string; initial: { privateKeyPem: string; certificate: string } | undefined } } | undefined {
  const s = options.signing;
  return s.managed ? { minPublishedMs: s.minPublishedMs, first: { commonName: rootCommonName(options.entityId), initial: s.initialKey } } : undefined;
}

/** The secrets for stored keys: each one's own option, else Better Auth's secret (`own`). */
export function keySecretsFor(options: ResolvedSamlIdpOptions, own: KeySecret): KeySecrets {
  const signing = options.signing;
  return { root: (signing.managed ? signing.keyEncryptionSecret : undefined) ?? own, tenant: options.tenants?.keyEncryptionSecret ?? own };
}

/**
 * The root IdP's key: the one in the options, or the managed one (D-080), generated and stored
 * the first time it's needed. Throws TenantKeyError when the stored key can't be used: the
 * caller refuses, and nothing else ever signs instead.
 */
export async function rootSigning(state: IdentityState, adapter: Adapter, secrets: KeySecrets, warn?: (message: string) => void): Promise<ResolvedSigning> {
  const configured = configuredKey(state.options);
  if (configured) return configured;
  const policy = managedKeyPolicy(state.options);
  if (!state.rootKeys || !policy) throw new Error("[saml-idp] managed signing key without a key store");
  if (await state.rootKeys.ensureFirstKey(adapter, secrets.root, ROOT_KEY_OWNER, policy.first))
    warn?.(
      policy.first.initial
        ? "[saml-idp] stored signing.initialKey as the IdP's managed signing key; it can now be removed from the options"
        : "[saml-idp] generated the IdP's managed signing key: SPs that pin the IdP's certificate need the new one, from the metadata",
    );
  return state.rootKeys.signing(adapter, secrets.root, ROOT_KEY_OWNER, { settings: signingSettings(state.options) }, warn);
}

/** The root IdP's identity, with its key loaded (D-080). */
export async function resolveRootIdentity(state: IdentityState, adapter: Adapter, secrets: KeySecrets, baseURL: string, warn?: (message: string) => void): Promise<IdpIdentity> {
  return rootIdentity(state.options, baseURL, await rootSigning(state, adapter, secrets, warn));
}

/**
 * A tenant's identity, signing with its own key when tenants have keys (D-058), else with the
 * root's (shared) key. Throws TenantKeyError when that key can't be used: the caller refuses,
 * never signs with another key.
 */
export async function resolveTenantIdentity(state: IdentityState, adapter: Adapter, secrets: KeySecrets, baseURL: string, tenant: Tenant, warn?: (message: string) => void): Promise<IdpIdentity> {
  const shared = () => rootSigning(state, adapter, secrets, warn);
  if (!state.tenantKeys) return tenantIdentity(state.options, baseURL, tenant, await shared());
  return tenantIdentity(state.options, baseURL, tenant, await state.tenantKeys.signing(adapter, secrets.tenant, tenant.organizationId, { settings: signingSettings(state.options), shared }, warn));
}

/**
 * The identity an SP deals with: its tenant's, or the root's. Undefined when the SP's tenant
 * doesn't exist or is disabled: its SPs then get nothing, never the root identity instead.
 */
export async function identityFor(
  state: IdentityState,
  adapter: Adapter,
  secrets: KeySecrets,
  requestBaseURL: string,
  sp: Pick<ResolvedServiceProvider, "tenantId">,
  warn?: (message: string) => void,
): Promise<IdpIdentity | undefined> {
  const base = idpBaseURL(state.options, requestBaseURL);
  if (sp.tenantId === undefined) return resolveRootIdentity(state, adapter, secrets, base, warn);
  if (!state.tenants) return undefined;
  const tenant = await state.tenants.byOrganization(adapter, sp.tenantId);
  return tenant ? resolveTenantIdentity(state, adapter, secrets, base, tenant, warn) : undefined;
}

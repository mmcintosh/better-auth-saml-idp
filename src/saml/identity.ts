// Which IdP speaks (D-052): the root IdP, or a tenant's. Everything the IdP signs or advertises
// (Issuer, signing key, SSO and SLO URLs, metadata) comes from an IdpIdentity, and this is the
// one module that reads `options.entityId` and the signing key for that purpose; a unit test
// fails if another source file does (multi-tenant design §5.8). A hard-wired use elsewhere
// would issue one tenant's messages under another identity.
import type { ResolvedSamlIdpOptions, ResolvedServiceProvider } from "../types";
import { idpBaseURL, METADATA_PATH, SSO_PATH } from "./idp";
import { SLO_PATH } from "./logout";
import type { Tenant, TenantDirectory } from "./tenant-directory";

export interface IdpIdentity {
  /** The tenant's organization id; null for the root IdP. */
  tenantId: string | null;
  /** The tenant's key in its URLs; null for the root IdP. */
  tenantKey: string | null;
  /** The Issuer of everything this identity sends. */
  entityId: string;
  /** Signs this identity's messages and metadata. Every tenant uses the root key in this version. */
  signing: ResolvedSamlIdpOptions["signing"];
  /** Also the `Destination` an AuthnRequest to this identity must carry. */
  ssoUrl: string;
  /** Also the `Destination` a logout message to this identity must carry. */
  sloUrl: string;
  metadataUrl: string;
}

const trim = (url: string) => url.replace(/\/+$/, "");

/** The root IdP: `options.entityId`, and the URLs it has always had. */
export function rootIdentity(options: ResolvedSamlIdpOptions, baseURL: string): IdpIdentity {
  const base = trim(baseURL);
  return {
    tenantId: null,
    tenantKey: null,
    entityId: options.entityId,
    signing: options.signing,
    ssoUrl: `${base}${SSO_PATH}`,
    sloUrl: `${base}${SLO_PATH}`,
    metadataUrl: `${base}${METADATA_PATH}`,
  };
}

/**
 * A tenant: `${baseURL}/saml2/idp/{sso,slo,metadata}/<tenantKey>`, and the metadata URL as the
 * entity ID (the authentik convention: self-describing, and derived from nothing that can change).
 * `baseURL` is pinned whenever tenants are on, so these never follow a Host header.
 */
export function tenantIdentity(options: ResolvedSamlIdpOptions, baseURL: string, tenant: Tenant): IdpIdentity {
  const base = trim(baseURL);
  const metadataUrl = `${base}${METADATA_PATH}/${tenant.tenantKey}`;
  return {
    tenantId: tenant.organizationId,
    tenantKey: tenant.tenantKey,
    entityId: metadataUrl,
    // tenants.keys: "shared" (the only choice in this version).
    signing: options.signing,
    ssoUrl: `${base}${SSO_PATH}/${tenant.tenantKey}`,
    sloUrl: `${base}${SLO_PATH}/${tenant.tenantKey}`,
    metadataUrl,
  };
}

type IdentityState = { options: ResolvedSamlIdpOptions; tenants: TenantDirectory | undefined };
type Adapter = Parameters<TenantDirectory["byOrganization"]>[0];

/**
 * The identity an SP deals with: its tenant's, or the root's. Undefined when the SP's tenant
 * doesn't exist or is disabled: its SPs then get nothing, never the root identity instead.
 */
export async function identityFor(
  state: IdentityState,
  adapter: Adapter,
  requestBaseURL: string,
  sp: Pick<ResolvedServiceProvider, "tenantId">,
): Promise<IdpIdentity | undefined> {
  const base = idpBaseURL(state.options, requestBaseURL);
  if (sp.tenantId === undefined) return rootIdentity(state.options, base);
  if (!state.tenants) return undefined;
  const tenant = await state.tenants.byOrganization(adapter, sp.tenantId);
  return tenant ? tenantIdentity(state.options, base, tenant) : undefined;
}

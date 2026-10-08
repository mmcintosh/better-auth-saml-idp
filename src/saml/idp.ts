import type { ResolvedSamlIdpOptions, ResolvedServiceProvider, SignatureAlgorithm } from "../types";
import { type IdpIdentity, rootIdentity } from "./identity";
import { buildIdpMetadata } from "./metadata";
import { trimSlashes } from "../url";

export { BINDING_POST, BINDING_REDIRECT } from "./metadata";

export const SIGNATURE_ALGORITHM_URI: Record<SignatureAlgorithm, string> = {
  "rsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "rsa-sha512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  "rsa-sha1": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
};

export const SSO_PATH = "/saml2/idp/sso";
export const METADATA_PATH = "/saml2/idp/metadata";

/** One IdP identity's metadata, built once (D-074). */
export interface Idp {
  getMetadata(): string;
}

/**
 * The metadata of one IdP identity (the root, or a tenant's, D-052), advertising the NameID
 * formats of that identity's SPs in code. Built on first use, then kept with the cached Idp.
 */
export function createIdp(options: ResolvedSamlIdpOptions, identity: IdpIdentity, serviceProviders: readonly ResolvedServiceProvider[]): Idp {
  let xml: string | undefined;
  return { getMetadata: () => (xml ??= buildIdpMetadata(options, identity, serviceProviders)) };
}

/**
 * Better Auth's rule for `baseURL` (API decision 6): a URL with no path is the site's origin
 * and gets `basePath` (default `/api/auth`) appended; a URL with a path is used as it is. So
 * `samlIdp({ baseURL })` takes the same value as `betterAuth({ baseURL })`.
 */
export function withBasePath(url: string, basePath: string | undefined = "/api/auth"): string {
  const trimmed = trimSlashes(url);
  if (trimSlashes(new URL(url).pathname) !== "") return trimmed;
  if (!basePath || basePath === "/") return trimmed;
  return trimSlashes(`${trimmed}${basePath.startsWith("/") ? basePath : `/${basePath}`}`);
}

/** The Better Auth base URL the IdP's own URLs use: the pinned option, else the request's. */
export function idpBaseURL(options: ResolvedSamlIdpOptions, requestBaseURL: string): string {
  return trimSlashes(options.baseURL ?? requestBaseURL);
}

const MAX_CACHED_BASE_URLS = 32;

/**
 * IdP per base URL. With `options.baseURL` pinned there is exactly one. Otherwise the
 * base URL follows the request's Host, so the cache is bounded (LRU) instead of growing with
 * every Host header a client sends (review finding #7).
 */
export function idpCache(options: ResolvedSamlIdpOptions) {
  const cache = lru(MAX_CACHED_BASE_URLS);
  // The root IdP's SPs in code; without tenants, all of them.
  const rootSps = options.serviceProviders.filter((sp) => sp.tenantId === undefined);
  return (requestBaseURL: string) => {
    const baseURL = idpBaseURL(options, requestBaseURL);
    return cache(baseURL, () => createIdp(options, rootIdentity(options, baseURL), rootSps));
  };
}

const MAX_CACHED_TENANTS = 256;

/** IdP per tenant (D-052), bounded like the root's: tenants are unbounded in number. */
export function tenantIdpCache(options: ResolvedSamlIdpOptions) {
  const cache = lru(MAX_CACHED_TENANTS);
  return (identity: IdpIdentity) =>
    // The certificates are in the key: a rotated tenant key gets a new IdP (D-058).
    cache(`${identity.entityId}\u0000${identity.tenantId}\u0000${identity.signing.certificate}\u0000${identity.signing.additionalCertificates.join("\u0000")}`, () =>
      createIdp(options, identity, options.serviceProviders.filter((sp) => sp.tenantId === identity.tenantId)),
    );
}

function lru(max: number) {
  const cache = new Map<string, Idp>();
  return (key: string, build: () => Idp) => {
    let idp = cache.get(key);
    if (idp) {
      cache.delete(key); // refresh LRU position
    } else {
      idp = build();
      if (cache.size >= max) {
        const oldest = cache.keys().next();
        if (!oldest.done) cache.delete(oldest.value);
      }
    }
    cache.set(key, idp);
    return idp;
  };
}

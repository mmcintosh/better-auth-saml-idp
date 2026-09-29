import * as samlify from "samlify";
import type { ResolvedSamlIdpOptions, ResolvedServiceProvider, SignatureAlgorithm } from "../types";
import { type IdpIdentity, rootIdentity } from "./identity";
import { trimSlashes } from "../url";

export const BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
export const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

export const SIGNATURE_ALGORITHM_URI: Record<SignatureAlgorithm, string> = {
  "rsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "rsa-sha512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  "rsa-sha1": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
};

export const SSO_PATH = "/saml2/idp/sso";
export const METADATA_PATH = "/saml2/idp/metadata";

export type Idp = ReturnType<typeof samlify.IdentityProvider>;

/**
 * samlify warns on the console whenever an IdP has no SingleLogoutService. Without
 * `singleLogout` we deliberately advertise none, so that one message is noise for every host.
 * Construction is synchronous, so the filter can't swallow anyone else's warnings.
 */
const SAMLIFY_NO_SLO = "missing endpoint of SingleLogoutService";
function quietly<T>(build: () => T): T {
  const warn = console.warn;
  console.warn = (...args: unknown[]) => {
    if (typeof args[0] === "string" && args[0].includes(SAMLIFY_NO_SLO)) return;
    warn(...args);
  };
  try {
    return build();
  } finally {
    console.warn = warn;
  }
}

/**
 * Builds the samlify IdentityProvider for one IdP identity (the root, or a tenant's, D-052),
 * advertising the NameID formats of that identity's SPs in code.
 */
export function createIdp(options: ResolvedSamlIdpOptions, identity: IdpIdentity, serviceProviders: readonly ResolvedServiceProvider[]): Idp {
  const nameIdFormats = [...new Set(serviceProviders.map((sp) => sp.nameIdFormat))];
  return quietly(() => samlify.IdentityProvider({
    entityID: identity.entityId,
    privateKey: identity.signing.privateKey,
    signingCert: [identity.signing.certificate, ...identity.signing.additionalCertificates],
    isAssertionEncrypted: false,
    // Per-SP enforcement happens in the sso endpoint; metadata advertises the strict
    // setting only if every SP requires it.
    // Only a promise we can keep: with a registry, SPs added later may not sign.
    wantAuthnRequestsSigned:
      options.registry === undefined && serviceProviders.length > 0 && serviceProviders.every((sp) => sp.requestSignatures === "require"),
    requestSignatureAlgorithm: SIGNATURE_ALGORITHM_URI[identity.signing.signatureAlgorithm],
    nameIDFormat: nameIdFormats,
    singleSignOnService: [
      { Binding: BINDING_REDIRECT, Location: identity.ssoUrl },
      { Binding: BINDING_POST, Location: identity.ssoUrl },
    ],
    ...(options.singleLogout
      ? {
          singleLogoutService: [
            { Binding: BINDING_REDIRECT, Location: identity.sloUrl },
            { Binding: BINDING_POST, Location: identity.sloUrl },
          ],
        }
      : {}),
  }));
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
 * samlify IdP per base URL. With `options.baseURL` pinned there is exactly one. Otherwise the
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

/** samlify IdP per tenant (D-052), bounded like the root's: tenants are unbounded in number. */
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

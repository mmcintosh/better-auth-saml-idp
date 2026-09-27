import * as samlify from "samlify";
import type { ResolvedSamlIdpOptions, SignatureAlgorithm } from "../types";

export const BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
export const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

export const SIGNATURE_ALGORITHM_URI: Record<SignatureAlgorithm, string> = {
  "rsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "rsa-sha512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  "rsa-sha1": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
};

export const SSO_PATH = "/saml2/idp/sso";

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

/** Builds the samlify IdentityProvider for a given Better Auth base URL. */
export function createIdp(options: ResolvedSamlIdpOptions, baseURL: string): Idp {
  const ssoUrl = `${baseURL.replace(/\/+$/, "")}${SSO_PATH}`;
  const nameIdFormats = [...new Set(options.serviceProviders.map((sp) => sp.nameIdFormat))];
  return quietly(() => samlify.IdentityProvider({
    entityID: options.entityId,
    privateKey: options.signing.privateKey,
    signingCert: [options.signing.certificate, ...options.signing.additionalCertificates],
    isAssertionEncrypted: false,
    // Per-SP enforcement happens in the sso endpoint; metadata advertises the strict
    // setting only if every SP requires it.
    // Only a promise we can keep: with a registry, SPs added later may not sign.
    wantAuthnRequestsSigned:
      options.registry === undefined && options.serviceProviders.length > 0 && options.serviceProviders.every((sp) => sp.requestSignatures === "require"),
    requestSignatureAlgorithm: SIGNATURE_ALGORITHM_URI[options.signing.signatureAlgorithm],
    nameIDFormat: nameIdFormats,
    singleSignOnService: [
      { Binding: BINDING_REDIRECT, Location: ssoUrl },
      { Binding: BINDING_POST, Location: ssoUrl },
    ],
    ...(options.singleLogout
      ? {
          singleLogoutService: [
            { Binding: BINDING_REDIRECT, Location: `${baseURL.replace(/\/+$/, "")}/saml2/idp/slo` },
            { Binding: BINDING_POST, Location: `${baseURL.replace(/\/+$/, "")}/saml2/idp/slo` },
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
  const trimmed = url.replace(/\/+$/, "");
  if (new URL(url).pathname.replace(/\/+$/, "") !== "") return trimmed;
  if (!basePath || basePath === "/") return trimmed;
  return `${trimmed}${basePath.startsWith("/") ? basePath : `/${basePath}`}`.replace(/\/+$/, "");
}

/** The Better Auth base URL the IdP's own URLs use: the pinned option, else the request's. */
export function idpBaseURL(options: ResolvedSamlIdpOptions, requestBaseURL: string): string {
  return (options.baseURL ?? requestBaseURL).replace(/\/+$/, "");
}

const MAX_CACHED_BASE_URLS = 32;

/**
 * samlify IdP per base URL. With `options.baseURL` pinned there is exactly one. Otherwise the
 * base URL follows the request's Host, so the cache is bounded (LRU) instead of growing with
 * every Host header a client sends (review finding #7).
 */
export function idpCache(options: ResolvedSamlIdpOptions) {
  const cache = new Map<string, Idp>();
  return (requestBaseURL: string) => {
    const baseURL = idpBaseURL(options, requestBaseURL);
    let idp = cache.get(baseURL);
    if (idp) {
      cache.delete(baseURL); // refresh LRU position
    } else {
      idp = createIdp(options, baseURL);
      if (cache.size >= MAX_CACHED_BASE_URLS) {
        const oldest = cache.keys().next();
        if (!oldest.done) cache.delete(oldest.value);
      }
    }
    cache.set(baseURL, idp);
    return idp;
  };
}

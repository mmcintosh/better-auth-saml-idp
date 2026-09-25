/// <reference path="./saml/wasm/wasm.d.ts" />
import type { BetterAuthPlugin } from "better-auth";
import { mergeSchema } from "better-auth/db";
import { initEndpoint } from "./endpoints/init";
import { metadataEndpoint } from "./endpoints/metadata";
import { resumeEndpoint } from "./endpoints/resume";
import { ssoEndpoint } from "./endpoints/sso";
import { SAML_IDP_ERROR_CODES } from "./errors";
import { resolveOptions } from "./options";
import { idpCache, SSO_PATH } from "./saml/idp";
import { samlIdpSchema } from "./schema";
import { SpMetadataCache } from "./saml/sp-metadata-refresh";
import { SpDirectory } from "./saml/sp-directory";
import { registryEndpoints } from "./endpoints/registry";
import { logoutEndpoint, sloEndpoint } from "./endpoints/slo";
import { SLO_PATH } from "./saml/logout";
import type { SamlIdpOptions } from "./types";

export { SAML_IDP_ERROR_CODES } from "./errors";
export { SamlIdpConfigError } from "./options";
export { libxml2Validator } from "./saml/validator";
export { serviceProviderFromMetadata, SpMetadataError } from "./saml/sp-metadata";
export type { SpFromMetadataOptions, SpFromMetadataResult } from "./saml/sp-metadata";
export type * from "./types";

export const samlIdp = (options: SamlIdpOptions) => {
  const resolved = resolveOptions(options);
  const directory = new SpDirectory(resolved.serviceProviders, resolved);
  const getIdp = idpCache(resolved);
  const state = { options: resolved, directory, metadata: new SpMetadataCache(resolved.schemaValidator) };

  return {
    id: "saml-idp",
    init(ctx) {
      for (const w of resolved.warnings) ctx.logger.warn(`[saml-idp] ${w}`);
      if (!resolved.baseURL && !ctx.options.baseURL)
        ctx.logger.warn(
          "[saml-idp] no baseURL: the IdP's SSO URL (metadata, Destination check, resume links) follows the request's Host header. Set samlIdp({ baseURL }) or Better Auth's baseURL.",
        );
      // SPs POST AuthnRequests cross-origin (HTTP-POST binding), like @better-auth/sso's ACS.
      const existing = ctx.skipOriginCheck;
      if (existing === true) return {};
      // /slo too: SPs POST LogoutRequests and LogoutResponses cross-origin (D-028).
      return { context: { skipOriginCheck: [...(Array.isArray(existing) ? existing : []), SSO_PATH, ...(resolved.singleLogout ? [SLO_PATH] : [])] } };
    },
    endpoints: {
      getSamlIdpMetadata: metadataEndpoint(getIdp, resolved),
      samlIdpSingleSignOn: ssoEndpoint(state),
      samlIdpResume: resumeEndpoint(state),
      samlIdpInitiatedSignOn: initEndpoint(state),
      ...(resolved.registry?.canManage ? registryEndpoints(state) : {}),
      ...(resolved.singleLogout ? { samlIdpSingleLogout: sloEndpoint(state), samlIdpLogout: logoutEndpoint(state) } : {}),
    },
    // A fresh schema object per plugin: mergeSchema mutates its first argument, so a shared
    // module-level object would leak one instance's renames into every other (finding #10).
    schema: mergeSchema(samlIdpSchema({ registry: resolved.registry !== undefined, singleLogout: resolved.singleLogout }), resolved.schema),
    $ERROR_CODES: SAML_IDP_ERROR_CODES,
    options: { directory },
  } satisfies BetterAuthPlugin;
};

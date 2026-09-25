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
import { createSpRegistry } from "./saml/sp-registry";
import type { SamlIdpOptions } from "./types";

export { SAML_IDP_ERROR_CODES } from "./errors";
export { SamlIdpConfigError } from "./options";
export { libxml2Validator } from "./saml/validator";
export { serviceProviderFromMetadata, SpMetadataError } from "./saml/sp-metadata";
export type { SpFromMetadataOptions, SpFromMetadataResult } from "./saml/sp-metadata";
export type * from "./types";

export const samlIdp = (options: SamlIdpOptions) => {
  const resolved = resolveOptions(options);
  const registry = createSpRegistry(resolved.serviceProviders);
  const getIdp = idpCache(resolved);
  const state = { options: resolved, registry };

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
      return { context: { skipOriginCheck: [...(Array.isArray(existing) ? existing : []), SSO_PATH] } };
    },
    endpoints: {
      getSamlIdpMetadata: metadataEndpoint(getIdp, resolved),
      samlIdpSingleSignOn: ssoEndpoint(state),
      samlIdpResume: resumeEndpoint(state),
      samlIdpInitiatedSignOn: initEndpoint(state),
    },
    // A fresh schema object per plugin: mergeSchema mutates its first argument, so a shared
    // module-level object would leak one instance's renames into every other (finding #10).
    schema: mergeSchema(samlIdpSchema(), resolved.schema),
    $ERROR_CODES: SAML_IDP_ERROR_CODES,
    options: { registry },
  } satisfies BetterAuthPlugin;
};

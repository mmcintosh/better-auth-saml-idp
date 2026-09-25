import type { BetterAuthPlugin } from "better-auth";
import { mergeSchema } from "better-auth/db";
import * as samlify from "samlify";
import { getContext } from "samlify/build/src/api";
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
export type * from "./types";

// samlify refuses to parse without a process-global validator. Install ours only if nobody
// else (e.g. @better-auth/sso) has; the plugin validates inbound XML itself regardless.
// See DECISIONS.md D-006.
function ensureSamlifyValidator(validate: (xml: string) => Promise<unknown>) {
  if (!getContext().validate) samlify.setSchemaValidator({ validate });
}

export const samlIdp = (options: SamlIdpOptions) => {
  const resolved = resolveOptions(options);
  const registry = createSpRegistry(resolved.serviceProviders);
  const getIdp = idpCache(resolved);
  const state = { options: resolved, registry };

  ensureSamlifyValidator(async (xml) => {
    const r = await resolved.schemaValidator.validate(xml, "protocol");
    if (!r.valid) throw new Error("ERR_INVALID_XML");
    return "SUCCESS_VALIDATE_XML";
  });

  return {
    id: "saml-idp",
    init(ctx) {
      for (const w of resolved.warnings) ctx.logger.warn(`[saml-idp] ${w}`);
      // SPs POST AuthnRequests cross-origin (HTTP-POST binding), like @better-auth/sso's ACS.
      const existing = ctx.skipOriginCheck;
      if (existing === true) return {};
      return { context: { skipOriginCheck: [...(Array.isArray(existing) ? existing : []), SSO_PATH] } };
    },
    endpoints: {
      getSamlIdpMetadata: metadataEndpoint(getIdp),
      samlIdpSingleSignOn: ssoEndpoint(state),
      samlIdpResume: resumeEndpoint(state),
    },
    schema: mergeSchema(samlIdpSchema, resolved.schema),
    $ERROR_CODES: SAML_IDP_ERROR_CODES,
    options: { registry },
  } satisfies BetterAuthPlugin;
};

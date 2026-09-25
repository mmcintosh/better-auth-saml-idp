import { inject } from "vitest";
import type { SamlIdpOptions } from "../../src/types";

export const IDP_ENTITY_ID = "https://auth.test/api/auth/saml2/idp";
export const SP_ENTITY_ID = "https://sp.test/metadata";
export const SP_ACS = "https://sp.test/acs";

/** A valid option set; tests override pieces of it. */
export function baseOptions(overrides: Partial<SamlIdpOptions> = {}): SamlIdpOptions {
  const keys = inject("keys");
  return {
    entityId: IDP_ENTITY_ID,
    loginPage: "/sign-in",
    signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate },
    serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }],
    ...overrides,
  };
}

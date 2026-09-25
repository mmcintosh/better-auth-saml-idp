// HTTPS everywhere (throwaway CA, lib/tls.mjs), so Secure cookies and schemeful SameSite
// behave as in production. Every party is its own *site* (different registrable domain), so Chromium applies
// SameSite and CSP exactly as it would in production. Chromium resolves *.test to
// 127.0.0.1 via --host-resolver-rules (see playwright.config.ts).
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const E2E_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
export const EXAMPLE_DIR = join(E2E_DIR, "../examples/workers-hono");
export const GENERATED = join(E2E_DIR, ".generated");

export const IDP = "https://idp.test:8787";
export const IDP_ENTITY = `${IDP}/api/auth/saml2/idp`;
export const IDP_SSO = `${IDP}/api/auth/saml2/idp/sso`;
export const KC = "https://kc.test:8080";
export const SSP = "https://ssp.test:8081";
export const TEST_SP = "https://sp.test:9100"; // node-saml SP, HTTP-POST binding
export const TEST_APP = "https://app.test:9101"; // where the test SP sends users after its ACS

export const SERVICE_PROVIDERS = [
  { id: "keycloak", entityId: `${KC}/realms/e2e`, acsUrls: [`${KC}/realms/e2e/broker/our-idp/endpoint`] },
  {
    id: "simplesamlphp",
    entityId: `${SSP}/simplesaml/module.php/saml/sp/metadata/default-sp`,
    acsUrls: [`${SSP}/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp`],
  },
  { id: "test-sp", entityId: `${TEST_SP}/metadata`, acsUrls: [`${TEST_SP}/acs`] },
  // The same node-saml SP, registered a second time for IdP-initiated SSO (unsolicited Responses).
  {
    id: "test-sp-idp-init",
    entityId: `${TEST_SP}/idp-initiated`,
    acsUrls: [`${TEST_SP}/acs-idp-initiated`],
    allowIdpInitiated: true,
    idpInitiatedRelayState: "default-landing",
    allowedRelayStates: ["reports"],
  },
];

export const PORTS = [8787, 8080, 8081, 9100, 9101];
export const CHROMIUM_ARGS = ["--host-resolver-rules=MAP *.test 127.0.0.1"];

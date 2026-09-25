import { IDP_ENTITY, IDP_SSO, KC } from "./config.mjs";
import { hostFetch } from "./procs.mjs";

export async function keycloakAdmin() {
  const tok = await (
    await hostFetch(`${KC}/realms/master/protocol/openid-connect/token`, {
      method: "POST",
      body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: "admin", password: "admin" }),
    })
  ).json();
  return (path, init = {}) =>
    hostFetch(`${KC}/admin${path}`, {
      ...init,
      headers: { authorization: `Bearer ${tok.access_token}`, "content-type": "application/json", ...(init.headers ?? {}) },
    });
}

/** Realm `e2e` with a SAML identity provider `our-idp` → our IdP; signatures required. */
export async function configureKeycloak(cert) {
  const admin = await keycloakAdmin();
  await admin("/realms/e2e", { method: "DELETE" });
  let r = await admin("/realms", { method: "POST", body: JSON.stringify({ realm: "e2e", enabled: true }) });
  if (!r.ok) throw new Error(`create realm: ${r.status} ${await r.text()}`);
  r = await admin("/realms/e2e/identity-provider/instances", {
    method: "POST",
    body: JSON.stringify({
      alias: "our-idp",
      providerId: "saml",
      enabled: true,
      trustEmail: true,
      config: {
        entityId: `${KC}/realms/e2e`,
        idpEntityId: IDP_ENTITY,
        singleSignOnServiceUrl: IDP_SSO,
        nameIDPolicyFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        principalType: "SUBJECT",
        postBindingResponse: "true",
        postBindingAuthnRequest: "false",
        validateSignature: "true",
        signingCertificate: cert,
        wantAssertionsSigned: "true",
        wantAuthnRequestsSigned: "false",
        syncMode: "IMPORT",
        allowedClockSkew: "30",
      },
    }),
  });
  if (!r.ok) throw new Error(`create IdP: ${r.status} ${await r.text()}`);
  for (const attr of ["email", "firstName", "lastName"]) {
    await admin("/realms/e2e/identity-provider/instances/our-idp/mappers", {
      method: "POST",
      body: JSON.stringify({
        name: attr,
        identityProviderAlias: "our-idp",
        identityProviderMapper: "saml-user-attribute-idp-mapper",
        config: { "attribute.name": attr, "user.attribute": attr, syncMode: "INHERIT" },
      }),
    });
  }
}

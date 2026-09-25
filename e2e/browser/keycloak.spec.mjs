// Keycloak 26.4 as a SAML identity broker in front of our IdP.
import { createHash, randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";
import { KC } from "../lib/config.mjs";
import { keycloakAdmin } from "../lib/keycloak.mjs";
import { idpSignUpAndVerify, newEmail, watchCsp } from "./helpers.mjs";

test("Keycloak broker: a new user signs in through our IdP", async ({ page }) => {
  const csp = watchCsp(page);
  const email = newEmail("kc");
  const redirect = `${KC}/realms/e2e/account/`;
  const auth = new URL(`${KC}/realms/e2e/protocol/openid-connect/auth`);
  const verifier = randomBytes(32).toString("base64url");
  Object.entries({
    client_id: "account-console",
    redirect_uri: redirect,
    response_type: "code",
    scope: "openid",
    kc_idp_hint: "our-idp",
    state: randomBytes(8).toString("hex"),
    nonce: randomBytes(8).toString("hex"),
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  }).forEach(([k, v]) => auth.searchParams.set(k, v));

  await page.goto(auth.href);
  await idpSignUpAndVerify(page, email);
  await page.waitForURL((u) => u.href.startsWith(redirect), { timeout: 60_000 });
  expect(new URL(page.url()).hash + new URL(page.url()).search).toMatch(/code=/);

  const admin = await keycloakAdmin();
  const users = await (await admin(`/realms/e2e/users?email=${encodeURIComponent(email)}&exact=true`)).json();
  expect(users).toHaveLength(1);
  expect(users[0]).toMatchObject({ firstName: "Pat", lastName: "Playwright" });
  const links = await (await admin(`/realms/e2e/users/${users[0].id}/federated-identity`)).json();
  expect(links).toContainEqual(expect.objectContaining({ identityProvider: "our-idp", userName: email }));
  expect(csp).toEqual([]);
});

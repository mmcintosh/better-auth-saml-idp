# Testing against real service providers

The IdP is checked against several independent SAML implementations, from automated tests that run on every commit up to hosted products that need an account.

| Tier | Service provider | How | Runs in CI |
|---|---|---|---|
| 1 | samlify (strict: message and assertion signatures required) | `test/integration/*.test.ts` | ✅ Node + workerd |
| 1 | **`@better-auth/sso`**, Better Auth's own SAML SP | `test/interop/sp-interop.test.ts` | ✅ Node + workerd |
| 1 | **`@node-saml/node-saml`** (`InResponseTo` validation always on, both signatures required) | `test/interop/sp-interop.test.ts` | ✅ Node + workerd |
| 2 | **Keycloak 26.4** as an identity broker | `pnpm e2e` (Docker) | local |
| 2 | **SimpleSAMLphp 2.5** SP | `pnpm e2e` (Docker) | local |
| 3 | **Cloudflare Access** (Zero Trust) | [sp-cloudflare-access.md](sp-cloudflare-access.md) | manual |
| 3 | **AWS IAM Identity Center** | [sp-aws-iam-identity-center.md](sp-aws-iam-identity-center.md) | manual |
| 3 | HubSpot | [hubspot.md](hubspot.md) | manual, not yet verified |
| 4 | SAMLtool, an external validator | below | manual |

## Tier 2: `pnpm e2e`

This needs Docker (`docker compose` or `docker-compose`), `openssl`, and ports 8787, 8080 and 8081 free. The script:
1. starts `examples/workers-hono` on **workerd** (`wrangler dev`, local D1), with both SPs registered through `SAML_SERVICE_PROVIDERS`
2. writes SimpleSAMLphp's remote-IdP metadata from the live IdP metadata, then starts Keycloak and SimpleSAMLphp (`e2e/docker-compose.yml`)
3. configures a Keycloak realm with a SAML identity provider pointing at our IdP, with signature validation and signed assertions required, through the admin REST API
4. uses a scripted browser (cookie jars, redirects, SAML auto-POST) to sign **new** users in through each SP, then checks what the SP received:
   - **Keycloak:** the user exists, is linked to `our-idp`, and has first and last names mapped from our attributes
   - **SimpleSAMLphp:** a protected page returns the NameID, the IdP entity ID and the attributes
   - it also checks that an existing IdP session signs the user in without showing the login page

`KEEP=1 pnpm e2e` leaves everything running so you can look around in a real browser:
- Keycloak admin: http://localhost:8080 (admin/admin, realm `e2e`)
- SimpleSAMLphp: http://localhost:8081/whoami.php

## External validator: SAMLtool

1. Run the IdP locally or deployed, and sign in through any SP.
2. In your browser's devtools, open the **Network** tab. Find the POST to the SP's ACS URL and copy the `SAMLResponse` form field.
3. Decode it at https://www.samltool.com/decode.php. Then validate the decoded XML at https://www.samltool.com/validate_response.php, pasting in the IdP certificate from `/api/auth/saml2/idp/metadata` and the SP entity ID and ACS URL.

> [!CAUTION]
> SAMLtool is a third-party website. Paste **only throwaway test users and dev keys**, never production assertions: a signed assertion is a credential until it expires.

SAMLtool, Cloudflare Access and AWS need your accounts or browser, so they're recorded as manual evidence in DECISIONS.md.

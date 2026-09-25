# Testing against real service providers

The IdP is checked against several independent SAML implementations, from automated tests that run on every commit up to hosted products that need an account.

| Tier | Service provider | How | Runs in CI |
|---|---|---|---|
| 1 | samlify (strict: message and assertion signatures required) | `test/integration/*.test.ts` | ✅ Node + workerd |
| 1 | **`@better-auth/sso`**, Better Auth's own SAML SP | `test/interop/sp-interop.test.ts` | ✅ Node + workerd |
| 1 | **`@node-saml/node-saml`** (`InResponseTo` validation always on, both signatures required) | `test/interop/sp-interop.test.ts` | ✅ Node + workerd |
| 2 | **Keycloak 26.4** as an identity broker | `pnpm e2e` (Playwright + Chromium, Docker) | ✅ |
| 2 | **SimpleSAMLphp 2.5** SP | `pnpm e2e` (Playwright + Chromium, Docker) | ✅ |
| 2 | **node-saml SP**: HTTP-POST binding, cross-site redirect after its ACS | `pnpm e2e` (Playwright + Chromium) | ✅ |
| 3 | **Cloudflare Access** (Zero Trust) | [sp-cloudflare-access.md](sp-cloudflare-access.md) | manual |
| 3 | **AWS IAM Identity Center** | [sp-aws-iam-identity-center.md](sp-aws-iam-identity-center.md) | manual |
| 3 | HubSpot | [hubspot.md](hubspot.md) | manual, not yet verified |
| 4 | SAMLtool, an external validator | below | manual |

## Tier 2: `pnpm e2e` (Playwright + Chromium)

This needs Docker (`docker compose` or `docker-compose`), `openssl`, Playwright's Chromium (`npx playwright install chromium`), and ports 8787, 8080, 8081, 9100 and 9101 free.

**Why a real browser:** the review found two bugs that only a real browser shows. `SameSite=Lax` cookies aren't sent on an SP's cross-site POST, and CSP `form-action` also applies to the redirect after the ACS. The earlier scripted browser sent every cookie and enforced no CSP. So:
- Everything runs over **HTTPS** with a throwaway CA (`e2e/lib/tls.mjs`, written to the gitignored `e2e/.generated/`).
- Every party is its own **site**: `idp.test`, `kc.test`, `ssp.test`, `sp.test`, `app.test`, resolved by Chromium's `--host-resolver-rules`.

Global setup (`e2e/global-setup.mjs`):
1. starts `examples/workers-hono` on **workerd** (`wrangler dev --local-protocol https`, fresh local D1, `DEV_MAILBOX=true`)
2. starts Keycloak and SimpleSAMLphp over TLS (`e2e/docker-compose.yml`) and a `node-saml` SP with its "app" on another site (`e2e/lib/test-sp.mjs`)
3. configures a Keycloak realm with a SAML identity provider pointing at our IdP, with signatures required

The tests (`e2e/browser/*.spec.mjs`) sign up through the real sign-in page and click the verification link from the dev mailbox. They then assert:
- **what each SP received**, including that Keycloak linked the user and mapped their names
- **no CSP violations** in Chromium's console
- **that the login page isn't shown** when the IdP session already exists, for both the POST and the Redirect binding
- **the IsPassive outcome in both cases**: success with a session, and a signed `NoPassive` without one

`KEEP=1 pnpm e2e` leaves everything running. On failure, Playwright keeps a trace in `test-results/`.

## External validator: SAMLtool

1. Run the IdP locally or deployed, and sign in through any SP.
2. In your browser's devtools, open the **Network** tab. Find the POST to the SP's ACS URL and copy the `SAMLResponse` form field.
3. Decode it at https://www.samltool.com/decode.php. Then validate the decoded XML at https://www.samltool.com/validate_response.php, pasting in the IdP certificate from `/api/auth/saml2/idp/metadata` and the SP entity ID and ACS URL.

> [!CAUTION]
> SAMLtool is a third-party website. Paste **only throwaway test users and dev keys**, never production assertions: a signed assertion is a credential until it expires.

SAMLtool, Cloudflare Access and AWS need your accounts or browser, so they're recorded as manual evidence in DECISIONS.md.

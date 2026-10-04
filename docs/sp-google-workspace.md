# Service provider: Google Workspace

This guide makes Google Workspace send its users' sign-ins to your IdP: they type their email at Google, sign in on your app's page, and land in Gmail, Drive and the rest. You can limit it to one organizational unit, so it's safe to try on a real Workspace.

Verified live on 2026-10-04 (DECISIONS.md D-063) with Google's third-party SSO profiles, assigned to one organizational unit. The Google steps follow the Admin console as it was that day.

## Before you start

- **The users must already exist in Workspace.** Google doesn't create accounts from SAML sign-ins. Create them in the Admin console, or let your app create them: [better-auth-scim-provisioning](https://www.npmjs.com/package/better-auth-scim-provisioning) creates, updates and suspends Workspace users from Better Auth through the Directory API, which is how the live test did it.
- **The NameID must be the user's Workspace primary email.** That's the plugin's default.
- **Super admins always sign in with Google directly**, never through SSO, so you can't lock yourself out.

## 1. Deploy the IdP

Follow [examples/workers-hono](../examples/workers-hono/README.md#deploy). You need:

| | Value |
|---|---|
| IdP entity ID | `https://<worker>.workers.dev/api/auth/saml2/idp` |
| Single Sign-On URL | `https://<worker>.workers.dev/api/auth/saml2/idp/sso` |
| Sign-out URL | `https://<worker>.workers.dev/api/auth/saml2/idp/logout` |
| Signing certificate | Contents of `idp.crt`, or the `<ds:X509Certificate>` from `/api/auth/saml2/idp/metadata`, saved as a `.pem` file |

## 2. Create an SSO profile in Google

**Admin console → Security → Authentication → SSO with third-party IdP → Third-party SSO profiles → Add SAML profile**

| Field | Value |
|---|---|
| SSO profile name | anything, e.g. `Better Auth` |
| IdP entity ID | the entity ID from step 1 |
| Sign-in page URL | the Single Sign-On URL from step 1 |
| Sign-out page URL | the sign-out URL from step 1 |
| Change password URL | leave empty, or your app's page |
| Verification certificate | upload the `.pem` from step 1 |

Leave "Use a domain specific issuer" off. **Save**, then open the profile: under **SP details** Google shows an **Entity ID** and an **ACS URL**, both like `https://accounts.google.com/samlrp/<id>`.

## 3. Register Google as an SP on the IdP

```json
[{ "id": "google-workspace",
   "entityId": "https://accounts.google.com/samlrp/<id>",
   "acsUrls": ["https://accounts.google.com/samlrp/<id>/acs"] }]
```

Put this in `SAML_SERVICE_PROVIDERS`, then redeploy. Leave `nameIdFormat` out (the default is `emailAddress`), or set it to `emailAddress`.

> [!IMPORTANT]
> **Before 1.1.2, `"nameIdFormat": "emailAddress"` broke every Google sign-in.** Google always asks for the emailAddress format by its full URN, and the short name the README documents was compared as given, so the IdP answered `InvalidNameIDPolicy` and Google showed "Couldn't sign you in". On 1.1.1 or earlier, leave `nameIdFormat` out.

## 4. Assign the profile

**SSO with third-party IdP → Manage SSO profile assignments**: select an organizational unit (or a group), choose **Another SSO profile**, pick yours, and **Save**. Start with a test organizational unit holding one test user; assigning it at the top level sends everyone's sign-ins to your IdP.

## 5. Sign in

In a private window, go to https://accounts.google.com and enter the test user's email. Google sends you to your IdP's sign-in page; after you sign in there, you land in the user's Google account. The IdP's audit log (if on) shows an `assertion.issued` for `google-workspace`.

## What Google sends

Google's AuthnRequest, over HTTP-Redirect, unsigned:

```xml
<saml2p:AuthnRequest AssertionConsumerServiceURL="https://accounts.google.com/samlrp/<id>/acs"
    ForceAuthn="false" IsPassive="false" ID="_…" IssueInstant="…" Version="2.0">
  <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://accounts.google.com/samlrp/<id></saml2:Issuer>
  <saml2p:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
</saml2p:AuthnRequest>
```

It asks for no authentication context, and needs no attributes beyond the NameID.

## When Google says "Couldn't sign you in"

That's all Google shows, whatever the reason. Look at the IdP's logs (on Workers, `npx wrangler tail`): a refusal sent back to Google is logged as a warning, such as `[saml-idp] SAML status Responder/InvalidNameIDPolicy for SP google-workspace: The requested NameID format is not available`. If nothing reached the IdP at all, check the profile's sign-in page URL and its assignment. If the IdP issued an assertion and Google still refused, check the verification certificate, and that the user exists in Workspace with that exact primary email and isn't suspended.

## Taking access away

Banning or deleting the user in Better Auth stops new sign-ins through your IdP (verified live: "You have been banned from this application"). To also suspend their Workspace account, do it in the Admin console, or let better-auth-scim-provisioning do it when you ban them in Better Auth (verified live in the same test).

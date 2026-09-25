# Service provider: Cloudflare Access (Zero Trust)

This guide makes Cloudflare Access trust the example IdP, and then protects an app with it. Cloudflare Zero Trust has a free plan (up to 50 users) that supports generic SAML identity providers.

Source for the Cloudflare side: https://developers.cloudflare.com/cloudflare-one/identity/idp-integration/generic-saml/ (checked 2026-09-25).

## 1. Deploy the IdP

Follow [examples/workers-hono](../examples/workers-hono/README.md#deploy). You need:

| | Value |
|---|---|
| IdP entity ID | `https://<worker>.workers.dev/api/auth/saml2/idp` |
| Single Sign-On URL | `https://<worker>.workers.dev/api/auth/saml2/idp/sso` |
| Signing certificate | Contents of `idp.crt`, or the `<ds:X509Certificate>` from `/api/auth/saml2/idp/metadata` |

## 2. Register Cloudflare Access as an SP on the IdP

Cloudflare uses a single URL as both its SP entity ID and its ACS URL. `<team>` is your Zero Trust team name.

```json
[{ "id": "cf-access",
   "entityId": "https://<team>.cloudflareaccess.com/cdn-cgi/access/callback",
   "acsUrls": ["https://<team>.cloudflareaccess.com/cdn-cgi/access/callback"] }]
```

Put this in `SAML_SERVICE_PROVIDERS`, then redeploy. The plugin's default NameID format is `emailAddress`, which is what Cloudflare requires.

> [!IMPORTANT]
> **Cloudflare Access sends a RelayState longer than the SAML spec's 80 bytes.** The plugin's default `relayStateMaxBytes` is 1024 for this reason. Don't lower it to the strict 80 if you use Cloudflare Access, or the IdP answers `RELAY_STATE_TOO_LONG`. This was verified against a real Zero Trust team on 2026-09-25.

## 3. Add the IdP in Zero Trust

**Zero Trust → Integrations → Identity providers → Add new identity provider → SAML**

| Field | Value |
|---|---|
| Name | `better-auth-saml-idp` |
| Single Sign-on URL | the SSO URL from step 1 |
| IdP Entity ID / Issuer URL | the entity ID from step 1 |
| Signing certificate | the certificate from step 1 |
| Email attribute name | `email` (optional; the NameID is already the email) |
| Sign SAML authentication requests | optional. Cloudflare signs over HTTP-Redirect, which the IdP verifies. To require it, set `requireSignedAuthnRequests: true` and give `spCertificate` **both** certificates from Cloudflare's SP metadata. `npx better-auth-saml-idp sp-from-metadata https://<team>.cloudflareaccess.com/cdn-cgi/access/saml-metadata --id cf-access` prints that entry. Verified live on 2026-09-25 (DECISIONS.md D-018) |

Save, then use **Test** on the provider. Run it in a private window: an existing Access session from another login method is reused otherwise, and the result shows that identity instead. You'll be sent to the IdP's `/sign-in` page. After you sign in, Cloudflare shows the identity and attributes it received. **Take a screenshot; this is the Phase 3 evidence.**

## 4. Protect an app (optional, for a real login)

**Access → Applications → Add an application → Self-hosted.** Choose a hostname you control, allow only the `better-auth-saml-idp` login method, and add a policy that allows your email. Visiting the hostname should send you through the IdP.

## 5. Encrypt assertions (optional)

Verified live on 2026-09-25 (DECISIONS.md D-020): Cloudflare decrypted and accepted our AES-256-GCM + RSA-OAEP assertions. With encryption on, it **rejects** plaintext assertions (`Encryption required but assertion not encrypted`).

1. Edit the identity provider in Zero Trust and turn on **Enable SAML encryption**. The setting is stored straight away, and the edit page then shows a **Certificate set ID**. From then on, logins fail until step 3 is done.
2. Get the encryption certificate. The dashboard shows only the set ID, and Cloudflare's SP metadata doesn't include the certificate. The API does: create an API token with **Access: Organizations, Identity Providers, and Groups → Read**, then run:
   ```sh
   curl -s -H "Authorization: Bearer $TOKEN" \
     https://api.cloudflare.com/client/v4/accounts/<account-id>/access/identity_providers \
     | jq -r '.result[] | select(.name=="better-auth-saml-idp") | .saml_certificate_set.current_certificate.public_certificate'
   ```
   The result is RSA 2048 and valid for a year, issued by your account's "Access CA - Cloudflare Managed". Its key usage is *Certificate Sign, CRL Sign*, with no `keyEncipherment`. The plugin doesn't enforce key usage on encryption certificates, so it's accepted.
3. Add it to the SP: `encryption: { certificate: "<that PEM>" }`. The defaults, AES-256-GCM with RSA-OAEP (XML Encryption 1.0), are what Cloudflare expects. Redeploy, then **Test**.
4. Rotation: Cloudflare replaces the certificate 30 days before expiry, and the set's `previous_certificate` keeps the old one. When that happens, update `encryption.certificate`. `npx better-auth-saml-idp check-config` reports the certificate's expiry.

To see what Cloudflare receives, capture the `SAMLResponse` from the browser's network tab. `npx better-auth-saml-idp decode` checks its structure, algorithms and Response signature. Decrypting it would need Cloudflare's private key, which you don't have.

## IdP-initiated SSO: not supported by Cloudflare Access

Tested on 2026-09-25 (DECISIONS.md D-021). With `allowIdpInitiated: true`, the IdP posts a signed, encrypted, unsolicited Response from `/saml2/idp/init?sp=cf-access`, and Access answers **"Invalid login session. Please try going to the URL of your application again."** Its callback only accepts Responses to logins that Access started itself. That limitation is known ([Cloudflare Community](https://community.cloudflare.com/t/idp-initiated-login/290252)). For an app portal, link to the protected application's URL instead, or to the Access App Launcher (`https://<team>.cloudflareaccess.com`). Access then starts an SP-initiated login, which this IdP answers without asking the user to sign in again.

## Troubleshooting

- The IdP returns `ACS_URL_NOT_ALLOWED` or `UNKNOWN_SERVICE_PROVIDER`: the team name in `SAML_SERVICE_PROVIDERS` doesn't match exactly. Compare it with `https://<team>.cloudflareaccess.com/cdn-cgi/access/saml-metadata`.
- `worker exceeded CPU` on the first request: you're on Workers Free; see the note in the example README.

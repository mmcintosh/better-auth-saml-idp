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
> **Cloudflare Access sends a RelayState longer than the SAML spec's 80 bytes.** With the default `relayStateMaxBytes` (80), the IdP answers `RELAY_STATE_TOO_LONG`. Set `relayStateMaxBytes: 1024`, as `examples/workers-hono` does. This was verified against a real Zero Trust team on 2026-09-25.

## 3. Add the IdP in Zero Trust

**Zero Trust → Integrations → Identity providers → Add new identity provider → SAML**

| Field | Value |
|---|---|
| Name | `better-auth-saml-idp` |
| Single Sign-on URL | the SSO URL from step 1 |
| IdP Entity ID / Issuer URL | the entity ID from step 1 |
| Signing certificate | the certificate from step 1 |
| Email attribute name | `email` (optional; the NameID is already the email) |
| Sign SAML authentication requests | **off** (signed requests are only supported with HTTP-Redirect; leave this off unless you also configure `requireSignedAuthnRequests` + `spCertificate`) |

Save, then use **Test** on the provider. Run it in a private window: an existing Access session from another login method is reused otherwise, and the result shows that identity instead. You'll be sent to the IdP's `/sign-in` page. After you sign in, Cloudflare shows the identity and attributes it received. **Take a screenshot; this is the Phase 3 evidence.**

## 4. Protect an app (optional, for a real login)

**Access → Applications → Add an application → Self-hosted.** Choose a hostname you control, allow only the `better-auth-saml-idp` login method, and add a policy that allows your email. Visiting the hostname should send you through the IdP.

## Troubleshooting

- The IdP returns `ACS_URL_NOT_ALLOWED` or `UNKNOWN_SERVICE_PROVIDER`: the team name in `SAML_SERVICE_PROVIDERS` doesn't match exactly. Compare it with `https://<team>.cloudflareaccess.com/cdn-cgi/access/saml-metadata`.
- `worker exceeded CPU` on the first request: you're on Workers Free; see the note in the example README.

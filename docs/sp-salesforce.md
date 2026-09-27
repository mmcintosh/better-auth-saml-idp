# Salesforce as a service provider

Salesforce can accept sign-ins from an external SAML identity provider, so users sign in to Salesforce with their Better Auth account. Verified live on 2026-09-27 with a free Salesforce Developer Edition org. Salesforce's **signed** AuthnRequests (HTTP-Redirect) were verified and required. Our signed assertion was accepted, with the NameID matched to the Salesforce user's Federation ID. **Single Logout** worked both ways. Salesforce is stored in the plugin's database registry (DECISIONS D-042).

Salesforce's request IDs are about 300 characters. Versions of the plugin before this fix refused IDs over 256 (`INVALID_SAML_REQUEST`).

## 1. Turn on SAML in Salesforce

**Setup → Single Sign-On Settings → Edit →** tick **SAML Enabled** → Save. Check that it stayed ticked: without it, your IdP won't appear in My Domain's Authentication Configuration (step 5).

Leave **Disable login with Salesforce credentials** off, so admins can still get in if the IdP is down. **Make Federation ID case-insensitive** is worth ticking.

## 2. Add the IdP

On the same page, **SAML Single Sign-On Settings → New**:

| Field | Value |
|---|---|
| Name | e.g. `Better Auth` |
| Issuer | your `entityId`, e.g. `https://auth.example.com/api/auth/saml2/idp` |
| Identity Provider Certificate | your IdP certificate as a `.crt` file (for example from `npx better-auth-saml-idp inspect`, or the PEM you created with `keygen`) |
| Request Signing Certificate | the default |
| Request Signature Method | `RSA-SHA256` |
| Assertion Decryption Certificate | `Assertion not encrypted` |
| SAML Identity Type | **Assertion contains the Federation ID from the User object** |
| SAML Identity Location | **Identity is in the NameIdentifier element of the Subject statement** |
| Service Provider Initiated Request Binding | `HTTP Redirect` |
| Identity Provider Login URL | `https://auth.example.com/api/auth/saml2/idp/sso` |
| Entity ID | required: your My Domain URL, e.g. `https://yourorg.my.salesforce.com` (any stable value works; it only has to match what you register) |
| Use Salesforce MFA for this SSO provider | off: your Better Auth sign-in is the authentication |
| Single Logout Enabled | on |
| Identity Provider Single Logout URL | `https://auth.example.com/api/auth/saml2/idp/slo` |
| Single Logout Request Binding | `HTTP Redirect` |

Save, then **Download Metadata**.

## 3. Register Salesforce on the IdP

```bash
npx better-auth-saml-idp sp-from-metadata SAMLSP-*.xml --id salesforce
```

This gives the entity ID, the ACS URL (your My Domain URL), `requestSignatures: "require"` and Salesforce's signing certificate. Salesforce signs every AuthnRequest, so keep `require`. If the metadata has no logout endpoint, add it yourself. It's shown under **Endpoints** on the SSO configuration's page:

```ts
singleLogoutService: { url: "https://yourorg.my.salesforce.com/services/auth/sp/saml2/logout", binding: "redirect" },
```

Add it to `serviceProviders`, or store it in the registry. Single Logout also needs `singleLogout: { enabled: true }` on the IdP.

## 4. Match users

Salesforce finds the user by **Federation ID**. By default the NameID is the user's email, so set each Salesforce user's **Federation ID** (Setup → Users → Edit → Single Sign On Information) to their Better Auth email. To match on something else, set that value as the Federation ID and choose the source with [`nameId: { field }`](guide/options.md#service-provider-options), for example an employee number.

## 5. Show the button

**Setup → My Domain → Authentication Configuration → Edit**: tick your SAML configuration, and keep **Login Form** ticked as a way back in. The My Domain login page then shows a button that starts SP-initiated sign-in.

## Troubleshooting

- **The IdP isn't listed in Authentication Configuration:** "SAML Enabled" (step 1) isn't saved.
- **"We are unable to log you out":** "Single Logout Enabled" is off in the SSO configuration.
- **Sign-in fails after our sign-in page:** open **SAML Assertion Validator** on the Single Sign-On Settings page. It loads the last failure. "Unable to map the subject to a Salesforce user", with every check passing, means no user has that Federation ID (step 4).
- **Salesforce emails a code after sign-in:** that's Salesforce's own verification for a new browser, not part of SAML.

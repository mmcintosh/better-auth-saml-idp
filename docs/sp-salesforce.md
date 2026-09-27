# Salesforce as a service provider

Salesforce can accept sign-ins from an external SAML identity provider, so users sign in to Salesforce with their Better Auth account. Verified live on 2026-09-27 with a free Salesforce Developer Edition org. Salesforce's **signed** AuthnRequests (HTTP-Redirect) were verified and required. Our signed assertion was accepted, with the NameID matched to the Salesforce user's Federation ID. Salesforce is stored in the plugin's database registry (DECISIONS D-042).

## 1. Turn on SAML in Salesforce

**Setup → Single Sign-On Settings → Edit →** tick **SAML Enabled** → Save.

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

Save, then **Download Metadata**.

## 3. Register Salesforce on the IdP

```bash
npx better-auth-saml-idp sp-from-metadata SAMLSP-*.xml --id salesforce
```

This gives the entity ID, the ACS URL (your My Domain URL), `requestSignatures: "require"` and Salesforce's signing certificate. Salesforce signs every AuthnRequest, so keep `require`. Add it to `serviceProviders`, or store it in the registry.

## 4. Match users

Salesforce finds the user by **Federation ID**. By default the NameID is the user's email, so set each Salesforce user's **Federation ID** (Setup → Users → Edit → Single Sign On Information) to their Better Auth email. To match on something else, set that value as the Federation ID and choose the source with [`nameId: { field }`](guide/options.md#service-provider-options), for example an employee number.

## 5. Show the button

**Setup → My Domain → Authentication Configuration → Edit**: tick your SAML configuration, and keep **Login Form** ticked as a way back in. The My Domain login page then shows a button that starts SP-initiated sign-in.

## Not yet verified

Single Logout: the downloaded metadata had no `SingleLogoutService`, so logout wasn't registered or tested.

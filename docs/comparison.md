# Comparison with other SAML identity providers

How `better-auth-saml-idp` compares with eleven SAML 2.0 identity providers, checked against each product's official documentation (and, for the open-source ones, their source code) on **2026-09-25**. **Not documented** means the research found no statement either way; it is not the same as *no*. SaaS products are *n/a* for self-hosting rows.

Our own column links to the tests that prove each entry. The roadmap derived from this comparison is in the [README](../README.md#roadmap).

## Where we lead

- **Replay protection you can check.** AuthnRequest replay is rejected by a database unique key and tested under concurrency across separate instances. Most peers don't document replay handling for inbound requests.
- **Strict identity by default.** Only verified email addresses get assertions; admin-impersonation sessions and anonymous users are refused. The user and session are re-read from the database right before signing.
- **Honest protocol answers.** IsPassive, RequestedAuthnContext, Subject and NameIDPolicy are honoured, and failures go back as signed SAML status Responses. authentik, Logto and Ory Polis show HTML errors instead.
- **Runs where your app runs.** A Better Auth plugin that runs on Cloudflare Workers and Node, verified live against Cloudflare Access. Every other self-hosted option here is a separate server.

## Where we trail

- **Breadth of flows.** No IdP-initiated SSO or Single Logout yet.
- **Encryption.** No encrypted assertions yet; several SPs and federations expect the option.
- **SP onboarding.** SPs are configured in code; no metadata import, registry or UI yet.

## Feature matrix

Products: **better-auth-saml-idp** (This plugin, pre-release); **Shibboleth IdP** (Reference, 5.2.3); **SimpleSAMLphp** (Reference, 2.5.3); **Keycloak** (Reference, 26.7.4); **Zitadel** (Open source, main, Sep 2026); **authentik** (Open source, main, Sep 2026); **Logto** (Open source, SAML apps); **Ory Polis** (Open source, SAML Federation (enterprise)); **Microsoft Entra ID** (Commercial, non-gallery apps); **Okta** (Commercial, custom SAML apps); **Google Workspace** (Commercial, custom SAML apps); **Auth0** (Commercial, SAML2 Web App addon).

### Flows

| Feature | better-auth-saml-idp | Shibboleth IdP | SimpleSAMLphp | Keycloak | Zitadel | authentik | Logto | Ory Polis | Microsoft Entra ID | Okta | Google Workspace | Auth0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SP-initiated SSO | ✅ Yes<br><sub>HTTP-Redirect and HTTP-POST in, POST out</sub> | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes<br><sub>brokered to an upstream IdP</sub> | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| IdP-initiated SSO | ❌ No<br><sub>roadmap v1.1</sub> | ✅ Yes | ✅ Yes | ✅ Yes<br><sub>per client</sub> | ❌ No | ✅ Yes | ❌ No | 🟡 Partial<br><sub>OIDC-initiated only</sub> | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Single Logout | ❌ No<br><sub>roadmap v1.2</sub> | ✅ Yes<br><sub>docs call it best-effort</sub> | 🟡 Partial<br><sub>front-channel only</sub> | ✅ Yes<br><sub>front and back channel</sub> | 🟡 Partial<br><sub>responds, ends nothing</sub> | ✅ Yes<br><sub>front and back channel</sub> | ❌ No | ❌ No | ✅ Yes<br><sub>Redirect only</sub> | ✅ Yes<br><sub>back-channel is Early Access</sub> | ❔ Not documented | 🟡 Partial<br><sub>no multi-app logout</sub> |

### Bindings

| Feature | better-auth-saml-idp | Shibboleth IdP | SimpleSAMLphp | Keycloak | Zitadel | authentik | Logto | Ory Polis | Microsoft Entra ID | Okta | Google Workspace | Auth0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AuthnRequest over Redirect and POST | ✅ Yes<br><sub>node-saml's DEFLATEd POST accepted too</sub> | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ❔ Not documented | ❔ Not documented | ❔ Not documented |
| Artifact binding | ❌ No<br><sub>not planned</sub> | 🟡 Partial<br><sub>responses only</sub> | 🟡 Partial<br><sub>responses, needs memcache</sub> | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No<br><sub>responses always POST</sub> | ❔ Not documented | ❔ Not documented | ❔ Not documented |

### Signing and encryption

| Feature | better-auth-saml-idp | Shibboleth IdP | SimpleSAMLphp | Keycloak | Zitadel | authentik | Logto | Ory Polis | Microsoft Entra ID | Okta | Google Workspace | Auth0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Response / Assertion signing choice | 🟡 Partial<br><sub>both signed by default; set globally, not per SP</sub> | ✅ Yes<br><sub>per SP</sub> | ✅ Yes<br><sub>per SP</sub> | ✅ Yes<br><sub>per client</sub> | ❌ No<br><sub>always both</sub> | ✅ Yes<br><sub>per SP</sub> | ❌ No<br><sub>response only</sub> | ❌ No<br><sub>always both</sub> | ✅ Yes | ✅ Yes | 🟡 Partial<br><sub>one checkbox</sub> | 🟡 Partial<br><sub>one or the other</sub> |
| Encrypted assertions | ❌ No<br><sub>roadmap v1.1</sub> | ✅ Yes<br><sub>on by default</sub> | ✅ Yes<br><sub>per SP</sub> | ✅ Yes<br><sub>AES-256-GCM default</sub> | ❌ No | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes<br><sub>needs P1</sub> | ✅ Yes | ❔ Not documented | ✅ Yes<br><sub>via Actions</sub> |
| Verifies and can require signed AuthnRequests | 🟡 Partial<br><sub>HTTP-Redirect only, per SP</sub> | ✅ Yes | ✅ Yes | ✅ Yes | 🟡 Partial<br><sub>instance-wide switch</sub> | ✅ Yes | ✅ Yes | ❌ No<br><sub>checks the key embedded in the request</sub> | ✅ Yes | ✅ Yes | ❔ Not documented | 🟡 Partial<br><sub>can verify; requiring not documented</sub> |
| SHA-256 default, SHA-1 only by opt-in | ✅ Yes<br><sub>opt-in logs a warning</sub> | ✅ Yes | ✅ Yes | ✅ Yes | 🟡 Partial<br><sub>accepts SHA-1 inbound</sub> | ✅ Yes | 🟡 Partial<br><sub>fixed SHA-256</sub> | ✅ Yes<br><sub>fixed SHA-256</sub> | ✅ Yes | ✅ Yes | ❔ Not documented | ❌ No<br><sub>SHA-1 is the default</sub> |
| Signing key rotation | 🟡 Partial<br><sub>publishes extra certificates; switch by hand</sub> | 🟡 Partial<br><sub>manual</sub> | ✅ Yes<br><sub>two-key rollover</sub> | ✅ Yes<br><sub>active and passive keys</sub> | ✅ Yes<br><sub>automatic</sub> | 🟡 Partial<br><sub>manual</sub> | 🟡 Partial<br><sub>one active at a time</sub> | 🟡 Partial<br><sub>single key</sub> | ✅ Yes<br><sub>expiry emails</sub> | ✅ Yes | ✅ Yes<br><sub>two certificates</sub> | 🟡 Partial<br><sub>tenant-wide key</sub> |
| Signed IdP metadata | ❌ No<br><sub>roadmap v1.1</sub> | 🟡 Partial<br><sub>left to federations</sub> | ✅ Yes<br><sub>optional</sub> | ❔ Not documented | ✅ Yes | ✅ Yes | ❔ Not documented | ❔ Not documented | ❔ Not documented | ❔ Not documented | ❔ Not documented | ❔ Not documented |

### Replay and protocol fidelity

| Feature | better-auth-saml-idp | Shibboleth IdP | SimpleSAMLphp | Keycloak | Zitadel | authentik | Logto | Ory Polis | Microsoft Entra ID | Okta | Google Workspace | Auth0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Rejects replayed AuthnRequest IDs | ✅ Yes<br><sub>DB unique key; concurrency and cross-instance tested</sub> | ✅ Yes<br><sub>replay cache</sub> | ❔ Not documented | ❔ Not documented | 🟡 Partial<br><sub>stores ID, no rejection found</sub> | ❔ Not documented | 🟡 Partial<br><sub>stores ID, no rejection found</sub> | ❔ Not documented | ❔ Not documented | ❔ Not documented | ❔ Not documented | ❔ Not documented |
| ForceAuthn, IsPassive, RequestedAuthnContext | ✅ Yes<br><sub>exact match on one configured class</sub> | ✅ Yes | 🟡 Partial | ✅ Yes<br><sub>step-up via LoA</sub> | ❌ No | 🟡 Partial<br><sub>ForceAuthn only</sub> | 🟡 Partial<br><sub>ForceAuthn only</sub> | ❌ No | ✅ Yes<br><sub>RequestedAuthnContext exact only</sub> | 🟡 Partial<br><sub>ForceAuthn setting</sub> | ❔ Not documented | 🟡 Partial<br><sub>no IsPassive</sub> |
| SAML error status Responses | ✅ Yes<br><sub>NoPassive, NoAuthnContext, UnknownPrincipal, InvalidNameIDPolicy</sub> | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No<br><sub>SSO errors are HTML pages</sub> | ❌ No | ❌ No | ✅ Yes | ❔ Not documented | 🟡 Partial<br><sub>mostly error pages</sub> | ❔ Not documented |

### Identity and access

| Feature | better-auth-saml-idp | Shibboleth IdP | SimpleSAMLphp | Keycloak | Zitadel | authentik | Logto | Ory Polis | Microsoft Entra ID | Okta | Google Workspace | Auth0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| NameID formats per SP | ✅ Yes<br><sub>email, persistent (per-SP HMAC), transient, unspecified</sub> | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No<br><sub>fixed; labelled email, carries username</sub> | ✅ Yes | ✅ Yes | 🟡 Partial<br><sub>passes upstream NameID</sub> | ✅ Yes | ✅ Yes | 🟡 Partial | ✅ Yes |
| Attribute mapping | 🟡 Partial<br><sub>per-SP function in code; no declarative map yet</sub> | ✅ Yes<br><sub>declarative + scripts</sub> | ✅ Yes | ✅ Yes<br><sub>mappers + scripts</sub> | 🟡 Partial<br><sub>fixed set + Actions</sub> | ✅ Yes<br><sub>Python mappings</sub> | ✅ Yes<br><sub>declarative</sub> | 🟡 Partial | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Per-SP access control | ✅ Yes<br><sub>authorize() hook, deny = no assertion</sub> | ✅ Yes | 🟡 Partial<br><sub>via authproc filters</sub> | 🟡 Partial<br><sub>via conditional flows</sub> | ✅ Yes<br><sub>per project</sub> | ✅ Yes<br><sub>policy bindings</sub> | ❔ Not documented | 🟡 Partial<br><sub>routing only</sub> | ✅ Yes<br><sub>app assignment</sub> | ✅ Yes<br><sub>app assignment</sub> | ✅ Yes<br><sub>per OU or group</sub> | ❔ Not documented |
| MFA and step-up for SAML | 🟡 Partial<br><sub>host's Better Auth 2FA; no step-up mapping yet</sub> | ✅ Yes | 🟡 Partial<br><sub>via modules</sub> | ✅ Yes | 🟡 Partial<br><sub>MFA, no step-up</sub> | 🟡 Partial<br><sub>ForceAuthn step-up</sub> | 🟡 Partial<br><sub>MFA, no step-up</sub> | ❌ No<br><sub>delegated upstream</sub> | ✅ Yes<br><sub>Conditional Access (P1)</sub> | ✅ Yes<br><sub>policies</sub> | ❔ Not documented | 🟡 Partial |

### Operations

| Feature | better-auth-saml-idp | Shibboleth IdP | SimpleSAMLphp | Keycloak | Zitadel | authentik | Logto | Ory Polis | Microsoft Entra ID | Okta | Google Workspace | Auth0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Register an SP from its metadata XML or URL | ❌ No<br><sub>roadmap v1.1 (XML), v1.2 (URL refresh)</sub> | ✅ Yes<br><sub>file, URL, MDQ</sub> | 🟡 Partial<br><sub>converter, refresh add-on</sub> | ✅ Yes<br><sub>XML import, URL for certificates</sub> | ✅ Yes<br><sub>the only way</sub> | 🟡 Partial<br><sub>file import</sub> | ❌ No | ❌ No | 🟡 Partial<br><sub>fills URLs, not certificates</sub> | ❌ No<br><sub>manual fields</sub> | ❌ No | ❌ No |
| Admin UI or management API for SPs | ❌ No<br><sub>SPs are configured in code; DB registry on roadmap</sub> | ❌ No | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Outbound SCIM provisioning | ❌ No<br><sub>not planned</sub> | ❌ No | ❌ No | 🟡 Partial<br><sub>preview</sub> | ❌ No<br><sub>inbound only</sub> | ✅ Yes | ❔ Not documented | ❌ No<br><sub>inbound only</sub> | ✅ Yes<br><sub>P1</sub> | ✅ Yes | 🟡 Partial<br><sub>catalog apps only</sub> | ❌ No |

### Platform

| Feature | better-auth-saml-idp | Shibboleth IdP | SimpleSAMLphp | Keycloak | Zitadel | authentik | Logto | Ory Polis | Microsoft Entra ID | Okta | Google Workspace | Auth0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Runs on serverless / edge (Cloudflare Workers) | ✅ Yes<br><sub>verified on a live Worker</sub> | ❌ No<br><sub>Java server</sub> | ❔ Not documented | ❌ No<br><sub>Java server</sub> | ❔ Not documented | ❔ Not documented | ❔ Not documented | ❔ Not documented | n/a<br><sub>SaaS</sub> | n/a<br><sub>SaaS</sub> | n/a<br><sub>SaaS</sub> | n/a<br><sub>SaaS</sub> |
| Embeds in an existing app | ✅ Yes<br><sub>a Better Auth plugin</sub> | ❌ No | ❌ No | ❌ No | 🟡 Partial<br><sub>Go library zitadel/saml</sub> | ❌ No | ❌ No | ✅ Yes<br><sub>npm library (licence needed)</sub> | n/a<br><sub>SaaS</sub> | n/a<br><sub>SaaS</sub> | n/a<br><sub>SaaS</sub> | n/a<br><sub>SaaS</sub> |
| Licence and cost | MIT | Apache-2.0 | LGPL-2.1 | Apache-2.0 | AGPL-3.0 | MIT core | MPL-2.0 | Enterprise licence | Free tier covers SAML SSO | Paid, from $6/user/month | Free (Cloud Identity Free) | Free tier, 25k MAU |

## Our evidence

- **SP-initiated SSO:** test/integration/sso-flow.test.ts, e2e/browser
- **AuthnRequest over Redirect and POST:** `test/integration/sso-flow.test.ts`
- **Response / Assertion signing choice:** `test/integration/security.test.ts`
- **Verifies and can require signed AuthnRequests:** test/integration/security.test.ts, review-findings.test.ts #2
- **SHA-256 default, SHA-1 only by opt-in:** `test/unit/options.test.ts`
- **Rejects replayed AuthnRequest IDs:** `test/integration/security.test.ts (R2)`
- **ForceAuthn, IsPassive, RequestedAuthnContext:** `test/integration/review-findings.test.ts #12`
- **SAML error status Responses:** `test/integration/review-findings.test.ts`
- **NameID formats per SP:** `test/integration/review-findings.test.ts #11`
- **Attribute mapping:** `test/integration/sso-flow.test.ts`
- **Per-SP access control:** `test/integration/security.test.ts`
- **Runs on serverless / edge (Cloudflare Workers):** DECISIONS.md D-016, test runs on workerd

## HubSpot's requirements

From [HubSpot's SSO setup guide](https://knowledge.hubspot.com/account-security/set-up-single-sign-on-sso):

- **Plan:** HubSpot Professional or Enterprise (Marketing, Sales, Service, Data, Content Hub, Smart CRM, Revenue Hub).
- **NameID:** Must be the user's email, matching the HubSpot user. Met: emailAddress is the default format.
- **Signing:** SHA-256 only. Met: RSA-SHA256 is the default.
- **Binding:** HTTP-POST. Met.
- **IdP values:** Issuer, SSO URL and a PEM certificate. Met: all in the metadata endpoint.

## Sources

- **better-auth-saml-idp** (pre-release): [Repository](https://github.com/mmcintosh/better-auth-saml-idp), [Decision log](https://github.com/mmcintosh/better-auth-saml-idp/blob/main/DECISIONS.md)
- **Shibboleth IdP** (5.2.3): [Relying party config](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199508680), [Metadata config](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199508402), [Replay cache](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199509576)
- **SimpleSAMLphp** (2.5.3): [IdP setup](https://simplesamlphp.org/docs/stable/simplesamlphp-idp.html), [SP remote reference](https://simplesamlphp.org/docs/stable/simplesamlphp-reference-sp-remote.html), [Key rollover](https://simplesamlphp.org/docs/stable/saml/keyrollover.html)
- **Keycloak** (26.7.4): [SAML client config](https://www.keycloak.org/docs/latest/server_admin/index.html#_client-saml-configuration), [SAML step-up](https://www.keycloak.org/docs/latest/server_admin/index.html#_step-up-authentication-saml)
- **Zitadel** (main, Sep 2026): [SAML guide](https://zitadel.com/docs/guides/integrate/login/saml), [zitadel/saml library](https://github.com/zitadel/saml)
- **authentik** (main, Sep 2026): [SAML provider](https://docs.goauthentik.io/add-secure-apps/providers/saml/), [SAML single logout](https://docs.goauthentik.io/add-secure-apps/providers/saml/saml_single_logout/)
- **Logto** (SAML apps): [SAML apps](https://docs.logto.io/integrate-logto/saml-app), [SAML app setup](https://docs.logto.io/integrate-logto/saml-app/setup)
- **Ory Polis** (SAML Federation (enterprise)): [SAML Federation](https://www.ory.com/docs/polis/saml-federation), [npm library](https://www.ory.com/docs/polis/guides/npm-library)
- **Microsoft Entra ID** (non-gallery apps): [SAML SSO protocol](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol), [Signing options](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/certificate-signing-options), [Token encryption](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/howto-saml-token-encryption)
- **Okta** (custom SAML apps): [SAML app reference](https://help.okta.com/oie/en-us/content/topics/apps/aiw-saml-reference.htm), [Signing certificates](https://developer.okta.com/docs/guides/updating-saml-cert/main/)
- **Google Workspace** (custom SAML apps): [Custom SAML app](https://knowledge.workspace.google.com/admin/apps/set-up-your-own-custom-saml-app), [SAML certificates](https://knowledge.workspace.google.com/admin/apps/maintain-saml-certificates)
- **Auth0** (SAML2 Web App addon): [SAML assertions](https://auth0.com/docs/authenticate/protocols/saml/saml-configuration/customize-saml-assertions), [Sign and encrypt](https://auth0.com/docs/authenticate/protocols/saml/saml-sso-integrations/sign-and-encrypt-saml-requests)

Research method: three parallel reviews of vendor documentation (and source code where the docs were silent), 2026-09-25. Corrections welcome as issues or pull requests.

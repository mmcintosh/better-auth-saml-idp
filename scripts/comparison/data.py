# Single source for docs/comparison.md and the published comparison page.
# y = yes, p = partial, n = no, u = not documented, na = not applicable (SaaS), t = text value
CHECKED = "2026-09-25"
PRODUCTS = [
  # key, name, group, version/tier note, sources
  ("us", "better-auth-saml-idp", "This plugin", "pre-release", [("Repository", "https://github.com/mmcintosh/better-auth-saml-idp"), ("Decision log", "https://github.com/mmcintosh/better-auth-saml-idp/blob/main/DECISIONS.md")]),
  ("shib", "Shibboleth IdP", "Reference", "5.2.3", [("Relying party config", "https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199508680"), ("Metadata config", "https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199508402"), ("Replay cache", "https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199509576")]),
  ("ssp", "SimpleSAMLphp", "Reference", "2.5.3", [("IdP setup", "https://simplesamlphp.org/docs/stable/simplesamlphp-idp.html"), ("SP remote reference", "https://simplesamlphp.org/docs/stable/simplesamlphp-reference-sp-remote.html"), ("Key rollover", "https://simplesamlphp.org/docs/stable/saml/keyrollover.html")]),
  ("kc", "Keycloak", "Reference", "26.7.4", [("SAML client config", "https://www.keycloak.org/docs/latest/server_admin/index.html#_client-saml-configuration"), ("SAML step-up", "https://www.keycloak.org/docs/latest/server_admin/index.html#_step-up-authentication-saml")]),
  ("zit", "Zitadel", "Open source", "main, Sep 2026", [("SAML guide", "https://zitadel.com/docs/guides/integrate/login/saml"), ("zitadel/saml library", "https://github.com/zitadel/saml")]),
  ("ak", "authentik", "Open source", "main, Sep 2026", [("SAML provider", "https://docs.goauthentik.io/add-secure-apps/providers/saml/"), ("SAML single logout", "https://docs.goauthentik.io/add-secure-apps/providers/saml/saml_single_logout/")]),
  ("logto", "Logto", "Open source", "SAML apps", [("SAML apps", "https://docs.logto.io/integrate-logto/saml-app"), ("SAML app setup", "https://docs.logto.io/integrate-logto/saml-app/setup")]),
  ("polis", "Ory Polis", "Open source", "SAML Federation (enterprise)", [("SAML Federation", "https://www.ory.com/docs/polis/saml-federation"), ("npm library", "https://www.ory.com/docs/polis/guides/npm-library")]),
  ("entra", "Microsoft Entra ID", "Commercial", "non-gallery apps", [("SAML SSO protocol", "https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol"), ("Signing options", "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/certificate-signing-options"), ("Token encryption", "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/howto-saml-token-encryption")]),
  ("okta", "Okta", "Commercial", "custom SAML apps", [("SAML app reference", "https://help.okta.com/oie/en-us/content/topics/apps/aiw-saml-reference.htm"), ("Signing certificates", "https://developer.okta.com/docs/guides/updating-saml-cert/main/")]),
  ("gws", "Google Workspace", "Commercial", "custom SAML apps", [("Custom SAML app", "https://knowledge.workspace.google.com/admin/apps/set-up-your-own-custom-saml-app"), ("SAML certificates", "https://knowledge.workspace.google.com/admin/apps/maintain-saml-certificates")]),
  ("auth0", "Auth0", "Commercial", "SAML2 Web App addon", [("SAML assertions", "https://auth0.com/docs/authenticate/protocols/saml/saml-configuration/customize-saml-assertions"), ("Sign and encrypt", "https://auth0.com/docs/authenticate/protocols/saml/saml-sso-integrations/sign-and-encrypt-saml-requests")]),
]
K = [p[0] for p in PRODUCTS]

def row(*vals):
    assert len(vals) == len(K), vals
    return dict(zip(K, vals))

# (group, feature, {key: (status, note)}, our evidence)
FEATURES = [
 ("Flows", "SP-initiated SSO", row(("y","HTTP-Redirect and HTTP-POST in, POST out"),("y",""),("y",""),("y",""),("y",""),("y",""),("y",""),("y","brokered to an upstream IdP"),("y",""),("y",""),("y",""),("y","")), "test/integration/sso-flow.test.ts, e2e/browser"),
 ("Flows", "IdP-initiated SSO", row(("y","opt-in per SP; RelayState allow-list"),("y",""),("y",""),("y","per client"),("n",""),("y",""),("n",""),("p","OIDC-initiated only"),("y",""),("y",""),("y",""),("y","")), "test/integration/idp-initiated.test.ts, test/interop/idp-initiated-interop.test.ts"),
 ("Flows", "Single Logout", row(("n","roadmap v1.2"),("y","docs call it best-effort"),("p","front-channel only"),("y","front and back channel"),("p","responds, ends nothing"),("y","front and back channel"),("n",""),("n",""),("y","Redirect only"),("y","back-channel is Early Access"),("u",""),("p","no multi-app logout")), ""),
 ("Bindings", "AuthnRequest over Redirect and POST", row(("y","node-saml's DEFLATEd POST accepted too"),("y",""),("y",""),("y",""),("y",""),("y",""),("y",""),("y",""),("y",""),("u",""),("u",""),("u","")), "test/integration/sso-flow.test.ts"),
 ("Bindings", "Artifact binding", row(("n","not planned"),("p","responses only"),("p","responses, needs memcache"),("y",""),("n",""),("n",""),("n",""),("n",""),("n","responses always POST"),("u",""),("u",""),("u","")), ""),
 ("Signing and encryption", "Response / Assertion signing choice", row(("y","per SP, with a global default; both signed by default"),("y","per SP"),("y","per SP"),("y","per client"),("n","always both"),("y","per SP"),("n","response only"),("n","always both"),("y",""),("y",""),("p","one checkbox"),("p","one or the other")), "test/integration/security.test.ts"),
 ("Signing and encryption", "Encrypted assertions", row(("y","AES-256-GCM + RSA-OAEP, per SP; verified live with Cloudflare Access, and with node-saml and samlify"),("y","on by default"),("y","per SP"),("y","AES-256-GCM default"),("n",""),("y",""),("y",""),("n",""),("y","needs P1"),("y",""),("u",""),("y","via Actions")), "test/interop/encryption-interop.test.ts, test/unit/encrypt.test.ts"),
 ("Signing and encryption", "Verifies and can require signed AuthnRequests", row(("p","HTTP-Redirect only, per SP; verified live with Cloudflare Access; multiple SP certs"),("y",""),("y",""),("y",""),("p","instance-wide switch"),("y",""),("y",""),("n","checks the key embedded in the request"),("y",""),("y",""),("u",""),("p","can verify; requiring not documented")), "test/integration/security.test.ts, review-findings.test.ts #2"),
 ("Signing and encryption", "SHA-256 default, SHA-1 only by opt-in", row(("y","opt-in logs a warning"),("y",""),("y",""),("y",""),("p","accepts SHA-1 inbound"),("y",""),("p","fixed SHA-256"),("y","fixed SHA-256"),("y",""),("y",""),("u",""),("n","SHA-1 is the default")), "test/unit/options.test.ts"),
 ("Signing and encryption", "Signing key rotation", row(("p","extra certs published; zero-downtime procedure verified live"),("p","manual"),("y","two-key rollover"),("y","active and passive keys"),("y","automatic"),("p","manual"),("p","one active at a time"),("p","single key"),("y","expiry emails"),("y",""),("y","two certificates"),("p","tenant-wide key")), ""),
 ("Signing and encryption", "Signed IdP metadata", row(("y","optional (signMetadata)"),("p","left to federations"),("y","optional"),("u",""),("y",""),("y",""),("u",""),("u",""),("u",""),("u",""),("u",""),("u","")), ""),
 ("Replay and protocol fidelity", "Rejects replayed AuthnRequest IDs", row(("y","DB unique key; concurrency and cross-instance tested"),("y","replay cache"),("u",""),("u",""),("p","stores ID, no rejection found"),("u",""),("p","stores ID, no rejection found"),("u",""),("u",""),("u",""),("u",""),("u","")), "test/integration/security.test.ts (R2)"),
 ("Replay and protocol fidelity", "ForceAuthn, IsPassive, RequestedAuthnContext", row(("y","ForceAuthn verified live with Cloudflare Access; RequestedAuthnContext exact match"),("y",""),("p",""),("y","step-up via LoA"),("n",""),("p","ForceAuthn only"),("p","ForceAuthn only"),("n",""),("y","RequestedAuthnContext exact only"),("p","ForceAuthn setting"),("u",""),("p","no IsPassive")), "test/integration/review-findings.test.ts #12"),
 ("Replay and protocol fidelity", "SAML error status Responses", row(("y","NoPassive, NoAuthnContext, UnknownPrincipal, InvalidNameIDPolicy"),("y",""),("y",""),("y",""),("y",""),("n","SSO errors are HTML pages"),("n",""),("n",""),("y",""),("u",""),("p","mostly error pages"),("u","")), "test/integration/review-findings.test.ts"),
 ("Identity and access", "NameID formats per SP", row(("y","email, persistent (per-SP HMAC), transient, unspecified"),("y",""),("y",""),("y",""),("n","fixed; labelled email, carries username"),("y",""),("y",""),("p","passes upstream NameID"),("y",""),("y",""),("p",""),("y","")), "test/integration/review-findings.test.ts #11"),
 ("Identity and access", "Attribute mapping", row(("y","per SP: declarative map (JSON-friendly) or a function"),("y","declarative + scripts"),("y",""),("y","mappers + scripts"),("p","fixed set + Actions"),("y","Python mappings"),("y","declarative"),("p",""),("y",""),("y",""),("y",""),("y","")), "test/integration/sso-flow.test.ts"),
 ("Identity and access", "Per-SP access control", row(("y","authorize() hook, deny = no assertion"),("y",""),("p","via authproc filters"),("p","via conditional flows"),("y","per project"),("y","policy bindings"),("u",""),("p","routing only"),("y","app assignment"),("y","app assignment"),("y","per OU or group"),("u","")), "test/integration/security.test.ts"),
 ("Identity and access", "MFA and step-up for SAML", row(("p","host's Better Auth 2FA; no step-up mapping yet"),("y",""),("p","via modules"),("y",""),("p","MFA, no step-up"),("p","ForceAuthn step-up"),("p","MFA, no step-up"),("n","delegated upstream"),("y","Conditional Access (P1)"),("y","policies"),("u",""),("p","")), ""),
 ("Operations", "Register an SP from its metadata XML or URL", row(("p","XML import helper; URL refresh on roadmap v1.2"),("y","file, URL, MDQ"),("p","converter, refresh add-on"),("y","XML import, URL for certificates"),("y","the only way"),("p","file import"),("n",""),("n",""),("p","fills URLs, not certificates"),("n","manual fields"),("n",""),("n","")), ""),
 ("Operations", "Admin UI or management API for SPs", row(("n","SPs are configured in code; DB registry on roadmap"),("n",""),("n",""),("y",""),("y",""),("y",""),("y",""),("y",""),("y",""),("y",""),("y",""),("y","")), ""),
 ("Operations", "Outbound SCIM provisioning", row(("n","not planned"),("n",""),("n",""),("p","preview"),("n","inbound only"),("y",""),("u",""),("n","inbound only"),("y","P1"),("y",""),("p","catalog apps only"),("n","")), ""),
 ("Platform", "Runs on serverless / edge (Cloudflare Workers)", row(("y","verified on a live Worker"),("n","Java server"),("u",""),("n","Java server"),("u",""),("u",""),("u",""),("u",""),("na","SaaS"),("na","SaaS"),("na","SaaS"),("na","SaaS")), "DECISIONS.md D-016, test runs on workerd"),
 ("Platform", "Embeds in an existing app", row(("y","a Better Auth plugin"),("n",""),("n",""),("n",""),("p","Go library zitadel/saml"),("n",""),("n",""),("y","npm library (licence needed)"),("na","SaaS"),("na","SaaS"),("na","SaaS"),("na","SaaS")), ""),
 ("Platform", "Licence and cost", row(("t","MIT"),("t","Apache-2.0"),("t","LGPL-2.1"),("t","Apache-2.0"),("t","AGPL-3.0"),("t","MIT core"),("t","MPL-2.0"),("t","Enterprise licence"),("t","Free tier covers SAML SSO"),("t","Paid, from $6/user/month"),("t","Free (Cloud Identity Free)"),("t","Free tier, 25k MAU")), ""),
]

ROADMAP = [
 ("v1.0", "First npm release", "Ship what is built, safely.", [
   ("Release engineering", "dist build with type declarations, lint, npm pack review, provenance, changelog, README quickstart from a clean project."),
   ("better-auth-cloudflare 0.4", "Replace the vendored build once 0.4 is on npm (the README requires it for Workers users)."),
   ("Key rotation guide (done)", "docs/key-rotation.md: add next certificate, switch, retire. Rehearsed live with Cloudflare Access with zero downtime."),
   ("Second adversarial review", "Review the new code paths from the first round: POST re-entry, error Responses, account policy, NameID."),
 ]),
 ("v1.1", "Close the expected-feature gaps", "What admins and SPs assume every IdP has.", [
   ("IdP-initiated SSO (done)", "Opt-in per SP, off by default; RelayState only from a per-SP allow-list. Supported by 8 of the 11 products compared (partially by Ory Polis), including all four commercial IdPs."),
   ("Encrypted assertions (done)", "AES-256-GCM with RSA-OAEP, per SP, sign-then-encrypt. Decrypted and validated by node-saml and samlify. Shibboleth encrypts by default; Keycloak, authentik, Logto, Entra and Okta offer it per SP."),
   ("Register SPs from metadata XML (done)", "serviceProviderFromMetadata(): a helper that turns an SP's metadata into a serviceProviders entry, including certificates and ACS URLs."),
   ("Per-SP signing choice (done)", "Move signResponse and signAssertion to each SP, as Shibboleth, Keycloak and authentik do."),
   ("Signed IdP metadata (done)", "Optional (signMetadata), for SPs and federations that verify metadata signatures."),
 ]),
 ("v1.2", "Operations at scale", "For hosts with many SPs or changing SPs.", [
   ("Single Logout", "SP-initiated, front-channel first. Entra, Okta, Keycloak and authentik support it; Shibboleth calls it best-effort."),
   ("Database-backed SP registry and API", "Add and change SPs at runtime without a redeploy (spec stretch goal)."),
   ("SP metadata URL with refresh", "Pick up SP certificate rotation automatically."),
   ("Signed AuthnRequests over HTTP-POST", "XML-signature verification with XSW defences, pinned to the SP's certificate."),
 ]),
 ("Later", "Considered", "Valuable, but needs design first or depends on the host.", [
   ("Step-up authentication", "Map RequestedAuthnContext to the host's Better Auth 2FA state, as Keycloak does with levels of authentication."),
   ("Declarative attribute mapping (done)", "Per-SP map from attribute name to user field, constant, split list or first/last name; usable from JSON configuration."),
   ("Upstreaming", "Propose integration with @better-auth/sso on better-auth #6254 once v1 is stable."),
 ]),
 ("Not planned", "Out of scope", "Deliberately left out.", [
   ("Artifact binding", "None of the four modern open-source IdPs supports it; no target SP needs it."),
   ("Outbound SCIM", "Provisioning is a separate concern from SSO; a separate plugin if ever."),
   ("Admin UI", "Better Auth hosts build their own UI on the registry API."),
 ]),
]

LEADS = [
 ("Replay protection you can check", "AuthnRequest replay is rejected by a database unique key and tested under concurrency across separate instances. Most peers don't document replay handling for inbound requests."),
 ("Strict identity by default", "Only verified email addresses get assertions; admin-impersonation sessions and anonymous users are refused. The user and session are re-read from the database right before signing."),
 ("Honest protocol answers", "IsPassive, RequestedAuthnContext, Subject and NameIDPolicy are honoured, and failures go back as signed SAML status Responses. authentik, Logto and Ory Polis show HTML errors instead."),
 ("Runs where your app runs", "A Better Auth plugin that runs on Cloudflare Workers and Node, verified live against Cloudflare Access. Every other self-hosted option here is a separate server."),
]
TRAILS = [
 ("Breadth of flows", "No Single Logout yet."),
 ("SP onboarding", "SPs are configured in code or imported from metadata XML; no registry, URL refresh or UI yet."),
]

HUBSPOT = [
 ("Plan", "HubSpot Professional or Enterprise (Marketing, Sales, Service, Data, Content Hub, Smart CRM, Revenue Hub)."),
 ("NameID", "Must be the user's email, matching the HubSpot user. Met: emailAddress is the default format."),
 ("Signing", "SHA-256 only. Met: RSA-SHA256 is the default."),
 ("Binding", "HTTP-POST. Met."),
 ("IdP values", "Issuer, SSO URL and a PEM certificate. Met: all in the metadata endpoint."),
]

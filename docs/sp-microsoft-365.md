# Service provider: Microsoft 365 (Entra ID domain federation)

This guide makes Microsoft 365 send sign-ins for one of your domains to your IdP. Users type their email at Microsoft, sign in on your app's page, and land in Microsoft 365: Outlook, Teams, My Apps and the rest. Federation is set per domain, so you can try it on a spare domain in an existing tenant without touching anyone else.

Verified live on 2026-10-08 (DECISIONS.md D-075): a spare custom domain federated to the example Worker, with two test users who had no licences, signing in at myapps.microsoft.com. Verified again on 2026-10-11 in a separate test tenant (D-076, D-077): Microsoft accepting your IdP's MFA, refusing a password as MFA, and sign-out. The Microsoft steps follow Microsoft Graph PowerShell 2.41, the Graph API and the Entra admin center as they were on those days.

## Before you start

- **A spare custom domain, verified in the tenant.** Not the tenant's default domain, and with no admin accounts on it. Adding a domain for verification costs nothing, and you don't need to set up Exchange or other services on it. Users on the domain sign in through your IdP once it's federated; everyone else is unaffected.
- **A Global Administrator on another domain**, such as the tenant's `*.onmicrosoft.com` one. It signs in at Microsoft as usual, so a broken IdP can't lock you out, and it's the account that runs every step below.
- **The users must already exist in Entra ID.** Microsoft doesn't create accounts from SAML sign-ins. Each user's `onPremisesImmutableId` must equal the NameID your IdP sends (step 3). No licence is needed to sign in.
- **One Microsoft tenant per IdP entity ID.** Microsoft lets an `IssuerUri` federate domains in only one tenant. Federating a second tenant with the same one is refused (`Request_MultipleObjectsWithSameKeyValue`), and can leave that domain half-federated: set it back to `Managed` (see [Taking it back](#taking-it-back)). For a second Microsoft tenant, use a [tenant](guide/multi-tenant.md) of your IdP: it has its own entity ID and URLs (below), and you register Microsoft in that tenant too.
- **Federation is set with Microsoft Graph PowerShell or the Graph API** (see [Without PowerShell](#without-powershell-the-graph-api)), not in the admin center. PowerShell runs on Linux and macOS too (`pwsh`). Install only the modules you need; installing the whole `Microsoft.Graph` module can hang for a long time:

  ```powershell
  Install-PSResource Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users -Scope CurrentUser -TrustRepository
  Connect-MgGraph -Scopes "Domain.ReadWrite.All","User.ReadWrite.All","Directory.AccessAsUser.All"
  ```

## 1. Deploy the IdP

Follow [examples/workers-hono](../examples/workers-hono/README.md#deploy). You need:

| | Value |
|---|---|
| IdP entity ID (Microsoft's `IssuerUri`) | `https://<worker>.workers.dev/api/auth/saml2/idp` |
| Single Sign-On URL (`PassiveSignInUri`) | `https://<worker>.workers.dev/api/auth/saml2/idp/sso` |
| Sign-out URL (`SignOutUri`) | `https://<worker>.workers.dev/api/auth/saml2/idp/slo` |
| Signing certificate | The `<ds:X509Certificate>` value from `/api/auth/saml2/idp/metadata`: one line of base64, without the PEM header and footer |

For a [tenant](guide/multi-tenant.md) of your IdP, use its own values: entity ID `…/saml2/idp/metadata/<tenant>`, `…/sso/<tenant>`, `…/slo/<tenant>`, and the certificate from its own metadata (with `keys: "per-tenant"`, each tenant signs with its own key). On a database that had the registry before tenants, registering Microsoft's entity ID in a second tenant first needs the old `UNIQUE(entityId)` dropped ([how](guide/multi-tenant.md#the-same-sp-in-several-tenants)).

## 2. Register Microsoft as an SP on the IdP

```json
{ "id": "microsoft-365",
  "entityId": "urn:federation:MicrosoftOnline",
  "acsUrls": ["https://login.microsoftonline.com/login.srf"],
  "nameIdFormat": "persistent",
  "nameId": { "field": "id" },
  "attributes": { "IDPEmail": "email" } }
```

Add it to `serviceProviders`, or store it with the [registry](guide/service-providers.md#registry) (on the example's admin page, start from empty JSON and paste it).

- **Add it by configuration, not from metadata.** Microsoft's SAML metadata (`https://nexus.microsoftonline-p.com/federationmetadata/saml20/federationmetadata.xml`) doesn't validate against the SAML metadata schema, so `sp-from-metadata` and the example's metadata import refuse it. The two values above are all it would give you.
- **`nameIdFormat: "persistent"` with a stable value.** Microsoft matches the NameID against the user's `onPremisesImmutableId`. The Better Auth user id never changes and users can't edit it, so it's a good choice. A field users can change, such as the email, would break the link the day it changes.
- **`IDPEmail`** is required by Microsoft and must be the user's sign-in name (UPN). With the users' Better Auth emails equal to their UPNs, `email` does it.

## 3. Link each user to their Better Auth account

Set each Entra user's `onPremisesImmutableId` to the NameID the IdP will send, here their Better Auth user id. Do it **while the domain is still managed** (before step 4). Changing it for users on a federated domain is restricted.

```powershell
Update-MgUser -UserId "user@your-domain.example" -OnPremisesImmutableId "<better-auth user id>"
```

For users created later, set it when creating them. A provisioning tool can create the Entra user with `onPremisesImmutableId` already set, so the user can sign in through the IdP at once.

## 4. Federate the domain

This is the step that changes sign-in, and only for users on this one domain. Save the current state first (`Get-MgDomain -DomainId your-domain.example`, `Get-MgDomainFederationConfiguration -DomainId your-domain.example`) so you have the way back.

```powershell
New-MgDomainFederationConfiguration -DomainId "your-domain.example" `
  -DisplayName "Better Auth SAML IdP" `
  -IssuerUri "https://<worker>.workers.dev/api/auth/saml2/idp" `
  -PassiveSignInUri "https://<worker>.workers.dev/api/auth/saml2/idp/sso" `
  -SignOutUri "https://<worker>.workers.dev/api/auth/saml2/idp/slo" `
  -SigningCertificate "<base64 certificate from step 1>" `
  -PreferredAuthenticationProtocol "saml" `
  -FederatedIdpMfaBehavior "rejectMfaByFederatedIdp"
```

The example starts on `rejectMfaByFederatedIdp`: Microsoft ignores what your IdP says about MFA, and asks for its own whenever its policies want MFA. Switch to accept once your IdP reports MFA honestly ([MFA at your IdP](#mfa-at-your-idp)). For signing out at Microsoft to sign the user out of your IdP too, see [Sign-out](#sign-out).

### Without PowerShell: the Graph API

Everything above can be done with `az rest` against Microsoft Graph, as a Global Administrator signed in with `az login --tenant <tenant>`. There's nothing to install beyond the Azure CLI.

| Step | Call |
|---|---|
| Add the domain | `POST /v1.0/domains` with `{"id": "your-domain.example"}` |
| Get the verification record | `GET /v1.0/domains/your-domain.example/verificationDnsRecords` (add only the TXT record) |
| Verify | `POST /v1.0/domains/your-domain.example/verify` |
| Link a user (step 3) | `PATCH /v1.0/users/<user id or UPN>` with `{"onPremisesImmutableId": "<better-auth user id>"}`, while the domain is still managed |
| Federate (step 4) | `POST /v1.0/domains/your-domain.example/federationConfiguration` with the body below |
| Accept the IdP's MFA | `PATCH /v1.0/domains/your-domain.example/federationConfiguration/<id>` with `{"federatedIdpMfaBehavior": "acceptIfMfaDoneByFederatedIdp"}` |
| Undo | `DELETE /v1.0/domains/your-domain.example/federationConfiguration/<id>`, then `PATCH /v1.0/domains/your-domain.example` with `{"authenticationType": "Managed"}` |

```json
{ "@odata.type": "#microsoft.graph.internalDomainFederation",
  "displayName": "Better Auth SAML IdP",
  "issuerUri": "https://<worker>.workers.dev/api/auth/saml2/idp",
  "passiveSignInUri": "https://<worker>.workers.dev/api/auth/saml2/idp/sso",
  "signOutUri": "https://<worker>.workers.dev/api/auth/saml2/idp/slo",
  "signingCertificate": "<base64 certificate from step 1>",
  "preferredAuthenticationProtocol": "saml",
  "federatedIdpMfaBehavior": "rejectMfaByFederatedIdp" }
```

Reading `federationConfiguration` on a domain that isn't federated returns `Request_ResourceNotFound`, which just means there is none.

`Get-MgDomain -DomainId your-domain.example` then shows `AuthenticationType` **Federated**. Allow up to about 15 minutes. Until then, Microsoft's sign-in page may still ask some users for a Microsoft password.

## 5. Sign in

In a private window, go to https://myapps.microsoft.com and enter a test user's email. Microsoft sends you to your IdP's sign-in page; after you sign in there, you land in Microsoft 365. The IdP's audit log (if on) shows an `assertion.issued` for `microsoft-365`. Microsoft may first ask "Stay signed in?": that's normal, and its sign-in log shows it as interrupt `50140`.

## MFA at your IdP

Microsoft can accept MFA done at your IdP instead of asking for its own. Two things are needed:

1. **Your IdP says when the user did MFA.** Microsoft reads the `AuthnContextClassRef` `http://schemas.microsoft.com/claims/multipleauthn` as "MFA done". Use [step-up levels](guide/flows.md#requestedauthncontext), reporting that class for sessions that passed a second factor:

   ```ts
   samlIdp({
     // …
     authnContext: {
       levels: [
         "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
         "http://schemas.microsoft.com/claims/multipleauthn",
       ],
       current: ({ session }) =>
         ["totp", "backup-code", "passkey"].includes(session.authMethod)
           ? "http://schemas.microsoft.com/claims/multipleauthn"
           : "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
     },
   });
   ```

   Judge the **session**, not the user: a user with two-step sign-in on can still hold a session from before they turned it on, and an admin impersonating them never entered their code. The [Workers example](../examples/workers-hono/README.md#two-step-sign-in) stores how each session was signed in, in a session field set by a `databaseHooks.session.create.before` hook from the endpoint that created it (`/two-factor/verify-totp`, `/two-factor/verify-backup-code`, `/passkey/verify-authentication`, `/admin/impersonate-user`, anything else a password). Since 1.4.0, the `assertion.issued` event and the audit log record the class sent (`authnContextClassRef`), so you can see what Microsoft was told.

2. **Microsoft accepts it**, for this domain only:

   ```powershell
   $fed = Get-MgDomainFederationConfiguration -DomainId "your-domain.example"
   Update-MgDomainFederationConfiguration -DomainId "your-domain.example" -InternalDomainFederationId $fed.Id -FederatedIdpMfaBehavior "acceptIfMfaDoneByFederatedIdp"
   ```

Verified on 2026-10-11 in a test tenant with security defaults **off** and `acceptIfMfaDoneByFederatedIdp`:

- **Second factor at your IdP: straight in.** Microsoft took `multipleauthn` as MFA both with per-user MFA set to Enforced and with a Conditional Access policy requiring MFA (Entra ID P1 or P2). The sign-in log's authentication details say "MFA requirement satisfied by claim in the token".
- **Password only at your IdP: Microsoft asks for its own MFA.** With `PasswordProtectedTransport`, the user got "Let's keep your account secure" (Microsoft's own MFA setup). Microsoft doesn't take a password as MFA.

> [!IMPORTANT]
> **Security defaults still ask for Microsoft Authenticator.** With the tenant's security defaults on, every user must register Microsoft Authenticator, whatever MFA your IdP did. A user who hasn't registered it gets "Let's keep your account secure" after signing in at your IdP (sign-in log interrupt `50072`). Security defaults also require MFA only now and then, so most sign-ins show "Single-factor authentication" in Microsoft's sign-in log either way. For Microsoft to rely on your IdP's MFA, turn security defaults off and require MFA with per-user MFA or Conditional Access. That affects every user in the tenant, so try it in a separate test tenant first.

An SP other than Microsoft that asks for exactly `PasswordProtectedTransport` would get `NoAuthnContext` from an MFA session. `current` also receives the SP and its request ([step-up](guide/flows.md#requestedauthncontext)), so it can answer such an SP with the password class.

## Sign-out

When a user signs out at Microsoft, Microsoft sends a LogoutRequest to the `SignOutUri`. For it to end the session at your IdP:

1. Turn on [Single Logout](guide/single-logout.md) (`singleLogout: { enabled: true }`) and give Microsoft's SP entry a `singleLogoutService`. Without one, the IdP refuses Microsoft's request (`LOGOUT_NOT_SUPPORTED`).

   ```json
   "singleLogoutService": { "url": "https://login.microsoftonline.com/login.srf", "binding": "post" }
   ```

2. **Leave Microsoft's certificate off the SP entry.** Microsoft signs its LogoutRequest with RSA-SHA1, which the IdP refuses unless `signing.allowInsecureSha1` is on. Without a certificate, the request is authenticated by its SessionIndex: Microsoft sends back the one your IdP issued with the assertion.

Microsoft sends the request from a hidden iframe on its sign-out page, which never gets your IdP's session cookie. Since 1.5.0, the IdP finds the session from the SessionIndex (D-076). Earlier versions answer the request but end nothing, so the next sign-in at Microsoft goes through without asking.

Verified live on 2026-10-11 with the example Worker: after signing out at myapps.microsoft.com, the next sign-in stopped at the IdP's sign-in page.

## When something goes wrong

- **`AADSTS51004: The user account <id> does not exist in the … directory`:** your IdP sent a NameID no Entra user has as `onPremisesImmutableId`. Most often it's the user who was already signed in to your IdP in that browser, not the one you meant: test in a private window, or sign out of your IdP first.
- **Microsoft still asks for a password, or shows an error before reaching your IdP:** the federation may not have settled yet (step 4). Check `https://login.microsoftonline.com/getuserrealm.srf?login=user@your-domain.example&json=1`: `NameSpaceType` should be `Federated`, with `AuthURL` pointing at your SSO URL.
- **Your IdP issued an assertion, and Microsoft refused it:** check the signing certificate in the federation configuration, the user's `onPremisesImmutableId` against the NameID sent (the audit log's `nameId`), and `IDPEmail` against the user's UPN.
- **Microsoft's sign-in logs** (Entra admin center → Users → the user → Sign-in logs) show each attempt with an error code and an Authentication Details tab. They can take 5 to 30 minutes to appear. With the Graph API: `GET /beta/auditLogs/signIns?$filter=userId eq '<id>'` (the beta version includes `authenticationDetails`).

## Taking it back

Any time, as the Global Administrator from "Before you start":

```powershell
$fed = Get-MgDomainFederationConfiguration -DomainId "your-domain.example"
Remove-MgDomainFederationConfiguration -DomainId "your-domain.example" -InternalDomainFederationId $fed.Id
Update-MgDomain -DomainId "your-domain.example" -AuthenticationType "Managed"
```

Users on the domain then sign in at Microsoft with their Microsoft passwords again. To stop one user, ban or delete them in Better Auth: the IdP then refuses their sign-in.

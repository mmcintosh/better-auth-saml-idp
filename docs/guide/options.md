# Options reference

[Guide](README.md) › Options

Every option `samlIdp()` accepts. Options are validated when `samlIdp()` is called: problems throw `SamlIdpConfigError` listing every issue, and warnings are logged once. `npx better-auth-saml-idp check-config config.json` runs the same validation from the command line.

- [Server options](#server-options)
- [`signing`](#signing)
- [`accountPolicy`](#accountpolicy)
- [`registry`](#registry)
- [`singleLogout`](#singlelogout)
- [`schema`](#schema)
- [Service provider options](#service-provider-options)
- [`encryption`](#encryption)
- [`metadata`](#metadata)
- [`organization`](#organization)
- [`attributes`](#attributes)
- [Client plugin](#client-plugin)

## Server options

| Option | Type | Default | Description |
|---|---|---|---|
| `entityId` | `string` | **required** | The IdP's entity ID, published in metadata and sent as the `Issuer` of every Response. Usually `https://<host>/<basePath>/saml2/idp`. SPs pin it, so choose it once. |
| `baseURL` | `string` | request host | The Better Auth base URL the IdP builds its own URLs from: the SSO URL in metadata, the expected `Destination`, resume links. Without it they follow the request's `Host` header, and a warning is logged. **Set it in production.** An absolute http(s) URL without query or fragment. |
| `loginPage` | `string` | **required** | Where signed-out users are sent, with `?callbackURL=<absolute resume URL>`. A path starting with `/` (not `//`), or an absolute http(s) URL. Backslashes, whitespace and control characters are refused. See [the sign-in page contract](getting-started.md#5-return-users-from-your-sign-in-page). |
| `signing` | `object` | **required** | The IdP's key and certificate, and signing choices. See [`signing`](#signing). |
| `serviceProviders` | `ServiceProviderConfig[]` | **required** | SPs defined in code. May be `[]` with a `registry`. See [Service provider options](#service-provider-options). |
| `assertionLifetimeSeconds` | `number` | `300` | How long an assertion is valid (`NotOnOrAfter`). 30 to 3600; above 300 logs a warning. |
| `clockSkewSeconds` | `number` | `60` | Tolerance for clock differences, applied to `NotBefore` and to request `IssueInstant` checks. 0 to 300. |
| `pendingRequestTtlSeconds` | `number` | `600` | How long a request waits while the user signs in (the `resume` link's lifetime). 60 to 3600. |
| `relayStateMaxBytes` | `number` | `1024` | Largest RelayState accepted, in UTF-8 bytes. 80 (the spec's limit) to 1024. Cloudflare Access sends more than 80. |
| `authnContextClassRef` | `string` | `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified` | The authentication context asserted, and matched against an SP's `RequestedAuthnContext`. Set it to what your sign-in actually guarantees, for example `…:PasswordProtectedTransport`. |
| `accountPolicy` | `object` | strict | Who may receive assertions. See [`accountPolicy`](#accountpolicy). |
| `registry` | `object` | off | The database-backed SP registry and its API. See [`registry`](#registry). |
| `singleLogout` | `object` | off | SAML Single Logout. See [`singleLogout`](#singlelogout). |
| `events` | `object` | none | `{ onAssertionIssued?, onDenied?, onLogout? }` callbacks. They run in the background and can't affect the flow. See [Observability](observability.md). |
| `auditLog` | `object` | off | `{ enabled, retentionDays? }`: also record events in the `samlIdpAuditEvent` table. See [`auditLog`](#auditlog). |
| `signMetadata` | `boolean` | `false` | Sign the IdP metadata document (enveloped signature with the active key). For SPs and federations that verify metadata. |
| `schema` | `object` | none | Rename the plugin's tables and columns. See [`schema`](#schema). |
| `schemaValidator` | `{ validate(xml, kind) }` | libxml2 (WASM) | Replace the XSD validator every inbound message goes through. You shouldn't need this. |

## `signing`

| Option | Type | Default | Description |
|---|---|---|---|
| `privateKey` | PEM `string` | **required** | The IdP's RSA private key (PKCS#1 or PKCS#8, unencrypted), 2048 bits or more. Only this key signs. Keep it in a secret store. |
| `certificate` | PEM `string` | **required** | The X.509 certificate matching `privateKey`, published in metadata. A mismatch is a startup error. Expiry only warns (30 days ahead), so a certificate expiring never takes your site down. |
| `additionalCertificates` | PEM `string[]` | `[]` | Published in metadata but never used to sign: the next key before a rotation, the previous one after. See [key rotation](../key-rotation.md). |
| `signatureAlgorithm` | `"rsa-sha256" \| "rsa-sha512" \| "rsa-sha1"` | `"rsa-sha256"` | Signature algorithm for everything the IdP signs. `rsa-sha1` also needs `allowInsecureSha1`. |
| `digestAlgorithm` | `"sha256" \| "sha512" \| "sha1"` | `"sha256"` | Digest algorithm. `sha1` also needs `allowInsecureSha1`. |
| `allowInsecureSha1` | `boolean` | `false` | Allow SHA-1: for signing with the options above, and for accepting SHA-1-signed requests. Logs a warning. Only for SPs that can't do SHA-256. |
| `signResponse` | `boolean` | `true` | Sign the `<Response>`. Each SP can override it. |
| `signAssertion` | `boolean` | `true` | Sign the `<Assertion>`. Each SP can override it. At least one of the two must be on. |

## `accountPolicy`

| Option | Type | Default | Description |
|---|---|---|---|
| `requireEmailVerified` | `boolean` | `true` | Refuse users whose email isn't verified (`EMAIL_NOT_VERIFIED`). An IdP vouches for identities; an unverified address isn't one. |
| `allowImpersonatedSessions` | `boolean` | `false` | Allow sessions created by the admin plugin's impersonation (`SESSION_NOT_ALLOWED` otherwise). |
| `allowAnonymousUsers` | `boolean` | `false` | Allow users of the anonymous plugin (`SESSION_NOT_ALLOWED` otherwise). |

## `registry`

SPs stored in the database, managed at runtime. See [Service providers › Registry](service-providers.md#registry).

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | `boolean` | **required** | Adds the `samlIdpServiceProvider` table and looks SPs up there after the code SPs. |
| `canManage` | `({ user, session }) => boolean \| Promise<boolean>` | none | Who may use the HTTP API. Must return exactly `true`; a throw denies. |
| `permissions` | `boolean` | `false` | Check each API action (`list`, `read`, `create`, `update`, `delete` on `samlServiceProvider`) against the admin plugin's access control. See [Organizations and permissions](users-and-access.md#registry-permissions). With `canManage` too, both must allow. |
| `cacheSeconds` | `number` | `60` | How long each isolate caches a stored SP, and a miss. 0 to 3600. Other isolates see changes within this window. |
| `authorize` | `(ctx) => boolean \| Promise<boolean>` | allow | `authorize` for stored SPs (functions can't be stored). |

The API is mounted only when `canManage` or `permissions` is set.

## `singleLogout`

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | `boolean` | **required** | Adds the `samlIdpSessionParticipant` table, the `/saml2/idp/slo` and `/saml2/idp/logout` endpoints, and `SingleLogoutService` in metadata. SPs take part with their [`singleLogoutService`](#service-provider-options). |

## `auditLog`

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | `boolean` | **required** | Adds the [`samlIdpAuditEvent`](schema.md#samlidpauditevent-with-auditlogenabled) table and records every event in it, except refusals that identify neither an SP nor a user. See [Observability](observability.md#audit-log-table). |
| `retentionDays` | `number` | `90` | How long rows are kept before the sweep deletes them. 1 to 3650. |

## `schema`

Rename tables or columns, as with other Better Auth plugins. Field maps use schema property keys (for Drizzle, the property names), not raw column names.

```ts
schema: {
  samlIdpSeenRequest: { modelName: "saml_replay", fields: { expiresAt: "expires" } },
  samlIdpServiceProvider: { modelName: "saml_sps" },
  samlIdpSessionParticipant: { fields: { sessionKey: "session_hash" } },
  samlIdpAuditEvent: { modelName: "saml_audit" },
}
```

The fields of each table are in the [schema reference](schema.md).

## Service provider options

The same options apply to SPs in `serviceProviders` and to SPs stored in the registry, except the function-valued ones (`nameId`, a function `attributes`, `authorize`), which only code SPs can have.

| Option | Type | Default | Description |
|---|---|---|---|
| `id` | `string` | **required** | Your name for the SP, 1 to 64 of `A–Z a–z 0–9 _ -`. Used in logs, `/init?sp=` and the registry. Unique. |
| `entityId` | `string` | **required** | The SP's entity ID, matched **exactly** against the request's `Issuer`. Unique. |
| `acsUrls` | `string[]` | **required** | Allow-list of Assertion Consumer Service URLs. A requested URL must match one exactly; with none requested, the first is used. https only (http only for `localhost`, `127.0.0.1` and `[::1]`). |
| `nameIdFormat` | `string` | `emailAddress` | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `…:2.0:nameid-format:persistent`, `…:2.0:nameid-format:transient` or `…:1.1:nameid-format:unspecified` (NAMEID_FORMAT exports these). See [NameID](users-and-access.md#nameid). |
| `nameId` | `(user) => string` | per format | Custom NameID value (code SPs only). |
| `attributes` | map or `(user, { organizations, organization }) => Record<string, string \| string[]>` | none | The `<AttributeStatement>`. See [`attributes`](#attributes). |
| `authorize` | `({ user, session, serviceProvider, organizations }) => boolean \| Promise<boolean>` | allow | Decide per user and SP. Anything but `true`, or a throw, is `ACCESS_DENIED` (code SPs only). |
| `organization` | `{ slug?, id?, roles? }` | none | Only members of this organization, with one of `roles` if given. See [`organization`](#organization). |
| `requireSignedAuthnRequests` | `boolean` | `false` | Refuse unsigned requests. Needs `spCertificate` or `metadata.url`. |
| `spCertificate` | PEM `string \| string[]` | none | The SP's signing certificates. Any of them may have signed (SPs rotate keys; Cloudflare Access publishes two). Parsed and checked (RSA) at startup. |
| `metadata` | `object` | none | Keep the SP's certificates current from its metadata URL. See [`metadata`](#metadata). |
| `encryption` | `object` | none | Encrypt assertions to this SP. See [`encryption`](#encryption). |
| `signResponse` | `boolean` | `signing.signResponse` | Per-SP override. |
| `signAssertion` | `boolean` | `signing.signAssertion` | Per-SP override. At least one of the two must stay on (with encryption, the assertion is always signed when the Response isn't). |
| `allowIdpInitiated` | `boolean` | `false` | Accept `/saml2/idp/init?sp=<id>` for this SP. See [IdP-initiated SSO](flows.md#idp-initiated-sso). |
| `idpInitiatedRelayState` | `string` | none | RelayState sent with IdP-initiated Responses. Needs `allowIdpInitiated`. |
| `allowedRelayStates` | `string[]` | `[]` | RelayState values a caller of `/init` may choose, matched exactly. Anything else is replaced by `idpInitiatedRelayState`. Needs `allowIdpInitiated`. |
| `singleLogoutService` | `{ url, binding?, responseUrl? }` | none | Where the SP receives logout messages. `binding`: `"redirect"` (default) or `"post"`. `responseUrl`: where LogoutResponses go, if not `url` (metadata's `ResponseLocation`). See [Single Logout](single-logout.md). |

## `encryption`

| Option | Type | Default | Description |
|---|---|---|---|
| `certificate` | PEM `string` | **required** | The SP's encryption certificate: RSA, 2048 bits or more. Key usage isn't enforced (Cloudflare's has none for encryption). |
| `dataAlgorithm` | `"aes256-gcm" \| "aes128-gcm" \| "aes256-cbc"` | `"aes256-gcm"` | Content encryption. `aes256-cbc` also needs `allowInsecureCbc`. |
| `keyAlgorithm` | `"rsa-oaep" \| "rsa-oaep-sha256"` | `"rsa-oaep"` | Key transport. `rsa-oaep` is `xmlenc#rsa-oaep-mgf1p` (widest support). `rsa-oaep-sha256` is `xmlenc11#rsa-oaep` with SHA-256, which node-saml and samlify can't decrypt. RSA PKCS#1 v1.5 isn't offered. |
| `allowInsecureCbc` | `boolean` | `false` | Allow AES-CBC for SPs without GCM. Logs a warning. |

## `metadata`

| Option | Type | Default | Description |
|---|---|---|---|
| `url` | `string` | **required** | The SP's metadata URL, https only. Fetched with a 5 s timeout, redirects not followed, 1 MiB at most (streamed), then XSD-validated. |
| `refreshSeconds` | `number` | `86400` | How often to refresh. 300 to 604800. Failures retry after 5 minutes, doubling. |
| `signingCertificate` | PEM `string \| string[]` | none | Pin the metadata's own signature; unsigned or wrongly signed metadata is rejected. Without it a warning is logged and trust rests on TLS. |

Only certificates are taken from metadata: signing certificates are **added** to `spCertificate`, and with `encryption` on, the metadata's encryption certificate **replaces** `encryption.certificate`. The entity ID must match, and ACS URLs always come from your configuration. See [Keeping SP certificates current](service-providers.md#keeping-sp-certificates-current).

## `organization`

| Option | Type | Description |
|---|---|---|
| `slug` | `string` | The organization's slug. Give exactly one of `slug` and `id`. |
| `id` | `string` | The organization's id. |
| `roles` | `string[]` | Only members holding at least one of these roles. |

Needs Better Auth's organization plugin; without it, the SP refuses everyone (`ACCESS_DENIED`).

## `attributes`

A function, or a map from attribute name to a source:

| Source | Example | Value |
|---|---|---|
| user field | `"email"`, `"role"` | The user's own property (core or additional field). |
| `{ field, split?, part? }` | `{ field: "teams", split: "," }`, `{ field: "name", part: "first" }` | A field split into several values, and/or its first word (`"first"`) or the rest (`"last"`). |
| `{ value }` | `{ value: "Acme" }`, `{ value: ["a", "b"] }` | A constant. |
| `{ organization, only? }` | `{ organization: "slugs", only: ["org_1"] }` | `"slugs"`, `"names"`, `"ids"` or `"roles"` of the organizations in `only` (ids or slugs); without `only`, the SP's `organization` if it has one, else all of the user's (roles as `"slug:role"`). Users can create organizations, so prefer rules by id and set `only`. |

Null, empty and object values are left out; dates become ISO 8601; arrays are multi-valued. A field the user doesn't have is logged once per SP. Attribute names are 1 to 256 characters; field names match `[A-Za-z_][A-Za-z0-9_]{0,63}`. See [Attributes](users-and-access.md#attributes).

## Client plugin

```ts
import { samlIdpClient } from "better-auth-saml-idp/client";
createAuthClient({ plugins: [samlIdpClient()] });
```

| Member | Description |
|---|---|
| `authClient.samlIdp.serviceProviders.{list,get,create,update,delete}` | The registry API, typed from the server plugin. |
| `authClient.samlIdp.logoutUrl({ returnTo? })` | URL of IdP-initiated Single Logout. |
| `authClient.samlIdp.signOutEverywhere({ returnTo? })` | Navigate there. |
| `authClient.samlIdp.launchUrl(spId, { relayState? })` | URL of IdP-initiated SSO. |
| `authClient.samlIdp.launch(spId, { relayState? })` | Navigate there. |

URLs are built from the client's `baseURL` and `basePath` (default `/api/auth`).

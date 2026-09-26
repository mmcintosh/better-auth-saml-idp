# Service providers

[Guide](README.md) › Service providers

An SP (service provider) is an application users sign in to through the IdP. There are three ways to register one, and they can be combined:

| | Where it lives | Can use functions | Changes need |
|---|---|---|---|
| [In code](#in-code) | `serviceProviders` | yes | a deploy |
| [From metadata](#from-metadata) | `serviceProviders`, built by a helper | yes | a deploy |
| [Registry](#registry) | the `samlIdpServiceProvider` table | no (JSON) | an API call |

SPs defined in code always win: the registry can't add an SP with the same `id` or entity ID.

## In code

```ts
samlIdp({
  // …
  serviceProviders: [
    {
      id: "hubspot",                       // your name for it: logs, /init?sp=, registry
      entityId: "https://api.hubspot.com/…", // must equal the AuthnRequest Issuer exactly
      acsUrls: ["https://api.hubspot.com/…/acs"],
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      attributes: { email: "email", firstName: { field: "name", part: "first" } },
    },
  ],
});
```

All options are in the [options reference](options.md#service-provider-options). To find an SP's entity ID and ACS URL, look in its SAML settings, in its metadata, or in an AuthnRequest it sends (`npx better-auth-saml-idp decode "<URL>"` shows both).

On Workers, the example reads SPs from a JSON variable, so adding one is a config change, not a code change: see [Cloudflare Workers](cloudflare-workers.md).

## From metadata

Most SPs publish metadata. Turn it into an entry:

```ts
import { serviceProviderFromMetadata } from "better-auth-saml-idp";

const { serviceProvider, encryptionCertificates, warnings } = await serviceProviderFromMetadata(xml, {
  id: "cf-access",                      // required
  attributes: { email: "email" },       // anything you pass wins over the metadata
});
```

Or from the command line (prints JSON):

```bash
npx better-auth-saml-idp sp-from-metadata https://sp.example.com/saml/metadata --id my-sp
npx better-auth-saml-idp sp-from-metadata sp-metadata.xml --id my-sp --entity-id <one entity from an aggregate>
```

What it reads:

| From the metadata | Becomes |
|---|---|
| `entityID` | `entityId` |
| HTTP-POST `AssertionConsumerService`s, default first, then by `index` | `acsUrls` (other bindings are listed in `warnings`) |
| The first supported `NameIDFormat` | `nameIdFormat` |
| `KeyDescriptor` `use="signing"` (or no `use`) certificates | `spCertificate` |
| `AuthnRequestsSigned="true"` | `requireSignedAuthnRequests` (with the certificates) |
| `SingleLogoutService` (Redirect preferred; `Location` for requests, `ResponseLocation` for responses) | `singleLogoutService` |
| `KeyDescriptor` `use="encryption"` certificates | returned separately as `encryptionCertificates`; encryption isn't turned on for you |

The document is size-checked, refused if it has a DOCTYPE, validated against the metadata XSD and strictly parsed. **Its own signature isn't checked by this helper**: fetch it over a channel you trust, review the result, and keep it in your code. To keep certificates current automatically (with optional signature pinning), use [`metadata.url`](#keeping-sp-certificates-current).

## Registry

Store SPs in the database and manage them at runtime, without a deploy:

```ts
samlIdp({
  // …
  serviceProviders: [], // code SPs still work alongside
  registry: {
    enabled: true,
    canManage: ({ user }) => user.role === "admin",  // or permissions: true, see below
    cacheSeconds: 60,                                 // default
  },
});
```

Enabling it adds the `samlIdpServiceProvider` table ([schema](schema.md#samlidpserviceprovider-with-registryenabled)).

### How stored SPs behave

- **Plain JSON.** A stored SP has the same options as a code SP minus functions, so `attributes` must be a [map](users-and-access.md#declarative-map), and `authorize` comes from `registry.authorize`.
- **Validated on every write and every read.** The API refuses an invalid configuration, with the same messages as startup validation. A row that no longer validates (edited by hand, or after an options change) is ignored at sign-in, logged, and shown as `valid: false` in the API.
- **Code wins.** The API refuses the `id` or entity ID of a code SP (`SERVICE_PROVIDER_IN_CODE`), and such a row is never used.
- **Lookups are exact:** an SP is found only by exactly its entity ID or id, even on databases whose collation is case-insensitive.
- **Cached per isolate** for `cacheSeconds`, misses included, so unknown issuers don't each cost a database read. A change is visible at once in the isolate that made it, and within `cacheSeconds` everywhere else, including rows edited in the database directly (the API is the supported way to change SPs). Use `0` to always read (more database load).
- **Disable instead of delete:** `enabled: false` makes the SP unknown without losing its configuration.

### Registry API

The API is mounted when `canManage` or `permissions` is set. Every call needs a signed-in user whose session is re-read from the database; see [Registry permissions](users-and-access.md#registry-permissions) for who's allowed.

| Method | Path | Body / query | Returns |
|---|---|---|---|
| GET | `/saml-idp/service-providers` | | `{ serviceProviders: [...] }`: code SPs (`source: "code"`) and stored SPs (`source: "database"`, with `config`, `enabled`, `valid`, `issues`, timestamps, `updatedBy`) |
| GET | `/saml-idp/service-providers/get` | `?id=` | `{ serviceProvider }` |
| POST | `/saml-idp/service-providers/create` | `{ serviceProvider, enabled? }` | `{ serviceProvider, warnings }` |
| POST | `/saml-idp/service-providers/update` | `{ id, serviceProvider, enabled? }` (full replacement; `id` can't change) | `{ serviceProvider, warnings }` |
| POST | `/saml-idp/service-providers/delete` | `{ id }` | `{ deleted }` |

With the [client plugin](options.md#client-plugin):

```ts
const { data, error } = await authClient.samlIdp.serviceProviders.create({
  serviceProvider: {
    id: "zoom",
    entityId: "https://example.zoom.us",
    acsUrls: ["https://example.zoom.us/saml/SSO"],
    attributes: { email: "email", firstName: { field: "name", part: "first" } },
    organization: { id: "org_8f3…" }, // by id: slugs can be claimed by whoever creates them first
  },
});
if (error?.code === "INVALID_SERVICE_PROVIDER") console.log(error.issues);
```

Or on the server:

```ts
await auth.api.samlIdpCreateServiceProvider({ body: { serviceProvider }, headers });
```

Every change is logged: `[saml-idp] registry: user <id> created SP zoom (https://example.zoom.us)`. Errors are in the [error reference](errors.md#registry-api-errors-json).

The plugin doesn't ship an admin UI; the API and the client plugin are designed for building one into your app.

## Keeping SP certificates current

SPs rotate their signing and encryption keys. Instead of copying certificates into your configuration, point at the SP's metadata:

```ts
{
  id: "cf-access",
  entityId: "https://team.cloudflareaccess.com/cdn-cgi/access/callback",
  acsUrls: ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"],
  requireSignedAuthnRequests: true,
  metadata: {
    url: "https://team.cloudflareaccess.com/cdn-cgi/access/saml-metadata",
    refreshSeconds: 86400,                 // default: daily
    signingCertificate: federationCert,    // optional: pin the metadata's own signature
  },
}
```

**Only certificates are taken from metadata.**
- Its signing certificates are **added** to `spCertificate`.
- With `encryption` configured, its encryption certificate **replaces** `encryption.certificate`. Your algorithms stay.
- The entity ID in the metadata must equal the configured one.
- **ACS URLs always come from your configuration**, so a compromised metadata URL can't redirect assertions.

**Fetching.** https only, 5 s timeout, redirects not followed, 1 MiB at most (enforced while streaming), then the XSD check, a strict parse, and a refusal when `validUntil` has passed. With `signingCertificate`, the metadata's signature must verify with it (the same [hardened verifier](security.md#xml-signature-verification)); otherwise a startup warning notes that trust rests on TLS.

**Freshness.**
- The first use in each isolate waits for the fetch (5 s at most).
- After that, requests use the cached copy while a due refresh runs in the background (`waitUntil` on Workers, through Better Auth's background tasks).
- A failure keeps the last good copy, or your configured certificates if there's none, and retries after 5 minutes, doubling up to `refreshSeconds`.
- Changing the URL, the pin, the entity ID or the encryption settings starts afresh, so certificates learned under an old pin are dropped.

Verified live with Cloudflare Access: signed requests verified with certificates learned only from its metadata.

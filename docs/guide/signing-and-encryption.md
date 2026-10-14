# Signing, encryption and keys

[Guide](README.md) › Signing, encryption and keys

## The IdP's signing key

Every Response the IdP sends is signed with its RSA key. SPs verify it with the certificate from your metadata (or one you give them).

```ts
signing: {
  privateKey: env.SAML_IDP_PRIVATE_KEY,   // RSA ≥ 2048 bits, PKCS#1 or PKCS#8, unencrypted
  certificate: env.SAML_IDP_CERT,         // must match the key
  additionalCertificates: [nextCert],     // published, never used to sign (rotation)
  signatureAlgorithm: "rsa-sha256",       // default; or rsa-sha512
  digestAlgorithm: "sha256",              // default; or sha512
}
```

Or let the plugin make and keep the key itself: [`signing: { managed: true }`](#a-key-the-plugin-manages).

Create a key with `npx better-auth-saml-idp keygen` ([getting started](getting-started.md#2-create-a-signing-key)). At startup the key is parsed once, checked to be RSA with 2048 bits or more, and checked against the certificate. Certificate expiry only **warns**, 30 days ahead, and never fails: a certificate expiring must not take your whole site down. `npx better-auth-saml-idp inspect` and `check-config` show the expiry too.

### What gets signed

By default, **both** the `<Response>` and the `<Assertion>` are signed: an enveloped XML signature, exclusive C14N, placed after the `Issuer` as the schema requires. Some SPs want only one:

```ts
signing: { /* … */, sign: "both" },                  // global default
serviceProviders: [
  { id: "legacy", /* … */, sign: "assertion" },     // this SP: assertion only
],
```

There is no way to sign neither. With encryption, the assertion is signed before it's encrypted whenever `sign` includes it.

### SHA-1

For SPs that can't do SHA-256, you can opt in:

```ts
signing: { /* … */, signatureAlgorithm: "rsa-sha1", digestAlgorithm: "sha1", allowInsecureSha1: true },
```

This logs a warning at startup, and it also allows SHA-1-signed requests. Avoid it where you can.

### Rotation

SPs pin your certificate, so rotate in three steps, each deployed and tested:

1. **Publish the next certificate** in `additionalCertificates`. SPs that read your metadata pick it up; add it by hand everywhere else, alongside the current one.
2. **Switch:** the next key and certificate become `privateKey` and `certificate`, and the old certificate moves to `additionalCertificates`.
3. **Retire** the old certificate from the SPs and from `additionalCertificates`.

The full procedure, rehearsed live with Cloudflare Access (including a zero-downtime switch), is in [docs/key-rotation.md](../key-rotation.md).

### A key the plugin manages

Instead of a key you make and keep yourself, the plugin can make and keep one (D-080):

```ts
signing: { managed: true },   // signatureAlgorithm, digestAlgorithm, allowInsecureSha1 and sign work as above
```

- **Made when first needed.** The first request that needs the key generates it: the metadata, a sign-in, or listing the keys. It's RSA 3072, with a two-year self-signed certificate named after your IdP's host (CN `saml-idp auth.example.com`). Concurrent first requests, on any number of isolates or servers, end up with one key: the table's UNIQUE index decides, and without it the extra keys are removed as soon as they're seen. To have it made before any SP asks, call `GET /saml-idp/signing-keys` as a manager during setup, or fetch the metadata.
- **Stored encrypted** in `samlIdpTenantKey`, the table per-tenant keys use, so run your migration ([Schema](schema.md#samlidptenantkey-with-per-tenant-or-managed-keys)). Its rows belong to the owner `saml-idp:root`. The private key is sealed with Better Auth's secret (its versioned `secrets`, else `secret`), or with `signing.keyEncryptionSecret`, and the sealed text names its purpose, owner and key id. This protects backups, dumps and read-only database leaks. It doesn't protect against a compromised server, which holds the secret too.
- **Never another key.** If the stored key can't be used, the metadata answers 500 and sign-ins are refused. That happens when it can't be decrypted, or when an activation was cut short. The plugin never signs with anything else, and never makes a new key while key rows exist. If every row is lost (a restore from before the key existed, or the table recreated), the next request makes a new key, and SPs need its certificate.
- **The secret it's sealed with matters.** By default that's Better Auth's secret. Rotating Better Auth's secret normally only signs users out; here, without the old version kept in `secrets`, the stored key can't be decrypted and the IdP stops signing (see [Recovering](#recovering-a-managed-key)). Set `signing.keyEncryptionSecret` to a secret of its own, which you don't rotate with the rest, and keep every version that sealed a stored key until that key is rotated out.
- **CPU.** Generating an RSA 3072 key takes a few hundred milliseconds of CPU, once per key. That's more than the Workers Free plan allows a request: on Free, give the key with `privateKey` and `certificate` instead.
- **Reported.** Generating it is a [`signing-key.changed`](observability.md#event-callbacks) event (`action: "key.generated"`, with no user), and a row in the audit log when that's on.
- **Database reads.** Like stored SPs, the stored key's rows are cached per isolate for `registry.cacheSeconds` (60 s by default). With 0, every sign-in reads them again.

#### Switching an existing deployment

Turning on `managed: true` where SPs already trust a key you gave as PEM would make a **new** key, and those SPs would refuse its signatures. Bring the current key along instead:

```ts
signing: { managed: true, initialKey: { privateKey: env.SAML_IDP_PRIVATE_KEY, certificate: env.SAML_IDP_CERT } },
```

The first request that needs a key stores `initialKey` as the active one, instead of generating one (a `signing-key.changed` event with `key.imported`), and logs that it can now be removed from the options. It's only used while no key is stored; if it's none of the stored keys, a warning says it isn't used. If you published a next certificate in `additionalCertificates`, finish or undo that rotation first: a managed key publishes only the keys it stores.

#### Rotating a managed key

The same three steps as above, through the registry API. They need a host manager: `canManage`, or with `permissions` the `samlSigningKey` statement ([Registry permissions](users-and-access.md#registry-permissions)).

| Step | Call |
|---|---|
| List | `GET /saml-idp/signing-keys` returns `{ keys, warnings }`. Each key has its `kid`, `state`, `certificate`, `notAfter`, `createdAt` and `activatedAt`, and the next key its `activatableAt`. `warnings` lists certificates that expire within 30 days, or have. |
| Publish the next key | `POST /saml-idp/signing-keys/rotate` with `{}` to generate one, or `{ privateKey, certificate }` to upload your own (a matching RSA pair, 2048 bits or more). |
| Switch | `POST /saml-idp/signing-keys/activate`, once the next key has been published for `signing.minPublishedSeconds` (default 86400, 24 hours), so SPs that read your metadata have it. `{ force: true }` skips the wait, for a leaked key; the event says `forced`. The active key stays published as the previous one. |
| Retire | `POST /saml-idp/signing-keys/retire`: the previous certificate is no longer published, and its private key is erased. |

With the client plugin: `authClient.samlIdp.signingKeys()`, `.rotate({})`, `.activate({})` and `.retire({})`. Each step is a `signing-key.changed` event with the acting `userId`. Most SPs pin the certificate by hand, so give them the next certificate (the list shows it) before you activate it.

Without the registry API for host managers, the key is still made and used, but there's nothing to rotate it with; a startup warning says so. Any host manager can rotate it: with `canManage`, everyone it allows (it isn't told which action), so give `samlSigningKey` to fewer roles with `permissions` if that matters.

**Wait between activating and retiring.** Each isolate caches the key rows for `registry.cacheSeconds`, so for that long after `activate` other isolates may still sign with the previous key. Retire it only after that time (and after any SP that fetches your metadata has had time to fetch the new one). The same applies to [assertion exchange](token-exchange.md): it checks only the active key's signature, so assertions signed just before an activation can't be exchanged after it.

#### Recovering a managed key

- **It can't be decrypted** (a secret version dropped, or the row damaged): `rotate` to make a new key, `activate` it with `{ force: true }` (there's nothing to wait for: the old key can't sign anyway), then `retire` the old one. None of these steps needs to decrypt the old key. Every SP that pins the certificate then needs the new one.
- **An activation was cut short** (no active key, a next one waiting): call `activate` again; it finishes the switch.

### Signed metadata

```ts
samlIdp({ /* … */, signMetadata: true });
```

The metadata document gets an enveloped signature with the active key, placed as the schema requires, and still validates against the metadata XSD. It's for SPs and federations that verify metadata signatures.

## Encrypted assertions

Encrypt the assertion so only the SP can read it (the Response itself stays signed):

```ts
{
  id: "zoom",
  entityId: "…",
  acsUrls: ["…"],
  encryption: {
    certificate: zoomEncryptionCert,  // the SP's encryption certificate (RSA ≥ 2048)
    dataAlgorithm: "aes256-gcm",      // default; or aes128-gcm, or aes256-cbc + allowInsecureCbc
    keyAlgorithm: "rsa-oaep",         // default; or rsa-oaep-sha256
  },
}
```

- **Order:** sign the assertion, encrypt that signed assertion into `<saml:EncryptedAssertion>`, then sign the Response. The SP decrypts, then verifies the assertion's signature.
- **Fresh keys:** a new AES key and IV for every assertion. The key is wrapped with RSA-OAEP for the SP's certificate. RSA PKCS#1 v1.5 isn't offered.
- **Interop:** decrypted by node-saml (Node and Workers) and samlify (Node), and verified live with **Cloudflare Access**. `rsa-oaep-sha256` (`xmlenc11#rsa-oaep`) is available, but node-saml and samlify can't decrypt it.
- **Key rotation:** the SP's encryption certificate can come from its [metadata URL](service-providers.md#keeping-sp-certificates-current).
- **Where the SP's certificate comes from:** usually its metadata (`use="encryption"`); `sp-from-metadata` returns it. Cloudflare Access only provides it through its API; see the [Cloudflare guide](../sp-cloudflare-access.md#5-encrypt-assertions-optional).

To check what an SP receives, capture the `SAMLResponse` and run `npx better-auth-saml-idp decode "<SAMLResponse=…>" --idp https://auth.example.com --key sp.key`. It decrypts with the SP's key, if you have it, and verifies both signatures.

## Signed requests from SPs

How the IdP verifies SPs' signatures (both bindings), and which algorithms it accepts, is in [Security › Signed requests](security.md#signed-requests).

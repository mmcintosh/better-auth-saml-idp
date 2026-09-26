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

Create a key with `npx better-auth-saml-idp keygen` ([getting started](getting-started.md#2-create-a-signing-key)). At startup the key is parsed once, checked to be RSA with 2048 bits or more, and checked against the certificate. Certificate expiry only **warns**, 30 days ahead, and never fails: a certificate expiring must not take your whole site down. `npx better-auth-saml-idp inspect` and `check-config` show the expiry too.

### What gets signed

By default, **both** the `<Response>` and the `<Assertion>` are signed: an enveloped XML signature, exclusive C14N, placed after the `Issuer` as the schema requires. Some SPs want only one:

```ts
signing: { /* … */, signResponse: true, signAssertion: true },   // global defaults
serviceProviders: [
  { id: "legacy", /* … */, signResponse: false },                // this SP: assertion only
],
```

At least one must stay on, and with encryption, the assertion is always signed when the Response isn't.

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

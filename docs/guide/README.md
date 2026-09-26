# better-auth-saml-idp guide

Everything about running Better Auth as a SAML 2.0 Identity Provider. New here? Start with **[Getting started](getting-started.md)**.

## Guides

| Page | What's in it |
|---|---|
| [Getting started](getting-started.md) | Install, create a key, configure, migrate, connect your sign-in page, register an SP, check it |
| [Service providers](service-providers.md) | SPs in code, from metadata, and in the database registry (with its API); keeping SP certificates current |
| [Sign-in flows](flows.md) | Endpoints; SP-initiated SSO over both bindings; ForceAuthn, IsPassive, RequestedAuthnContext; IdP-initiated SSO; metadata |
| [Users and access](users-and-access.md) | Account policy, NameID formats, attributes, organizations, `authorize`, registry permissions |
| [Signing, encryption and keys](signing-and-encryption.md) | The IdP's key, what gets signed, SHA-1, rotation, signed metadata, encrypted assertions |
| [Single Logout](single-logout.md) | SP- and IdP-initiated logout, how it's authenticated, its limits |
| [Using with `@better-auth/sso`](better-auth-sso.md) | Better Auth on both sides, and using both plugins as an identity broker |
| [Databases](databases.md) | Which databases CI proves, creating tables, MongoDB notes |
| [Cloudflare Workers](cloudflare-workers.md) | Requirements, `withCloudflare`, `waitUntil`, secrets, D1 migrations |
| [Command-line tool](cli.md) | `inspect`, `decode`, `request`, `smoke`, `sp-from-metadata`, `check-config`, `keygen` |
| [Troubleshooting](troubleshooting.md) | Common problems by symptom |

## Reference

| Page | What's in it |
|---|---|
| [Options](options.md) | Every option, its type, default and effect |
| [Errors](errors.md) | Every error code, when it happens and what to do; SAML status Responses |
| [Security](security.md) | Every control: how it works, its options, the errors it produces |
| [Schema](schema.md) | Every table and field |

## SP guides

[Cloudflare Access](../sp-cloudflare-access.md) · [Okta](../sp-okta.md) · [Auth0](../sp-auth0.md) · [HubSpot](../hubspot.md) · [AWS IAM Identity Center](../sp-aws-iam-identity-center.md) · [Testing with other SPs](../testing-with-sps.md)

## Background

- [Threat model](../security.md): the attacks each control answers, and known limitations
- [Key rotation](../key-rotation.md): the zero-downtime procedure
- [DECISIONS.md](../../DECISIONS.md): every design decision, with its tests, mutation proofs and review findings
- [Feature comparison](https://mmcintosh.github.io/better-auth-saml-idp/comparison/) with eleven other SAML IdPs

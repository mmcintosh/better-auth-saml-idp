# Command-line tool

[Guide](README.md) › CLI

The package includes a CLI for checking and debugging an IdP. It runs on Node, with nothing extra to install:

```bash
npx better-auth-saml-idp <command> [options]
```

Every command takes `--json` for machine-readable output. Exit codes: `0` means OK, `1` means a check failed, and `2` means a usage or input error, so it works in scripts and CI. The CLI only reads from an IdP (except `smoke`, which sends test requests) and never needs the IdP's private key.

Common options: `--base-path <path>` (where Better Auth is mounted, default `/api/auth`), and `--allow-http` (allow `http://` URLs, for local development).

## `inspect <idp-url>`

What SPs see when they read your metadata.

```bash
npx better-auth-saml-idp inspect https://auth.example.com
npx better-auth-saml-idp inspect https://auth.example.com --cert idp.crt   # pin the metadata signature
```

Reports the HTTP headers, XSD validity, entity ID, SSO (and SLO) URLs, NameID formats, `WantAuthnRequestsSigned`, and each certificate (subject, key size, expiry in days, SHA-256 fingerprint). Checks: an expired certificate or a key under 2048 bits is a failure, expiry within 30 days is a warning, and an SSO URL on another host than the metadata is a warning (is `baseURL` pinned?). With signed metadata, it verifies the signature (and with `--cert`, against the pinned certificate).

## `decode [input]`

Explains a captured SAML message and verifies it the way the IdP does.

```bash
# a Redirect URL, a form body, base64, or XML: as an argument, a file, or - for stdin
npx better-auth-saml-idp decode "https://auth.example.com/api/auth/saml2/idp/sso?SAMLRequest=…"
npx better-auth-saml-idp decode "SAMLResponse=PHNhbWxwOl…" --idp https://auth.example.com --sp <SP entity ID>
pbpaste | npx better-auth-saml-idp decode - --cert idp.crt --key sp.key --xml
```

| Option | For |
|---|---|
| `--cert <file>` | Certificate(s) to verify with: the IdP's for Responses, the SP's for requests (repeatable) |
| `--idp <url>` | Take the IdP's certificates from its metadata, and check the Issuer |
| `--key <file>` | The SP's private key, to decrypt an `EncryptedAssertion` |
| `--sp <entity-id>` | Check the Audience |
| `--acs <url>` | Check `Destination` and `Recipient` |
| `--request-id <id>` | Check `InResponseTo` |
| `--sso <url>` | Check an AuthnRequest's `Destination` |
| `--xml` | Also print the XML (and the decrypted assertion) |

- **For a Response** it shows the status, Issuer, Destination and InResponseTo; each signature (Response and Assertion) is verified with the same hardened verifier the IdP uses, so wrapped or duplicate-ID messages are reported invalid. It shows the NameID, SubjectConfirmation, Conditions (with how long ago or ahead), Audience, AuthnStatement and attributes, and checks the XSD.
- **For an AuthnRequest** it runs the IdP's validation (without the age limit, so captured requests can be explained) and verifies Redirect or POST signatures with `--cert`.
- A captured Response being expired is only a warning.

## `request <idp-url> --sp <entity-id>`

Builds an AuthnRequest to try the IdP by hand: open the URL in a browser.

```bash
npx better-auth-saml-idp request https://auth.example.com --sp https://sp.example.com --acs https://sp.example.com/acs
npx better-auth-saml-idp request https://auth.example.com --sp … --passive --name-id-format persistent
npx better-auth-saml-idp request https://auth.example.com --sp … --binding post --sign-key sp.key > form.html
```

Options: `--acs`, `--binding redirect|post`, `--relay-state`, `--force-authn`, `--passive`, `--name-id-format email|persistent|transient|<URI>`, `--authn-context <URI>`, `--sign-key <file>` (a query signature for redirect, an XML signature for post) and `--sig-alg rsa-sha256|rsa-sha512`. The URL (or HTML form) is the only thing on stdout.

## `smoke <idp-url> --sp <entity-id>`

15 security checks against a deployed IdP, with no user needed. It only leaves short-lived rows, which the IdP sweeps.

```bash
npx better-auth-saml-idp smoke https://auth.example.com --sp https://sp.example.com --acs https://sp.example.com/acs
```

It checks:
- metadata headers;
- an unknown SP and an unlisted ACS URL, both refused without being reflected;
- replay;
- duplicate or encoded parameters;
- RelayState limits;
- DOCTYPE, schema, stale and zone-less timestamps, and the wrong message type;
- a DEFLATE bomb;
- a signed `NoPassive` Response verified against the metadata certificate;
- the POST binding's same-site re-entry being single-use;
- a malformed `resume` link.

The `--sp` must be registered on the IdP.

## `sp-from-metadata [file|url|-]`

Prints a `serviceProviders` entry for an SP's metadata, as JSON on stdout (the report goes to stderr).

```bash
npx better-auth-saml-idp sp-from-metadata https://sp.example.com/saml/metadata --id my-sp > sp.json
```

`--id` names the SP; `--entity-id` picks one entity from an aggregate. If the SP publishes an encryption certificate, `encryption` is included. Fetched metadata isn't signature-checked, so review it; see [From metadata](service-providers.md#from-metadata).

## `check-config <file>`

Runs the plugin's startup validation on your options, without starting the app.

```bash
npx better-auth-saml-idp check-config saml.json    # PEMs as "file:./idp.crt", relative to the file
npx better-auth-saml-idp check-config saml.mjs     # a module exporting the options (default or samlIdpOptions)
```

Lists every issue and warning, summarises the IdP and each SP (signing, encryption, signed requests, IdP-initiated, attributes, metadata refresh), and checks every certificate's expiry and key.

## `keygen`

Creates an RSA key and a self-signed certificate for the IdP.

```bash
npx better-auth-saml-idp keygen --cert-out idp.crt --key-out idp.key                           # files (key mode 0600)
npx better-auth-saml-idp keygen --cert-out idp.crt | npx wrangler secret put SAML_IDP_PRIVATE_KEY  # key to a pipe
```

Options: `--cn` (default `better-auth-saml-idp`), `--days` (730), `--bits` (2048, 3072 or 4096; default 3072) and `--force` (replace existing files; they're recreated, never reused). It refuses to print a private key to a terminal, and verifies the certificate against the key before writing anything.

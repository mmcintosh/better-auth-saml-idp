# Rotating the IdP signing key

Every SP pins your IdP's signing certificate. Rotating the key means getting each SP to trust the new certificate **before** you start signing with it, then retiring the old one. Done in that order, sign-in never breaks.

This procedure was rehearsed end to end against Cloudflare Access on 2026-09-25 (DECISIONS.md D-019), including a zero-downtime switch.

## How the plugin supports it

- `signing.privateKey` / `signing.certificate` hold the **active** key. Only this key signs.
- `signing.additionalCertificates` holds certificates that are **published in metadata but not used to sign**: the next key before the switch, and the previous key for a short grace period after it.
- Expired or soon-to-expire certificates only produce **warnings** at startup (30-day advance notice), never an outage.

## Procedure

1. **Create the next key pair**, and keep the private key secret:
   ```sh
   openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 730 -subj "/CN=my-idp (next)" -keyout next.key -out next.crt
   ```
2. **Publish the next certificate.** Put `next.crt` in `signing.additionalCertificates` and deploy. Signing doesn't change.
3. **Make every SP trust the next certificate *as well as* the current one.**
   - SPs that read your metadata URL pick it up on their next refresh.
   - Everywhere else, add it by hand **as an additional certificate**, keeping the current one (see the SP notes below).
   - Test each SP. It should still work, since you're still signing with the current key.
4. **Switch.** Move `next.key`/`next.crt` into `signing.privateKey`/`signing.certificate`, put the *old* certificate in `additionalCertificates`, and deploy. Test each SP. No SP configuration changes at this step.
5. **Retire the old certificate.** Remove it from each SP and from `additionalCertificates`, deploy, and test again.
6. **Destroy the old private key** and any local copies of the new one (`shred -u`). On Workers, the keys only need to live in `wrangler secret`.

If step 4 breaks an SP, that SP didn't really trust the next certificate. Switch back by swapping the two again, and fix that SP before retrying.

## SP-specific notes

### Cloudflare Access

- **Add each certificate as a separate entry** with the button for adding another certificate in the SAML identity provider's settings. Cloudflare then accepts a Response signed by either one.
- **Don't paste two PEM blocks into one certificate box.** Cloudflare saves it without complaint, but then trusts **neither** certificate. Every login fails with `SAML Verify: Invalid SAML response, SAML verify: Response uses a certificate that is not configured.` (seen in the rehearsal).
- Access doesn't read IdP metadata, so steps 3 and 5 are manual.

### Workers deployments (examples/workers-hono)

The example reads `SAML_IDP_PRIVATE_KEY`, `SAML_IDP_CERT` and `SAML_IDP_ADDITIONAL_CERTS` (concatenated PEMs) from secrets:

```sh
npx wrangler secret put SAML_IDP_ADDITIONAL_CERTS < next.crt   # step 2
npx wrangler secret put SAML_IDP_PRIVATE_KEY < next.key        # step 4
npx wrangler secret put SAML_IDP_CERT < next.crt               # step 4
npx wrangler secret put SAML_IDP_ADDITIONAL_CERTS < old.crt    # step 4 (grace period)
npx wrangler secret delete SAML_IDP_ADDITIONAL_CERTS           # step 5
```

Each `wrangler secret` command deploys a new version immediately. After step 5, check that `/api/auth/saml2/idp/metadata` lists only the new certificate.

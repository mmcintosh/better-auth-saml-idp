#!/bin/sh
# Generates a throwaway IdP signing key + self-signed cert and writes .dev.vars (gitignored).
# For production, create the key pair yourself and `wrangler secret put` each value.
set -eu
dir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 -subj "/CN=better-auth-saml-idp dev" \
  -keyout "$dir/key.pem" -out "$dir/cert.pem" 2>/dev/null
secret=$(openssl rand -base64 32)
esc() { awk 'BEGIN{ORS="\\n"} {print}' "$1"; }
{
  printf 'BETTER_AUTH_SECRET="%s"\n' "$secret"
  printf 'SAML_IDP_PRIVATE_KEY="%s"\n' "$(esc "$dir/key.pem")"
  printf 'SAML_IDP_CERT="%s"\n' "$(esc "$dir/cert.pem")"
} > .dev.vars
rm -rf "$dir"
echo "wrote .dev.vars (dev-only key pair)"

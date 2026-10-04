#!/bin/sh
# Deploys the Workers example (examples/workers-hono) as a separate benchmark Worker,
# better-auth-saml-idp-bench, with its own D1 database saml-idp-bench, a fresh signing key, one
# dummy SP (https://bench.invalid, never contacted: responses are only returned, not posted), and
# Better Auth's rate limit off (RATE_LIMIT=off), so a load test from one machine measures the IdP,
# not the per-IP limit. Everything else is the example as it ships.
#
#   sh scripts/bench/deploy.sh          first run creates the database and secrets; later runs redeploy
#   sh scripts/bench/deploy.sh delete   removes the Worker and its database when you're done
set -eu
cd "$(dirname "$0")/../../examples/workers-hono"
cfg=wrangler.bench.jsonc
dbid() { npx wrangler d1 list --json 2>/dev/null | node -e 'const d = JSON.parse(require("fs").readFileSync(0, "utf8")); process.stdout.write(d.find((x) => x.name === "saml-idp-bench")?.uuid ?? "")'; }

if [ "${1:-}" = "delete" ]; then
  npx wrangler delete -c "$cfg" || true
  npx wrangler d1 delete saml-idp-bench -y || true
  rm -f "$cfg"
  exit 0
fi

if [ ! -f "$cfg" ]; then
  id=$(dbid)
  if [ -z "$id" ]; then
    npx wrangler d1 create saml-idp-bench --update-config=false </dev/null || true
    id=$(dbid)
  fi
  [ -n "$id" ] || { echo "could not create or find the D1 database saml-idp-bench (see Wrangler's message above)"; exit 1; }
  cat > "$cfg" <<JSON
// Benchmark deploy config (git-ignored), written by scripts/bench/deploy.sh.
{
  "name": "better-auth-saml-idp-bench",
  "main": "src/index.ts",
  "compatibility_date": "2026-08-15",
  "compatibility_flags": ["nodejs_compat"],
  "d1_databases": [{ "binding": "DB", "database_name": "saml-idp-bench", "database_id": "$id", "migrations_dir": "migrations" }],
  "workers_dev": true,
  "preview_urls": false,
  "vars": {
    "RATE_LIMIT": "off",
    "SAML_SERVICE_PROVIDERS": "[{\\"id\\": \\"bench\\", \\"entityId\\": \\"https://bench.invalid/sp\\", \\"acsUrls\\": [\\"https://bench.invalid/acs\\"]}]"
  }
}
JSON
  echo "== Applying migrations"
  npx wrangler d1 migrations apply saml-idp-bench --remote -c "$cfg"
  echo "== Secrets: a fresh signing key pair and BETTER_AUTH_SECRET"
  keys=$(mktemp -d)
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 -subj "/CN=better-auth-saml-idp bench" -keyout "$keys/key.pem" -out "$keys/cert.pem" 2>/dev/null
  npx wrangler secret put SAML_IDP_PRIVATE_KEY -c "$cfg" < "$keys/key.pem"
  npx wrangler secret put SAML_IDP_CERT -c "$cfg" < "$keys/cert.pem"
  openssl rand -base64 32 | tr -d '\n' | npx wrangler secret put BETTER_AUTH_SECRET -c "$cfg"
  rm -rf "$keys"
fi
echo "== Deploying"
npx wrangler deploy -c "$cfg"

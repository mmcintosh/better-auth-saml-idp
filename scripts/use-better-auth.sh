#!/usr/bin/env bash
# Install one Better Auth version across every @better-auth/* package the tests use.
# Usage: scripts/use-better-auth.sh <version|latest-1.7|latest|next>
set -euo pipefail
want="${1:?version}"
case "$want" in
  latest-1.7) v="$(npm view 'better-auth@>=1.7.0 <1.8.0' version --json | node -e 'const v=JSON.parse(require("fs").readFileSync(0,"utf8"));console.log(Array.isArray(v)?v.at(-1):v)')" ;;
  latest|next) v="$(npm view "better-auth@$want" version)" ;;
  *) v="$want" ;;
esac
echo "better-auth $want -> $v"
# -w: the workspace root is where the tests' dependencies live (pnpm asks for it explicitly once
# pnpm-workspace.yaml excludes a folder, as it does examples/chardb).
# Better Auth pins @better-auth/utils exactly, and @better-auth/core takes it as a peer. Without the
# same version at the root, pnpm gives core a second instance, and an adapter's schema check is
# registered in one and looked up in the other (1.7.8 next to a lockfile from 1.7.13, 2026-10-25).
u="$(npm view "better-auth@$v" 'dependencies.@better-auth/utils')"
pnpm add -w -D "better-auth@$v" "@better-auth/core@$v" "@better-auth/drizzle-adapter@$v" "@better-auth/sso@$v" "@better-auth/utils@$u"
# The example apps must use the same version, or two copies of Better Auth's types collide.
pnpm -C examples/workers-hono add "better-auth@$v" "@better-auth/passkey@$v"
pnpm -C examples/nextjs add "better-auth@$v"
pnpm -C examples/workers-neon add "better-auth@$v"

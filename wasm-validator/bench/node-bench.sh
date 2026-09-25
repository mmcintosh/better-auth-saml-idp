#!/usr/bin/env bash
# Bundles node-bench.ts with esbuild and runs it on Node. Run from the repo root.
set -euo pipefail
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
npx esbuild wasm-validator/bench/node-bench.ts --bundle --platform=node --format=esm \
  --outfile="$OUT/bench.mjs" --log-level=warning \
  --banner:js="import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);"
for i in 1 2 3; do node "$OUT/bench.mjs"; done

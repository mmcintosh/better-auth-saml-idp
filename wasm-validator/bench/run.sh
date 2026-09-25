#!/usr/bin/env bash
# Times the validators on real workerd (wrangler dev, local mode) from outside with curl.
# Run from the repo root: wasm-validator/bench/run.sh [rounds]
# Each cold measurement uses a freshly started wrangler dev (fresh isolate).
set -euo pipefail
ROUNDS="${1:-3}"
WARM_N=200
PORT="${PORT:-18931}"
CFG="wasm-validator/bench/bench.wrangler.jsonc"
URL="http://127.0.0.1:$PORT"
t() { curl -s -o /dev/null -w '%{time_total}' "$URL$1"; }
body() { curl -s "$URL$1"; }

start() {
  if curl -s -o /dev/null "$URL"; then echo "port $PORT already in use" >&2; exit 1; fi
  setsid npx wrangler dev --config "$CFG" --port "$PORT" --ip 127.0.0.1 >/tmp/xsd-bench-wrangler.log 2>&1 &
  WPID=$!
  for _ in $(seq 1 120); do curl -s -o /dev/null "$URL/noop" && return 0; sleep 0.5; done
  echo "wrangler dev did not come up" >&2; cat /tmp/xsd-bench-wrangler.log >&2; exit 1
}
stop() {
  [ -n "${WPID:-}" ] || return 0
  kill -- -"$WPID" 2>/dev/null || true; wait "$WPID" 2>/dev/null || true
  for _ in $(seq 1 60); do curl -s -o /dev/null "$URL" || break; sleep 0.25; done
  WPID=
}
trap stop EXIT

for which in wasm xmllint; do
  for r in $(seq 1 "$ROUNDS"); do
    start
    t /noop >/dev/null; t /noop >/dev/null
    noop=$(t /noop)
    cold=$(t "/$which")
    second=$(t "/$which")
    # warm: one request doing WARM_N validations, minus a noop request
    t "/$which?n=10" >/dev/null
    warm=$(t "/$which?n=$WARM_N")
    noop2=$(t /noop)
    result=$(body "/$which")
    awk -v w="$which" -v r="$r" -v n="$noop" -v c="$cold" -v s="$second" -v wm="$warm" -v n2="$noop2" -v N="$WARM_N" -v res="$result" 'BEGIN {
      printf "%-8s round %d: noop %.1f ms | cold first call %.1f ms (%.1f net) | 2nd call %.1f ms | warm %.3f ms/validation (%d in one request) | result %s\n",
        w, r, n*1000, c*1000, (c-n)*1000, s*1000, (wm-n2)*1000/N, N, res }'
    stop
  done
done

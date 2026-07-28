#!/usr/bin/env bash
# Run the k6 suites against the kind deployment and drop JSON results into
# loadtest/results/.
#
#   scripts/run-k6.sh baseline               # 3 load levels
#   scripts/run-k6.sh correctness [label]    # rate limit correctness run
#   scripts/run-k6.sh fairness
#
# Requires key envs (see scripts/seed.sh kind):
#   K6_KEY_LOADTEST K6_KEY_METERED K6_KEY_NOISY K6_KEY_QUIET
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p loadtest/results

BASE="${BASE:-http://127.0.0.1:30080}"
SUITE="${1:-baseline}"

case "$SUITE" in
  baseline)
    for rate in 500 1000 2000; do
      echo "==> baseline @ ${rate} rps" >&2
      k6 run --quiet -e RATE=$rate -e DURATION=60s -e BASE="$BASE" \
        -e KEY="$K6_KEY_LOADTEST" loadtest/baseline.js
    done
    ;;
  correctness)
    LABEL="${2:-redis}"
    echo "==> correctness (limiter=$LABEL)" >&2
    k6 run --quiet -e LIMIT=300 -e DURATION=30 -e BASE="$BASE" \
      -e KEY="$K6_KEY_METERED" -e LABEL="$LABEL" loadtest/correctness.js
    ;;
  fairness)
    echo "==> fairness (noisy vs quiet)" >&2
    k6 run --quiet -e LIMIT=200 -e DURATION=30s -e BASE="$BASE" \
      -e NOISY_KEY="$K6_KEY_NOISY" -e QUIET_KEY="$K6_KEY_QUIET" loadtest/fairness.js
    ;;
  *)
    echo "unknown suite: $SUITE" >&2; exit 1 ;;
esac

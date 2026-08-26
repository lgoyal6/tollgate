#!/usr/bin/env bash
# The headline demo: with 3 gateway replicas, a naive in-memory limiter
# multiplies every tenant's quota by the replica count; the Redis limiter
# holds the global limit exactly.
#
# Runs the correctness k6 suite twice - once per limiter backend - by
# redeploying the Helm release with limiter=memory and then limiter=redis.
# Results land in loadtest/results/correctness-{memory,redis}.json.
#
# Requires: kind deployment up (make deploy && make kind-seed), K6_KEY_METERED set.
set -euo pipefail
cd "$(dirname "$0")/.."

redeploy() {
  local limiter=$1
  echo "==> switching gateway to limiter=$limiter" >&2
  helm upgrade tollgate deploy/helm/tollgate -n tollgate --reuse-values --set limiter="$limiter" >/dev/null
  kubectl -n tollgate rollout status deploy/tollgate --timeout=120s >/dev/null
  # Let readiness and endpoints settle.
  sleep 5
}

redeploy memory
scripts/run-k6.sh correctness memory

redeploy redis
scripts/run-k6.sh correctness redis

echo
echo "==> verdict"
for f in loadtest/results/correctness-memory.json loadtest/results/correctness-redis.json; do
  echo "--- $f"
  cat "$f"
done

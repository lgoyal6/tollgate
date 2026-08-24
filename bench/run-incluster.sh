#!/usr/bin/env bash
# Run the fixed limiter-cost protocol in the current Kubernetes context.
set -euo pipefail
cd "$(dirname "$0")/.."

source bench/protocol.sh

NAMESPACE=${BENCH_NAMESPACE:-tollgate}
DEPLOYMENT=${BENCH_DEPLOYMENT:-tollgate}
RESULTS=bench/results/incluster
REPORT=bench/results/limiter_cost_incluster.txt
TMP=bench/.tmp/incluster

log() { printf '[bench-eks %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

mkdir -p "$RESULTS" "$TMP"
rm -f "$RESULTS"/cost-*.json

for command in kubectl jq python3; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

kubectl get namespace "$NAMESPACE" >/dev/null
kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" >/dev/null
kubectl get deployment redis -n "$NAMESPACE" >/dev/null
kubectl get statefulset postgres -n "$NAMESPACE" >/dev/null

log "fixing benchmark replicas, HPA state, logging, tracing, and upstream mock"
kubectl delete hpa "$DEPLOYMENT" -n "$NAMESPACE" --ignore-not-found >/dev/null
kubectl scale deployment "$DEPLOYMENT" -n "$NAMESPACE" --replicas="$BENCH_REPLICAS" >/dev/null
kubectl set env deployment/"$DEPLOYMENT" -n "$NAMESPACE" \
  ACCESS_LOG=false TRACE_SAMPLE_RATIO=0 HEDGING_ENABLED=false RATE_LIMITER=redis >/dev/null
for upstream in upstream-a upstream-b; do
  kubectl set env deployment/"$upstream" -n "$NAMESPACE" \
    BASE_DELAY_MS="$BENCH_UPSTREAM_BASE_DELAY_MS" \
    JITTER_MS="$BENCH_UPSTREAM_JITTER_MS" >/dev/null
  kubectl rollout status deployment/"$upstream" -n "$NAMESPACE" --timeout=5m >/dev/null
done
kubectl rollout status deployment/"$DEPLOYMENT" -n "$NAMESPACE" --timeout=5m >/dev/null

available=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.status.availableReplicas}')
[[ "$available" == "$BENCH_REPLICAS" ]] || { echo "expected $BENCH_REPLICAS available gateway replicas, got ${available:-0}" >&2; exit 1; }

log "applying benchmark seed to the already migrated deployment"
schema_ready=$(kubectl exec statefulset/postgres -n "$NAMESPACE" -- \
  psql -At -U tollgate -d tollgate -c "SELECT to_regclass('public.tenants') IS NOT NULL")
[[ "$schema_ready" == t ]] || { echo "database migrations must be applied before the benchmark" >&2; exit 1; }
sed -e 's|__UPSTREAM_A__|upstream-a:9000|g' -e 's|__UPSTREAM_B__|upstream-b:9000|g' \
  migrations/seed.sql | kubectl exec -i statefulset/postgres -n "$NAMESPACE" -- \
    psql -v ON_ERROR_STOP=1 -U tollgate -d tollgate >/dev/null
kubectl exec -i statefulset/postgres -n "$NAMESPACE" -- \
  psql -v ON_ERROR_STOP=1 -U tollgate -d tollgate >/dev/null <<'SQL'
INSERT INTO tenants (id, name, rl_algorithm, rl_rate, rl_burst, rl_window_ms, rl_limit)
VALUES ('loadtest-sw', 'Load Test SW', 'sliding_window', 50, 100, 1000, 200000)
ON CONFLICT (id) DO UPDATE SET
  rl_algorithm = EXCLUDED.rl_algorithm,
  rl_window_ms = EXCLUDED.rl_window_ms,
  rl_limit = EXCLUDED.rl_limit;
INSERT INTO routes (tenant_id, path_prefix, upstream_url, strip_prefix, timeout_ms, retry_max, hedge_enabled, hedge_delay_ms)
VALUES ('loadtest-sw', '/echo/', 'http://upstream-a:9000', true, 5000, 0, false, 50)
ON CONFLICT (tenant_id, path_prefix) DO UPDATE SET upstream_url = EXCLUDED.upstream_url;
SQL

log "issuing benchmark API keys"
KEY_LOADTEST=$(kubectl exec deployment/"$DEPLOYMENT" -n "$NAMESPACE" -- \
  /tollgate-admin issue-key -tenant loadtest -scopes read,write 2>/dev/null | tail -1)
KEY_SW=$(kubectl exec deployment/"$DEPLOYMENT" -n "$NAMESPACE" -- \
  /tollgate-admin issue-key -tenant loadtest-sw -scopes read,write 2>/dev/null | tail -1)
[[ "$KEY_LOADTEST" == tg_* && "$KEY_SW" == tg_* ]] || { echo "failed to issue benchmark keys" >&2; exit 1; }

kubectl create configmap tollgate-limiter-cost-script -n "$NAMESPACE" \
  --from-file=limiter_cost.js=bench/k6/limiter_cost.js \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create secret generic tollgate-bench-keys -n "$NAMESPACE" \
  --from-literal=loadtest="$KEY_LOADTEST" --from-literal=sliding_window="$KEY_SW" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
unset KEY_LOADTEST KEY_SW

cleanup() {
  kubectl delete secret tollgate-bench-keys -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete configmap tollgate-limiter-cost-script -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

switch_arm() {
  local arm=$1 limiter=$1
  [[ "$arm" == redis-sw ]] && limiter=redis
  if [[ "${CURRENT_LIMITER:-}" == "$limiter" ]]; then
    return
  fi
  kubectl set env deployment/"$DEPLOYMENT" -n "$NAMESPACE" RATE_LIMITER="$limiter" >/dev/null
  kubectl rollout status deployment/"$DEPLOYMENT" -n "$NAMESPACE" --timeout=5m >/dev/null
  available=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.status.availableReplicas}')
  [[ "$available" == "$BENCH_REPLICAS" ]] || { echo "gateway replica count changed during arm $arm" >&2; exit 1; }
  CURRENT_LIMITER=$limiter
}

run_k6() {
  local arm=$1 run=$2 key_field=loadtest
  [[ "$arm" == redis-sw ]] && key_field=sliding_window
  local job="limiter-cost-${arm}-${run}"
  kubectl delete job "$job" -n "$NAMESPACE" --ignore-not-found >/dev/null
  sed \
    -e "s|__JOB_NAME__|$job|g" \
    -e "s|__NAMESPACE__|$NAMESPACE|g" \
    -e "s|__K6_IMAGE__|$BENCH_K6_IMAGE|g" \
    -e "s|__RATE__|$BENCH_RATE|g" \
    -e "s|__WARMUP_S__|$BENCH_WARMUP_S|g" \
    -e "s|__MEASURE_S__|$BENCH_MEASURE_S|g" \
    -e "s|__ARM__|$arm|g" \
    -e "s|__RUN__|$run|g" \
    -e "s|__KEY_FIELD__|$key_field|g" \
    bench/k8s/limiter-cost-job.yaml | kubectl apply -f - >/dev/null
  if ! kubectl wait job/"$job" -n "$NAMESPACE" --for=condition=complete --timeout=5m >/dev/null; then
    kubectl logs job/"$job" -n "$NAMESPACE" >&2 || true
    exit 1
  fi
  kubectl logs job/"$job" -n "$NAMESPACE" \
    | awk '/^\{"arm":/{line=$0} END {print line}' >"$RESULTS/cost-$arm-run$run.json"
  jq -e --arg arm "$arm" --argjson run "$run" \
    '.arm == $arm and .run == $run and (.p50_ms | type == "number")' \
    "$RESULTS/cost-$arm-run$run.json" >/dev/null
}

STARTED_AT=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
CURRENT_LIMITER=redis
for round in $(seq 1 "$BENCH_ROUNDS"); do
  for arm in "${BENCH_ARMS[@]}"; do
    log "round $round/$BENCH_ROUNDS: arm $arm"
    switch_arm "$arm"
    run_k6 "$arm" "$round"
  done
done
FINISHED_AT=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

python3 bench/summarize.py "$RESULTS" >"$TMP/summary.txt"

GIT_REV=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
[[ -z "$(git status --porcelain 2>/dev/null)" ]] || GIT_REV="$GIT_REV (dirty)"
CONTEXT=$(kubectl config current-context)
K8S_VERSION=$(kubectl version -o json | jq -r '.serverVersion.gitVersion')
NODE_COUNT=$(kubectl get nodes -o json | jq '.items | length')
INSTANCE_TYPES=$(kubectl get nodes -o json | jq -r '[.items[].metadata.labels["node.kubernetes.io/instance-type"]] | unique | join(",")')
ZONES=$(kubectl get nodes -o json | jq -r '[.items[].metadata.labels["topology.kubernetes.io/zone"]] | unique | sort | join(",")')
GATEWAY_IMAGE=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}')
GATEWAY_IMAGE=${GATEWAY_IMAGE##*/}
UPSTREAM_IMAGES=$(kubectl get deployment upstream-a upstream-b -n "$NAMESPACE" -o json | jq -r '[.items[].spec.template.spec.containers[0].image | split("/")[-1]] | unique | join(",")')
REDIS_REPLICAS=$(kubectl get deployment redis -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
POSTGRES_REPLICAS=$(kubectl get statefulset postgres -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
POSTGRES_STORAGE=$(kubectl get statefulset postgres -n "$NAMESPACE" -o jsonpath='{.spec.volumeClaimTemplates[0].spec.resources.requests.storage}')
POSTGRES_STORAGE_CLASS=$(kubectl get statefulset postgres -n "$NAMESPACE" -o jsonpath='{.spec.volumeClaimTemplates[0].spec.storageClassName}')
{
  echo "tollgate bench: limiter cost, Amazon EKS in-cluster"
  echo "====================================================="
  echo "generated: $STARTED_AT to $FINISHED_AT by bench/run-incluster.sh"
  echo "git: $GIT_REV"
  echo "kubernetes context: $CONTEXT; server: $K8S_VERSION"
  echo "provider: AWS; nodes: $NODE_COUNT; instance types: $INSTANCE_TYPES; availability zones: $ZONES"
  echo "images: gateway $GATEWAY_IMAGE; mock upstream $UPSTREAM_IMAGES; Redis redis:7-alpine; Postgres postgres:16-alpine"
  echo "backing stores: $REDIS_REPLICAS Redis Deployment replica; $POSTGRES_REPLICAS Postgres StatefulSet replica with $POSTGRES_STORAGE $POSTGRES_STORAGE_CLASS PVC"
  echo "k6: $BENCH_K6_IMAGE"
  echo "arms, in round order: ${BENCH_ARMS[*]}"
  echo "topology: in-cluster k6 -> ClusterIP Service -> $BENCH_REPLICAS gateway replicas -> mock upstream (${BENCH_UPSTREAM_BASE_DELAY_MS}ms delay, ${BENCH_UPSTREAM_JITTER_MS}ms jitter)"
  echo "load: constant-arrival-rate $BENCH_RATE rps; ${BENCH_WARMUP_S}s warmup DISCARDED + ${BENCH_MEASURE_S}s measured; $BENCH_ROUNDS runs/arm"
  echo "headline estimator: median of paired same-round redis-minus-memory p50 deltas"
  echo
  sed -e '${/^$/d;}' "$TMP/summary.txt"
} >"$REPORT"

log "done: $REPORT and raw data in $RESULTS"

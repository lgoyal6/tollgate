#!/usr/bin/env bash
# Run the fixed limiter-cost protocol in Docker Compose.
set -euo pipefail
cd "$(dirname "$0")/.."

source bench/protocol.sh

if [[ -z "${BENCH_CAFFEINATED:-}" ]] && command -v caffeinate >/dev/null 2>&1; then
  BENCH_CAFFEINATED=1 exec caffeinate -dims "$0" "$@"
fi

COMPOSE=(docker compose -f bench/compose.yaml)
NET=tollgate-bench
RESULTS=bench/results/local
REPORT=bench/results/limiter_cost.txt
TMP=bench/.tmp/local

log() { printf '[bench-local %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

mkdir -p "$RESULTS" "$TMP"
rm -f "$RESULTS"/cost-*.json "$RESULTS"/checkhist-*.prom

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
docker ps --format '{{.Names}}' | grep -v '^tollgate-bench' >"$TMP/other-containers.txt" || true
if [[ -s "$TMP/other-containers.txt" ]]; then
  log "WARNING: unrelated containers are running: $(tr '\n' ' ' <"$TMP/other-containers.txt")"
fi

psql_c() { "${COMPOSE[@]}" exec -T postgres psql -q -U tollgate -d tollgate "$@"; }
admin() { "${COMPOSE[@]}" run --rm --no-deps --entrypoint /tollgate-admin gateway "$@"; }

wait_ready() {
  local i deadline=$((SECONDS + 90))
  for i in $(seq 1 "$BENCH_REPLICAS"); do
    until "${COMPOSE[@]}" exec -T helper wget -qO- "http://tollgate-bench-gateway-$i:9090/readyz" >/dev/null 2>&1; do
      if (( SECONDS >= deadline )); then
        "${COMPOSE[@]}" logs --tail 20 gateway >&2
        exit 1
      fi
      sleep 0.5
    done
  done
}

switch_arm() {
  local arm=$1 limiter=$1
  [[ "$arm" == redis-sw ]] && limiter=redis
  if [[ "${CURRENT_LIMITER:-}" == "$limiter" ]]; then
    return
  fi
  log "switching gateways to RATE_LIMITER=$limiter"
  BENCH_LIMITER="$limiter" "${COMPOSE[@]}" up -d --force-recreate gateway >/dev/null 2>&1
  "${COMPOSE[@]}" restart lb >/dev/null 2>&1
  wait_ready
  CURRENT_LIMITER=$limiter
}

k6_cost() {
  local arm=$1 run=$2 key=$3
  docker run --rm --network "$NET" \
    -v "$PWD/bench/k6:/scripts:ro" -v "$PWD/$RESULTS:/results" \
    -e BASE=http://lb:8080 -e RATE="$BENCH_RATE" \
    -e WARMUP_S="$BENCH_WARMUP_S" -e MEASURE_S="$BENCH_MEASURE_S" \
    -e ARM="$arm" -e RUN="$run" -e KEY="$key" \
    "$BENCH_K6_IMAGE" run --quiet /scripts/limiter_cost.js
}

cleanup() {
  if [[ "${KEEP_STACK:-0}" != 1 ]]; then
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log "building images"
"${COMPOSE[@]}" build >"$TMP/build.log" 2>&1 || { sed -n '1,240p' "$TMP/build.log" >&2; exit 1; }
docker pull -q "$BENCH_K6_IMAGE" >/dev/null

log "starting Redis, Postgres, upstream, and helper"
"${COMPOSE[@]}" up -d --wait redis postgres upstream helper >/dev/null 2>&1

log "applying migrations and seed"
for migration in migrations/0*.sql; do psql_c <"$migration" >/dev/null; done
sed -e 's|__UPSTREAM_A__|upstream:9000|g' -e 's|__UPSTREAM_B__|upstream:9000|g' \
  migrations/seed.sql | psql_c >/dev/null
psql_c >/dev/null <<'SQL'
INSERT INTO tenants (id, name, rl_algorithm, rl_rate, rl_burst, rl_window_ms, rl_limit)
VALUES ('loadtest-sw', 'Load Test SW', 'sliding_window', 50, 100, 1000, 200000)
ON CONFLICT (id) DO UPDATE SET
  rl_algorithm = EXCLUDED.rl_algorithm,
  rl_window_ms = EXCLUDED.rl_window_ms,
  rl_limit = EXCLUDED.rl_limit;
INSERT INTO routes (tenant_id, path_prefix, upstream_url, strip_prefix, timeout_ms, retry_max, hedge_enabled, hedge_delay_ms)
VALUES ('loadtest-sw', '/echo/', 'http://upstream:9000', true, 5000, 0, false, 50)
ON CONFLICT (tenant_id, path_prefix) DO UPDATE SET upstream_url = EXCLUDED.upstream_url;
SQL

log "issuing benchmark API keys"
KEY_LOADTEST=$(admin issue-key -tenant loadtest -scopes read,write 2>/dev/null | tail -1)
KEY_SW=$(admin issue-key -tenant loadtest-sw -scopes read,write 2>/dev/null | tail -1)
[[ "$KEY_LOADTEST" == tg_* && "$KEY_SW" == tg_* ]] || { echo "failed to issue benchmark keys" >&2; exit 1; }

log "starting $BENCH_REPLICAS gateway replicas and load balancer"
BENCH_LIMITER=redis "${COMPOSE[@]}" up -d gateway lb >/dev/null 2>&1
wait_ready
CURRENT_LIMITER=redis

for round in $(seq 1 "$BENCH_ROUNDS"); do
  for arm in "${BENCH_ARMS[@]}"; do
    log "round $round/$BENCH_ROUNDS: arm $arm"
    switch_arm "$arm"
    key=$KEY_LOADTEST
    [[ "$arm" == redis-sw ]] && key=$KEY_SW
    k6_cost "$arm" "$round" "$key"
  done
done

bench/assemble-local.sh

log "done: $REPORT and raw data in $RESULTS"

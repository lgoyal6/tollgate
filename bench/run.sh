#!/usr/bin/env bash
# Reproduces bench/results/limiter_cost.txt end to end (~25 min):
#
#   (A) latency cost of the global limiter - 3 arms, identical everything:
#         redis   global limiter, atomic Redis Lua (the default)
#         memory  per-replica in-process limiter (no Redis in request path)
#         none    limiter bypassed entirely (floor)
#       plus a redis sliding-window variant, 5 runs per arm interleaved by
#       round, 10s warmup discarded / 30s measured per run, 3 gateway
#       replicas behind nginx, upstream mocked at 0ms.
#   (B) bare Redis RTT (redis-cli --latency / redis-benchmark) as the floor.
#   (C) Redis killed mid-run: fail-open vs fail-closed, error rate + p99
#       during outage, time to recover limiting.
#
# Usage:  make bench-limiter-cost
#         ROUNDS=5 RATE=1000 bench/run.sh     # the defaults
# See bench/METHODOLOGY.md for the honest caveats.
set -euo pipefail
cd "$(dirname "$0")/.."

# macOS: an idle laptop sleeps mid-run, which suspends the Docker VM and
# shreds the numbers (observed: a 40s run stretched to 27 wall-clock minutes
# with a 26-minute in-flight request). Keep the machine awake for the
# duration; re-exec exactly once.
if [ -z "${BENCH_CAFFEINATED:-}" ] && command -v caffeinate >/dev/null 2>&1; then
  BENCH_CAFFEINATED=1 exec caffeinate -dims "$0" "$@"
fi

COMPOSE=(docker compose -f bench/compose.yaml)
NET=tollgate-bench
RESULTS=bench/results
TMP=bench/.tmp
K6_IMAGE="${K6_IMAGE:-grafana/k6:2.1.0}"

RATE="${RATE:-1000}"
WARMUP_S="${WARMUP_S:-10}"
MEASURE_S="${MEASURE_S:-30}"
ROUNDS="${ROUNDS:-5}"

OUTAGE_RATE="${OUTAGE_RATE:-600}"
OUTAGE_DURATION_S="${OUTAGE_DURATION_S:-110}"
OUTAGE_KILL_AT="${OUTAGE_KILL_AT:-35}"
OUTAGE_DOWN_S="${OUTAGE_DOWN_S:-30}"

log() { printf '[bench %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
now() { python3 -c 'import time; print(f"{time.time():.3f}")'; }

mkdir -p "$RESULTS" "$TMP"
rm -f "$RESULTS"/cost-*.json "$RESULTS"/checkhist-*.prom "$TMP"/outage.csv

cleanup() { docker rm -f bench-k6-outage >/dev/null 2>&1 || true; }
trap cleanup EXIT

# ---------------------------------------------------------------- preflight
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
OTHER=$(docker ps --format '{{.Names}}' | grep -v '^tollgate-bench' || true)
if [ -n "$OTHER" ]; then
  log "WARNING: other containers running; they compete for CPU and add noise:"
  log "         $(echo "$OTHER" | tr '\n' ' ')"
  log "         (the committed results were measured with these stopped)"
fi

psql_c() { "${COMPOSE[@]}" exec -T postgres psql -q -U tollgate -d tollgate "$@"; }
admin() { "${COMPOSE[@]}" run --rm --no-deps --entrypoint /tollgate-admin gateway "$@"; }

wait_ready() {
  local i deadline=$((SECONDS + 90))
  for i in 1 2 3; do
    until "${COMPOSE[@]}" exec -T helper wget -qO- "http://tollgate-bench-gateway-$i:9090/readyz" >/dev/null 2>&1; do
      if [ $SECONDS -ge $deadline ]; then
        log "gateway-$i never became ready; recent logs:"
        "${COMPOSE[@]}" logs --tail 20 gateway >&2
        exit 1
      fi
      sleep 0.5
    done
  done
}

switch_arm() { # $1 = redis|memory|none
  log "switching gateways to RATE_LIMITER=$1"
  BENCH_LIMITER="$1" "${COMPOSE[@]}" up -d --force-recreate gateway >/dev/null 2>&1
  "${COMPOSE[@]}" restart lb >/dev/null 2>&1 # nginx resolves replica IPs at startup
  wait_ready
}

k6_cost() { # $1 arm-label  $2 run  $3 api-key
  docker run --rm --network "$NET" \
    -v "$PWD/bench/k6:/scripts:ro" -v "$PWD/$RESULTS:/results" \
    -e BASE=http://lb:8080 -e RATE="$RATE" -e WARMUP_S="$WARMUP_S" -e MEASURE_S="$MEASURE_S" \
    -e ARM="$1" -e RUN="$2" -e KEY="$3" \
    "$K6_IMAGE" run --quiet /scripts/limiter_cost.js
}

scrape_checkhist() { # $1 label -> results/checkhist-$1.prom
  local i
  {
    for i in 1 2 3; do
      "${COMPOSE[@]}" exec -T helper wget -qO- "http://tollgate-bench-gateway-$i:9090/metrics" \
        | grep -E '^tollgate_ratelimit_(check_duration_seconds|errors_total)' \
        | sed "s/^/gateway-$i /" || true
    done
  } >"$RESULTS/checkhist-$1.prom"
}

# ------------------------------------------------------------------- build
log "building images"
"${COMPOSE[@]}" build >"$TMP/build.log" 2>&1 || { cat "$TMP/build.log" >&2; exit 1; }
docker pull -q "$K6_IMAGE" >/dev/null

log "starting redis + postgres + upstream + helper"
"${COMPOSE[@]}" up -d --wait redis postgres upstream helper >/dev/null 2>&1

# --------------------------------------------------------- migrate + seed
log "applying migrations + seed"
for m in migrations/0*.sql; do psql_c <"$m" >/dev/null; done
sed -e 's|__UPSTREAM_A__|upstream:9000|g' -e 's|__UPSTREAM_B__|upstream:9000|g' \
  migrations/seed.sql | psql_c >/dev/null
# Bench-only tenant: sliding-window script on the hot path but with a limit
# (200k/s) that never trips, so the redis-sw arm measures cost, not 429s.
psql_c >/dev/null <<'SQL'
INSERT INTO tenants (id, name, rl_algorithm, rl_rate, rl_burst, rl_window_ms, rl_limit)
VALUES ('loadtest-sw', 'Load Test SW', 'sliding_window', 50, 100, 1000, 200000)
ON CONFLICT (id) DO UPDATE SET
  rl_algorithm = EXCLUDED.rl_algorithm,
  rl_window_ms = EXCLUDED.rl_window_ms,
  rl_limit     = EXCLUDED.rl_limit;
INSERT INTO routes (tenant_id, path_prefix, upstream_url, strip_prefix, timeout_ms, retry_max, hedge_enabled, hedge_delay_ms)
VALUES ('loadtest-sw', '/echo/', 'http://upstream:9000', true, 5000, 0, false, 50)
ON CONFLICT (tenant_id, path_prefix) DO NOTHING;
SQL

log "issuing API keys"
KEY_LOADTEST=$(admin issue-key -tenant loadtest -scopes read,write 2>/dev/null | tail -1)
KEY_SW=$(admin issue-key -tenant loadtest-sw -scopes read,write 2>/dev/null | tail -1)
KEY_METERED=$(admin issue-key -tenant metered -scopes read,write 2>/dev/null | tail -1)
case "$KEY_LOADTEST" in tg_*) ;; *) log "unexpected key output: $KEY_LOADTEST"; exit 1 ;; esac

log "starting gateways (redis) + lb"
BENCH_LIMITER=redis "${COMPOSE[@]}" up -d gateway lb >/dev/null 2>&1
wait_ready

# ------------------------------------------------- section 1: Redis floor
log "measuring bare Redis RTT floor"
{
  echo "SECTION 1 - bare Redis RTT, measured from a sibling container on the same"
  echo "docker network (the gateway's exact network path). Theoretical floor for"
  echo "the redis-arm delta; anything above this is client/gateway code."
  echo
  echo "-- redis-cli --latency, 15s (columns: min max avg ms, samples):"
  docker run --rm --network "$NET" redis:7-alpine \
    sh -c 'timeout 15 redis-cli -h redis --latency' </dev/null | tail -1 || true
  echo
  echo "-- redis-benchmark PING, 1 connection, 20k requests:"
  docker run --rm --network "$NET" redis:7-alpine \
    redis-benchmark -h redis -c 1 --threads 1 -n 20000 -t ping_mbulk --precision 3 </dev/null \
    | sed -n '/^Summary:/,$p' || true
  echo
  echo "-- redis-benchmark EVALSHA tokenbucket.lua, 1 connection, 20k requests"
  echo "   (script execution included - the exact hot-path command):"
  SHA=$(docker run --rm -i --network "$NET" redis:7-alpine redis-cli -h redis -x script load <internal/ratelimit/tokenbucket.lua)
  docker run --rm --network "$NET" redis:7-alpine \
    redis-benchmark -h redis -c 1 --threads 1 -n 20000 --precision 3 \
    evalsha "$SHA" 1 'rl:tb:{bench-floor}' 400000 200000 1 3600000 </dev/null \
    | sed -n '/^Summary:/,$p' || true
  docker run --rm --network "$NET" redis:7-alpine redis-cli -h redis del 'rl:tb:{bench-floor}' >/dev/null
  echo
} >"$TMP/section1.txt" 2>&1

# --------------------------------------------- sections 2-4: latency arms
for round in $(seq 1 "$ROUNDS"); do
  log "round $round/$ROUNDS: arm redis"
  switch_arm redis
  k6_cost redis "$round" "$KEY_LOADTEST"
  scrape_checkhist "redis-run$round"
  log "round $round/$ROUNDS: arm redis-sw (same deployment)"
  k6_cost redis-sw "$round" "$KEY_SW"
  scrape_checkhist "redis-sw-run$round"

  log "round $round/$ROUNDS: arm memory"
  switch_arm memory
  k6_cost memory "$round" "$KEY_LOADTEST"
  scrape_checkhist "memory-run$round"

  log "round $round/$ROUNDS: arm none"
  switch_arm none
  k6_cost none "$round" "$KEY_LOADTEST"
done

python3 bench/summarize.py "$RESULTS" >"$TMP/sections234.txt"

# ------------------------------------------------- section 5: kill redis
log "outage experiment: ${OUTAGE_RATE} rps vs metered tenant (limit 300/s)"
switch_arm redis
T0=$(now)
docker run -d --name bench-k6-outage --network "$NET" \
  -v "$PWD/bench/k6:/scripts:ro" -v "$PWD/$RESULTS:/results" -v "$PWD/$TMP:/csv" \
  -e BASE=http://lb:8080 -e RATE="$OUTAGE_RATE" -e DURATION_S="$OUTAGE_DURATION_S" \
  -e KEY="$KEY_METERED" -e URL_PATH=/echo/outage \
  "$K6_IMAGE" run --quiet --out csv=/csv/outage.csv /scripts/limiter_outage.js >/dev/null
sleep "$OUTAGE_KILL_AT"
T_KILL=$(now)
"${COMPOSE[@]}" kill redis >/dev/null 2>&1
log "redis KILLED at $T_KILL"
sleep "$OUTAGE_DOWN_S"
T_STARTCMD=$(now)
"${COMPOSE[@]}" start redis >/dev/null 2>&1
until "${COMPOSE[@]}" exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do sleep 0.2; done
T_PONG=$(now)
log "redis back (PONG) at $T_PONG"
docker wait bench-k6-outage >/dev/null
docker logs bench-k6-outage >"$TMP/outage-k6.log" 2>&1
docker rm bench-k6-outage >/dev/null

# Gateway-side evidence of the failure path taken.
FAILLOG=$("${COMPOSE[@]}" logs gateway 2>&1 | grep -c 'rate limiter check failed' || true)
ERRMETRIC=$(
  for i in 1 2 3; do
    "${COMPOSE[@]}" exec -T helper wget -qO- "http://tollgate-bench-gateway-$i:9090/metrics" 2>/dev/null \
      | grep '^tollgate_ratelimit_errors_total' | awk '{print $2}'
  done | awk '{s += $1} END {printf "%.0f\n", s}'
)
{
  python3 bench/outage_timeline.py "$TMP/outage.csv" "$T0" "$T_KILL" "$T_STARTCMD" "$T_PONG" \
    "$RESULTS/outage-timeline.json"
  echo
  echo "  gateway-side evidence: 'rate limiter check failed' log lines: $FAILLOG;"
  echo "  tollgate_ratelimit_errors_total summed across replicas: ${ERRMETRIC:-n/a}"
  echo "  (config: RATE_LIMIT_FAIL_OPEN unset -> default true; middleware admits on"
  echo "  limiter error. Source: internal/middleware/middleware.go RateLimit())"
} >"$TMP/section5.txt"

# -------------------------------------------------------------- assemble
log "assembling $RESULTS/limiter_cost.txt"
GIT_REV=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
git diff --quiet 2>/dev/null || GIT_REV="$GIT_REV (dirty)"
REDIS_VER=$("${COMPOSE[@]}" exec -T redis redis-server --version | sed 's/.*v=\([^ ]*\).*/\1/')
K6_VER=$(docker run --rm "$K6_IMAGE" version 2>/dev/null | head -1)
{
  echo "tollgate bench: the cost of global rate-limit correctness"
  echo "=========================================================="
  echo "generated: $(date -u '+%Y-%m-%d %H:%M UTC') by bench/run.sh (make bench-limiter-cost)"
  echo "git: $GIT_REV"
  echo "host: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), $(sysctl -n hw.ncpu 2>/dev/null || echo '?') cores; $(sw_vers -productName 2>/dev/null || uname -s) $(sw_vers -productVersion 2>/dev/null || uname -r)"
  echo "docker: $(docker --version | sed 's/Docker version //'); VM: $(docker info --format '{{.NCPU}} cpus, {{.MemTotal}} bytes' 2>/dev/null)"
  echo "images: redis $REDIS_VER, postgres:16-alpine, nginx:1.27-alpine; gateway built from golang:1.26-alpine"
  echo "k6: $K6_VER (in-network container; no host<->VM port proxy in measured path)"
  echo "topology: k6 -> nginx -> 3 gateway replicas -> mock upstream (0ms delay, 0ms jitter)"
  echo "load: constant-arrival-rate $RATE rps; ${WARMUP_S}s warmup DISCARDED + ${MEASURE_S}s measured; $ROUNDS runs/arm, arms interleaved per round"
  echo "gateway env (all arms): ACCESS_LOG=false TRACE_SAMPLE_RATIO=0; only RATE_LIMITER differs"
  echo
  cat "$TMP/section1.txt"
  cat "$TMP/sections234.txt"
  cat "$TMP/section5.txt"
} >"$RESULTS/limiter_cost.txt"

if [ "${KEEP_STACK:-0}" != "1" ]; then
  log "tearing down bench stack (KEEP_STACK=1 to keep it)"
  "${COMPOSE[@]}" down -v >/dev/null 2>&1
fi
log "done: $RESULTS/limiter_cost.txt"

#!/usr/bin/env bash
# Rebuild the local human-readable report from immutable per-run JSON files.
set -euo pipefail
cd "$(dirname "$0")/.."

source bench/protocol.sh

RESULTS=bench/results/local
REPORT=bench/results/limiter_cost.txt
TMP=bench/.tmp/local
mkdir -p "$TMP"

python3 bench/summarize.py "$RESULTS" >"$TMP/summary.txt"

GIT_REV=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
[[ -z "$(git status --porcelain 2>/dev/null)" ]] || GIT_REV="$GIT_REV (dirty)"
K6_VER=$(docker run --rm "$BENCH_K6_IMAGE" version 2>/dev/null | head -1)
{
  echo "tollgate bench: limiter cost, local Docker Compose"
  echo "===================================================="
  echo "assembled: $(date -u '+%Y-%m-%d %H:%M UTC') from 48 raw per-run JSON artifacts"
  echo "git: $GIT_REV"
  echo "host: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), $(sysctl -n hw.ncpu 2>/dev/null || echo '?') cores; $(sw_vers -productName 2>/dev/null || uname -s) $(sw_vers -productVersion 2>/dev/null || uname -r)"
  echo "docker: $(docker --version | sed 's/Docker version //'); VM: $(docker info --format '{{.NCPU}} cpus, {{.MemTotal}} bytes' 2>/dev/null)"
  echo "k6: $K6_VER"
  echo "arms, in round order: ${BENCH_ARMS[*]}"
  echo "topology: in-network k6 -> nginx -> $BENCH_REPLICAS gateway replicas -> mock upstream (${BENCH_UPSTREAM_BASE_DELAY_MS}ms delay, ${BENCH_UPSTREAM_JITTER_MS}ms jitter)"
  echo "load: constant-arrival-rate $BENCH_RATE rps; ${BENCH_WARMUP_S}s warmup DISCARDED + ${BENCH_MEASURE_S}s measured; $BENCH_ROUNDS runs/arm"
  echo "headline estimator: median of paired same-round redis-minus-memory p50 deltas"
  echo
  sed -e '${/^$/d;}' "$TMP/summary.txt"
} >"$REPORT"

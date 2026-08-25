#!/usr/bin/env bash
# Shared limiter-cost protocol. Both environment runners source this file so
# the comparison cannot drift through environment-specific defaults.

readonly BENCH_RATE=1000
readonly BENCH_WARMUP_S=10
readonly BENCH_MEASURE_S=30
readonly BENCH_ROUNDS=12
readonly BENCH_REPLICAS=3
readonly BENCH_UPSTREAM_BASE_DELAY_MS=0
readonly BENCH_UPSTREAM_JITTER_MS=0
readonly BENCH_K6_IMAGE=grafana/k6:2.1.0

readonly -a BENCH_ARMS=(redis redis-sw memory none)

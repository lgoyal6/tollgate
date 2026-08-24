# Measuring the cost of global rate-limit correctness

This benchmark measures the request latency added by a globally correct Redis
rate limiter relative to the same token-bucket policy in process. Local Docker
Compose and AWS EKS use one shared protocol in `bench/protocol.sh`. Reported
numbers come from committed per-run k6 JSON summaries. Nothing is estimated.

## Audit of the prior six-run point estimates

The two prior result files did not differ in any requested control. They did
differ in execution environment and network topology, which is the comparison
the benchmark is intended to expose.

| requested field | prior local file | prior EKS file | difference |
|---|---|---|---|
| arm set | `redis`, `redis-sw`, `memory`, `none` | `redis`, `redis-sw`, `memory`, `none` | none |
| runs per arm | 6 | 6 valid | none |
| offered load | constant-arrival-rate 1000 rps | constant-arrival-rate 1000 rps | none |
| gateway replicas | 3 | 3 | none |
| upstream mock | 0 ms base delay, 0 ms jitter | 0 ms base delay, 0 ms jitter | none |
| warmup and measurement | 10 s discarded, then 30 s measured | 10 s discarded, then 30 s measured | none |
| headline delta estimator | median p50 of Redis arm minus median p50 of memory arm | median p50 of Redis arm minus median p50 of memory arm | none |

Both files also printed a paired-same-round estimator, but neither used it as
the headline. Locally the delta of arm medians was 0.189 ms and the median of
paired deltas was 0.162 ms, a 0.027 ms difference. In EKS those values were
0.159 ms and 0.254 ms, a 0.095 ms difference.

The estimators disagree because a median is nonlinear, so the difference of
two separately ranked arm medians does not generally equal the median of the
within-round differences. The EKS paired deltas were `0.374, 0.561, -0.124,
0.178, 0.106, 0.330` ms, whose middle pair is 0.178 and 0.330 ms after sorting,
while the separate Redis and memory arm medians were 1.413 and 1.254 ms. The
local paired deltas were `0.011, 0.228, 0.137, 0.194, 0.065, 0.187` ms, whose
middle pair is 0.137 and 0.187 ms, while the separate arm medians were 0.702
and 0.513 ms. The larger EKS disagreement is therefore present in the raw
same-round pair structure, especially its negative and large positive pairs.

## Matched latency protocol

The protocol is fixed in `bench/protocol.sh` and sourced by both environment
runners:

- arm order within every round: `redis`, `redis-sw`, `memory`, `none`;
- 12 runs per arm, interleaved by round;
- constant-arrival-rate 1000 requests per second;
- 10 seconds of discarded warmup followed by 30 measured seconds;
- exactly 3 Ready gateway replicas in every arm;
- mock upstream with `BASE_DELAY_MS=0` and `JITTER_MS=0`;
- `ACCESS_LOG=false`, `TRACE_SAMPLE_RATIO=0`, and `HEDGING_ENABLED=false` in
  every arm;
- k6 2.1.0 running inside the environment's service network;
- only `RATE_LIMITER` differs between `redis`, `memory`, and `none`;
- `redis-sw` uses the Redis deployment and a separate seeded tenant whose
  sliding-window limit cannot trip at the offered load.

The four arms are:

| arm | limiter | Redis in request path |
|---|---|---|
| `redis` | global token bucket, atomic Lua via EVALSHA | yes, one request per check |
| `redis-sw` | global sliding-window log | yes, one request per check |
| `memory` | token bucket in each gateway process | no |
| `none` | RateLimit middleware omitted | no |

## Estimator and interval choice

The preselected headline estimator is the median of the 12 same-round
`p50(redis) - p50(memory)` deltas. Round is the matching block created by the
interleaved design, so pairing retains the temporal control that interleaving
was introduced to provide. The older difference-of-arm-medians calculation is
still printed as a descriptive cross-check, but it is not the headline.

For every arm and for the paired Redis-minus-memory deltas, the report prints
the median, the Q1..Q3 interval and its IQR width, and min/max. Quartiles use
Tukey hinges: Q1 is the median of the lower half of sorted observations and Q3
is the median of the upper half. The Q1..Q3 range is an observed interval, not
a confidence interval. Environment intervals overlap when their closed Q1..Q3
ranges have at least one value in common.

Every run emits its measurement-window p50, p95, p99, average, maximum,
achieved request rate, error rate, and dropped iterations. Raw local JSON is
stored in `bench/results/local/`; raw EKS JSON is stored in
`bench/results/incluster/`. Each environment's `summary.json` contains the
same values plus the paired delta distribution.

## Validity checks

A run is invalid when any of these conditions holds:

- error rate exceeds 1 percent;
- achieved rate is below 97 percent of offered rate;
- dropped iterations exceed 1 percent of offered iterations.

Invalid runs remain visible in the raw table and are explicitly excluded from
descriptive distributions. A publishable matched result requires 12 valid
same-round Redis and memory pairs in each environment.

## Exact commands

```bash
make bench-limiter-cost-local
make bench-limiter-cost-incluster  # current context must contain the EKS stack

# Run both sequentially:
make bench-limiter-cost
```

The local runner builds and seeds its isolated Compose stack, runs all 48
latency measurements, writes raw JSON, aggregates, and tears down the stack.
The EKS runner requires an already deployed and migrated benchmark stack. It
fixes the HPA state, replicas, logging, tracing, and mock-upstream controls;
seeds the same tenants and routes; runs k6 Jobs inside the cluster; writes the
pod summaries as raw local JSON artifacts; and removes transient API-key and
script objects.

## Environment boundaries and caveats

The local path is in-network k6 to nginx to three gateways to the mock
upstream, with Redis, Postgres, and every container sharing the Docker Desktop
VM. The EKS path is in-cluster k6 to a ClusterIP Service to three gateways to
the mock upstream, with Redis and Postgres also in the cluster. Absolute arm
latencies include those deliberately different environments. The paired delta
isolates the Redis request-path cost within each environment.

The load generator shares compute with the system under test in both
environments. The validity checks detect gross saturation, but do not turn the
12 observed pairs into a population confidence interval. The reported IQR and
min/max are observed run-to-run spread only.

The earlier local artifact also contained a Redis crash experiment. That is a
separate behavioral test, not part of this matched latency rerun, and it is not
used in the limiter-cost interval.

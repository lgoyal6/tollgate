# Measuring the cost of global rate-limit correctness

The README claims a win: three gateway replicas enforcing "300 req/s" admit
300 req/s, not 900, because every admission decision is one atomic Lua script
in shared Redis. This benchmark publishes what that costs: the Redis round
trip every request pays, and what happens when Redis is gone. All numbers in
`bench/results/limiter_cost.txt` come from `make bench-limiter-cost` on the
hardware listed there; nothing is estimated.

## What is measured

**(A) Latency cost.** The same k6 profile against the same stack, three ways —
only `RATE_LIMITER` differs:

| arm | limiter | Redis in request path |
|---|---|---|
| `redis` | global token bucket, atomic Lua via EVALSHA | yes — 1 RTT/request |
| `redis-sw` | global sliding-window log (supplementary) | yes — 1 RTT/request |
| `memory` | same algorithm, in-process per replica | no |
| `none` | RateLimit middleware not in the chain at all | no |

The headline number is `median p50(redis) − median p50(memory)`: what one
globally-correct admission decision adds over a per-replica one. `none` is
the floor that shows what the limiter middleware itself costs.

**(B) Redis-unavailable behaviour.** A constant 600 req/s against the
`metered` tenant (sliding window, limit 300/s — so 429s are the visible
signal that limiting works). Redis is killed (`docker compose kill`) ~35s in
and restarted ~30s later. The per-second timeline (status mix, p99) comes
from k6's CSV output; recovery is "first 429 after Redis answers PING again".

## Controls

- **Upstream mocked.** `cmd/upstream` with `BASE_DELAY_MS=0 JITTER_MS=0`, so
  provider variance cannot pollute the arm-to-arm delta.
- **Identical replica count.** 3 gateway replicas in every arm, behind nginx
  (round-robin, keepalive). nginx resolves replica IPs at startup, so the
  runner restarts it after every gateway recreation.
- **Warmup discarded.** Each run is 10s warmup + 30s measurement as two
  back-to-back k6 scenarios; only `{scenario:measure}` samples are reported.
- **At least 5 runs per arm, interleaved by round** (redis → redis-sw →
  memory → none, per round), so slow drift (thermal, background) spreads
  across arms instead of biasing one. Medians and min..max spread are
  reported per arm, plus paired per-round deltas. The committed run used
  `ROUNDS=6` for headroom against a transient bad run.
- **The machine is kept awake.** The runner re-execs itself under
  `caffeinate -dims` on macOS. This matters: this laptop's idle sleep is
  1 minute, and a first attempt without it had the Docker VM suspended
  mid-run — a 40s test stretched to 27 wall-clock minutes with one request
  "in flight" for 26 minutes. Those runs were discarded and the whole
  benchmark rerun; the validity checks would have flagged them anyway.
- **Noise reduction, identical across arms:** `ACCESS_LOG=false`,
  `TRACE_SAMPLE_RATIO=0`. k6 runs in a container on the docker network, so
  the macOS host↔VM port proxy is not in the measured path.
- **Validity checks.** A run with error rate > 1%, achieved < 97% of offered,
  or > 1% dropped iterations is flagged INVALID in the output and excluded
  from medians with an explicit note (none were excluded silently).
- **Theoretical floor recorded.** `redis-cli --latency`, single-connection
  `redis-benchmark` PING, and single-connection `redis-benchmark EVALSHA` of
  the actual token-bucket script, all from a sibling container on the same
  docker network — the gateway's exact network path. This separates "Redis
  RTT" from "gateway code" in the measured delta.
- **In-gateway cross-check.** The gateway's own
  `tollgate_ratelimit_check_duration_seconds` histogram is scraped after each
  run; its mean should bracket the k6-visible delta from below.

## Exact commands

```bash
make bench-limiter-cost            # everything below, end to end
# equivalently:
ROUNDS=5 RATE=1000 bench/run.sh
```

The runner (`bench/run.sh`) does, in order: build images → start
redis/postgres/upstream → apply `migrations/` + seed → issue API keys via
`tollgate-admin` → start 3 gateway replicas + nginx → Redis floor probes →
5 interleaved rounds of the 4 arms (k6 `bench/k6/limiter_cost.js`) → outage
run (k6 `bench/k6/limiter_outage.js` + timed `docker compose kill/start
redis`) → aggregate (`bench/summarize.py`, `bench/outage_timeline.py`) into
`bench/results/limiter_cost.txt` + JSON.

## Environment

Recorded in the header of `bench/results/limiter_cost.txt` for the committed
run: hardware, macOS/Docker/k6/Redis versions, git revision. Everything —
k6, nginx, 3 gateways, Redis, Postgres, the mock upstream — shares one
laptop (Docker Desktop VM), and the machine was otherwise quiesced (dev
compose stack and kind cluster stopped). The runner warns if other
containers are running.

## Honest caveats

- **Laptop numbers are not datacenter numbers.** Everything in the laptop run
  shares one machine. The separately committed AWS EKS run repeats the same
  four arms in-cluster; see `bench/results/limiter_cost_incluster.txt` instead
  of extrapolating from the laptop's container-to-container RTT.
- The load generator shares CPUs with the system under test (identical
  across arms; validity checks would flag saturation).
- The latency arms use the token-bucket script on the hot path; `redis-sw`
  covers the sliding-window script. The outage run uses sliding-window (the
  `metered` tenant).
- One outage run, not five: it's a behavioural observation (fail-open vs
  fail-closed, recovery), not a latency estimate. Timeline resolution is 1s
  (k6 CSV timestamps).
- `docker compose kill` models a Redis crash (connections die fast). A
  network partition where packets silently drop would instead surface the
  configured 500 ms read timeout (+ up to 3 go-redis retries) per request —
  a different, slower failure mode this run does not measure.

## What was changed in the repo to make this measurable

- `RATE_LIMITER=none` (config + gateway): a bypass arm that omits the
  RateLimit middleware from the chain entirely. Without it there was no
  floor to compare against. Guarded by a loud startup warning.
- Everything else is additive under `bench/` (compose file, nginx config, k6
  scripts, aggregation scripts, runner) plus this file and the Makefile
  target. The dev `docker-compose.yml`, Helm chart, and limiter code paths
  are untouched.

## AWS EKS in-cluster run

The in-cluster result is committed separately at
`bench/results/limiter_cost_incluster.txt`. It was collected on 2026-08-13 UTC
in `us-east-1`, spanning `us-east-1a` and `us-east-1b`, on an Amazon EKS 1.36
cluster with two on-demand `m7i-flex.large` workers. Each worker had a 20 GiB
gp3 root volume. The load generator, gateway, Redis, Postgres, and mock
upstreams all ran inside that cluster.

Redis topology was one `redis:7-alpine` Deployment replica behind a ClusterIP
Service. Postgres remained in-cluster as one StatefulSet replica with a 10 GiB
encrypted gp3 PVC. No managed database service participated in the run.

The latency method matched the laptop run: `none`, `memory`, `redis`, and
`redis-sw`; six valid runs per arm; 1000 offered requests per second; three
gateway replicas; 10 seconds of discarded warmup followed by 30 measured
seconds; and a mock upstream configured for 0ms base delay and 0ms jitter.
All 24 runs passed the existing validity thresholds, with no errors or dropped
iterations.

The committed result also contains the raw scrape of
`tollgate_ratelimit_check_duration_seconds` captured at
2026-08-13T01:30:57Z. A separate 1000 rps HPA exercise began with three Ready
gateway replicas. With a disclosed test-only 1ms p99 target and maximum of
five replicas, Kubernetes emitted a `SuccessfulRescale` event at
2026-08-13T01:45:09Z requesting five replicas. The two-node benchmark shape
could not schedule the fifth pod because both workers reported insufficient
CPU, so this evidence verifies the HPA decision from 3 to 5 desired replicas,
not five Ready replicas.

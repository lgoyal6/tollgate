# tollgate — interview rehearsal

Answers rehearsed as spoken: **claim → mechanism → number**. Every factual
claim cites `file:line` in this repo. Where a number is not backed by a
committed artifact, that is said explicitly rather than smoothed over.
Verified against the working tree on 2026-07-28.

---

## 1. "Per-replica limiting over-admitting 3× on 3 replicas is just arithmetic — what's the finding?"

**Claim.** Correct — the over-admission itself is arithmetic. The finding is
what fixing it *costs*, and that the cost is structural, not incidental: a
correct distributed limit puts one authoritative read-modify-write into the
hot path of every request, which means (a) one Redis round trip per request,
and (b) the gateway's availability is now coupled to Redis's, forcing an
explicit fail-open/fail-closed policy decision that per-replica limiting
never had to make. The project's contribution is measuring both sides of that
trade instead of asserting it.

**Mechanism.** The pipeline is
`Recover → RequestID → AccessLog → Metrics → Tracing → Auth → Router →
RateLimit → proxy` (`internal/middleware/middleware.go:1-8`) — RateLimit sits
before the proxy so rejected requests never consume upstream capacity
(`middleware.go:6-8`). Every admitted request therefore executes
`limiter.Allow` inline (`middleware.go:352-354`), which for the Redis backend
is exactly one `EVALSHA` round trip running the tenant's Lua script atomically
(`internal/ratelimit/redis.go:21-25, 60-104`). There is no local shortcut, no
cache, no batching — that's the price of the property.

The availability coupling is handled in code, not hand-waved: on limiter
error the middleware consults `failOpen` (`middleware.go:356-368`). Default is
fail-open — `RATE_LIMIT_FAIL_OPEN` defaults `true`
(`internal/config/config.go:73`), wired in
`internal/gateway/gateway.go:110` — i.e., "temporarily unlimited, loudly":
`tollgate_ratelimit_errors_total` increments per fallback decision
(`middleware.go:357`, metric at `internal/observability/metrics.go:67-70`)
and is meant to feed an alert. Fail-closed (`=false`) turns a Redis blip into
a 503 for every tenant. Neither answer is free; the code makes the trade a
config knob with a stated default and a visible error signal
(README.md:121).

**The numbers.**

- **Correctness side (committed, reproducible):** one tenant at 300 req/s
  sliding-window, offered 1,200 req/s for 30 s across 3 replicas; ceiling
  9,300. Naive in-memory limiter admitted **26,942 (+190%)**; the Redis Lua
  limiter admitted **9,000 — exactly 300/s × 30 s**
  (`docs/ratelimit-proof.md:23-50`; raw k6 JSON at
  `loadtest/results/correctness-memory.json` / `correctness-redis.json`).
  And the sharper point for the "just arithmetic" interviewer: the multiplier
  is the *replica count*, which the HPA changes under load — the error grows
  precisely when traffic peaks (`ratelimit-proof.md:43-44`).
- **Cost side:** `bench/results/limiter_cost.txt` **does not exist in this
  repo** — do not cite it. What exists: the check is instrumented end-to-end
  by the `tollgate_ratelimit_check_duration_seconds` histogram wrapped
  around `limiter.Allow` (`middleware.go:352-354`,
  `observability/metrics.go:71-75`, buckets from 100 µs up), and README.md:213
  states the measured figure: **~0.2–0.5 ms added per admitted request
  in-cluster**. That README number has no committed raw capture, so the honest
  phrasing is: "measured live via the histogram at ~0.2–0.5 ms in-cluster;
  committing a scrape of that histogram is on my list." The k6 baseline table
  (p50 ≈ 11 ms at 500–2,000 rps, README.md:41-47) *includes* the limiter RTT
  but cannot isolate it — the demo upstream adds 5–15 ms simulated latency
  (README.md:171).
- **Availability side:** no committed chaos-test artifact kills Redis under
  load — the fail-open path is unit-tested behavior plus an error counter,
  not a measured outage drill. Open item; say so if pushed.

---

## 2. Why atomic Lua, not WATCH/MULTI or Redlock

**Claim.** The decision procedure: the state lives in *one* authoritative
Redis, and the operation is a small read-modify-write on a hot key. That
shape wants serialized execution at the data, which is exactly what a Lua
script is. WATCH/MULTI gives the same atomicity but pays retries under
contention — and a rate limiter's hot key is *by definition* contended when
it matters. Redlock solves a different problem (mutual exclusion across
independent Redis masters) that this design doesn't have.

**Mechanism — what the scripts guarantee.** Redis executes a script alone on
its single execution thread, so read-refill-check-write commits as one unit;
two replicas can never both spend the same token
(`internal/ratelimit/redis.go:21-23`; token bucket:
`tokenbucket.lua:22-45` reads state, refills from elapsed time, decrements,
writes back; sliding window: `slidingwindow.lua:16-24` trims, counts, inserts
— each a single atomic unit). Steady state is one round trip carrying a SHA:
`redis.Script` does `EVALSHA` with automatic `EVAL` fallback after a script
flush (`redis.go:23-25, 37-39`). Two supporting decisions ride along:

- **One clock.** Scripts read Redis `TIME`, never the gateway clock, so
  replica clock skew can't corrupt refill math or window edges
  (`tokenbucket.lua:11-15`, `slidingwindow.lua:10-11`); safe because Redis ≥ 5
  replicates scripts by effects (`tokenbucket.lua:12-13`).
- **Same-microsecond disambiguation.** ZSET members are
  `<now_us>-<request_id>` so two replicas admitting in the same microsecond
  insert two members instead of collapsing into one
  (`slidingwindow.lua:6-7, 22`; `limiter.go:81-83`).

**Against WATCH/MULTI:** optimistic concurrency — WATCH the key, GET, compute
in the client, MULTI/EXEC, and if any watched key changed, EXEC aborts and you
retry. Under N replicas hammering one tenant's key, aborts are the common
case, each retry is another full round trip, and the retry count is unbounded
exactly at peak. It also drags the refill/window math into the client, giving
back the multi-clock problem the scripts eliminate. Lua is one RTT,
zero retries, guaranteed single execution.

**Against Redlock:** Redlock acquires a quorum of locks across ≥5 independent
Redis masters to build mutual exclusion without a single authority. Here the
*state itself* has a single authority — the script already executes serially
at the data, so a lock around it is redundant machinery: N extra round trips
per decision, lock TTL tuning, and safety that famously depends on clock and
pause assumptions. Redlock is what you reach for when you can't put the
computation where the data is; we can. The single-Redis SPOF this implies is
acknowledged and bounded: keys are hash-tagged per tenant
(`redis.go:61-62, 85`) so Redis Cluster is a config change, and fail-open
covers failover windows (README.md:211).

**Not verifiable from code:** there's no committed benchmark of a WATCH/MULTI
variant — the argument above is architectural, not measured in this repo.

**The number.** The property the Lua path buys, verified under real
concurrency: 20 goroutines × 50 requests at one tenant — sliding window
admitted **exactly 100 of 1,000** (limit 100); token bucket admitted **103**
against a computed refill ceiling of 108
(`internal/ratelimit/redis_test.go:100-140`, summarized README.md:65).

---

## 3. Token bucket vs sliding-window log — the per-tenant choice

**Claim.** They answer different contract questions. Token bucket enforces an
*average rate with a burst allowance*; sliding window log enforces a *hard
count per rolling window*. Pick by what the tenant's sentence is: "roughly R
per second, spikes OK" → bucket; "never more than L per window, ever" →
window. tollgate makes it a per-tenant column, not a global choice
(`internal/ratelimit/limiter.go:17-25`, `PolicyForTenant` at `60-68`).

**Mechanism and cost, side by side:**

| | token bucket | sliding window log |
|---|---|---|
| state per tenant | 2-field hash `tokens, ts` (`tokenbucket.lua:22`) | ZSET, one member per admitted request (`slidingwindow.lua:22`) |
| decision | refill from elapsed × rate, cap at burst, decrement if ≥ cost (`tokenbucket.lua:30-42`) | trim expired, count, insert if under limit (`slidingwindow.lua:16-24`) |
| cost | O(1) | O(log n) + range-trim; memory O(limit) |
| burst behavior | admits up to `Burst` instantly, then `Rate`/s; max over d = `Burst + Rate·d` (`limiter.go:47-51`) | hard cap `Limit` per rolling `Window`, no burst above it, max over d = `Limit × (⌊d/Window⌋+1)` (`limiter.go:51-53`) |
| Retry-After | computed from token deficit ÷ rate (`tokenbucket.lua:41`) | exact: oldest entry + window − now (`slidingwindow.lua:26-32`) |

When each is right, concretely: a teammate's agent loop (the README's origin
story, README.md:3-5) wants sliding window — a runaway loop hits a hard
ceiling and gets a precise `Retry-After`; the quickstart seeds tenants that
way (README.md:20). An interactive client that legitimately fires 30 requests
on page load but averages 2/s wants a bucket (burst 50, rate 5) — a window
of the same average would 429 the burst. Cost asymmetry matters at scale: a
window with limit 10,000 keeps up to 10,000 ZSET members per tenant in Redis,
a bucket keeps two fields regardless of rate — so very high limits push
toward the bucket even when the SLA language sounds window-shaped. Both carry
TTLs so departed tenants leak nothing (`tokenbucket.lua:45`,
`slidingwindow.lua:35`, `redis.go:30-32`).

**The numbers.** Same integration test as §2: window admitted exactly its
limit under 20-way concurrency; the bucket's 103 > 100 is not a bug — 60 ms
of test runtime refilled ~3 tokens at rate 50/s, and the test asserts against
that computed ceiling of 108 (`redis_test.go:113-121`,
`docs/ratelimit-proof.md:54-59`).

---

## 4. With more time / deliberately not hand-rolled

**Claim.** The build philosophy was: hand-roll whatever embodies a design
decision, take dependencies for protocol plumbing, and make every headline
property measured rather than asserted (README.md:9). The "more time" list is
mostly written down in the README's limitations section — each item is a
known trade, not an oversight.

**What I'd change with more time** (each grounded in a committed limitation):

1. **Token-aware budgets.** Limits meter *requests*; for the LLM use case the
   scarce resource is tokens. Next step is parsing usage from provider
   responses into a per-tenant token budget (README.md:216). Request-metering
   was the right v1 cut because it's provider-agnostic.
2. **Redis HA.** Single Redis today; keys are already hash-tagged per tenant
   (`redis.go:61-62, 85`) so Redis Cluster is config, not code; fail-open
   covers failover windows (README.md:211).
3. **Commit the limiter-cost artifact.** The ~0.2–0.5 ms RTT figure
   (README.md:213) is read off the live
   `tollgate_ratelimit_check_duration_seconds` histogram
   (`observability/metrics.go:71-75`) but no scrape is committed — the
   `bench/results/limiter_cost.txt` an interviewer might ask for should
   exist. Cheap to produce; makes answer §1 fully self-contained.
4. **A two-tier limiter, only if the number justifies it.** Local
   per-replica allowance topped up from Redis asynchronously would cut the
   per-request RTT at the price of bounded over-admission — deliberately
   *not* built (**not in code**; design discussion only), because at
   0.2–0.5 ms against upstreams that cost 5 ms–seconds, correctness was the
   better buy at this scale. This is the honest counter to my own §1: the
   hot-path RTT is real but small relative to LLM upstream latency.
5. **A Redis-outage drill.** Fail-open is unit-tested logic plus an alertable
   counter (`middleware.go:356-368`), not a measured chaos scenario; killing
   Redis mid-k6-run and publishing the behavior would close the loop.
6. **WebSocket/gRPC passthrough** (README.md:210) — orthogonal plumbing,
   skipped for scope.

**What I deliberately did not implement myself, and why:**

- **Redis client (go-redis), Postgres driver (pgx), OpenTelemetry SDK,
  Prometheus client** — the four dependencies (README.md:9). Each is protocol
  plumbing where a hand-rolled version is risk without insight: RESP parsing
  and connection pooling teach nothing about admission control. Note the
  design still doesn't lean on client magic — the atomicity story is Redis's
  execution model plus my Lua, not library behavior; `redis.Script` is used
  only for the EVALSHA/EVAL fallback convenience (`redis.go:23-25`).
- **Everything with a decision in it is hand-rolled:** both limiter
  algorithms (`internal/ratelimit`), the circuit breaker's rolling-window
  state machine (`internal/resilience/breaker.go`), full-jitter retries
  restricted to idempotent methods (`retry.go`), request hedging with
  loser-cancellation (`hedge.go`), and the reverse proxy itself
  (`internal/proxy`) — including the credential-injection boundary (upstream
  key attached from gateway env on the way out; caller keys stripped —
  `middleware.go:266-268`, README.md:99). Router is stdlib `net/http`
  (README.md:9).
- **Harness, not product:** k6, Prometheus, Jaeger, kind, Terraform, Helm are
  used as instruments to *measure* the system; reimplementing instruments
  proves nothing (README.md:153-166).
- One adjacent trade worth having ready: API-key secrets are SHA-256, not
  bcrypt — correct for 256-bit random secrets (nothing to brute-force),
  wrong for human passwords; documented in `internal/auth` (README.md:212).

---

## Cross-checks worth having loaded

- Fail-open default: `RATE_LIMIT_FAIL_OPEN=true` (`config.go:73`); flipping
  it is the whole availability-vs-strictness trade in one env var.
- Tenant isolation number (a different property than §1's correctness): noisy
  tenant at 4× quota admitted exactly 200/s × 30 s = 6,000 with 18,001 429s;
  the quiet tenant sharing the gateway kept 0 429s and unchanged 25.2 ms p99
  (README.md:56-61, `loadtest/results/fairness.json`).
- Hot reload: config changes propagate via Postgres LISTEN/NOTIFY into
  atomically swapped in-memory snapshots, ~1 s from `UPDATE` to enforcement;
  request handlers never touch the database (README.md:101-103,
  `internal/store/watcher.go`).
- Methodology caveats to volunteer before being asked: everything (replicas,
  Redis, Postgres, k6) shares one laptop through kind's NodePort; numbers
  demonstrate correctness and relative behavior, not datacenter capacity
  (README.md:168-174).

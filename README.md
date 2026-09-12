<a href="https://lgoyal6.github.io/tollgate/">
  <img alt="tollgate - open the live demo" src="docs/og.png">
</a>

**[Open the live demo](https://lgoyal6.github.io/tollgate/)** - The real limiter code in your tab: watch per-replica counters admit 3x the policy while the shared store holds the ceiling exact, then read what the difference costs on a shared key.

# tollgate

Every hackathon team I've been on ends up sharing one LLM API key. It gets pasted into the group chat, someone's agent loop goes runaway at 3am, and the shared budget is gone before judging. The fixes people actually use - "everyone be careful" and rotating the key after each scare - aren't fixes.

tollgate is the piece of infrastructure that problem deserves: a small self-hosted gateway you park in front of any shared upstream (Anthropic, OpenAI, anything HTTP). Each teammate gets **their own revocable key with their own rate limit**; the real provider credential lives only in the gateway's environment and is injected on the way out, so nobody can paste what they never had. When someone's loop runs away, *they* get 429s with `Retry-After` - everyone else's budget is untouched.

Sharing one upstream fairly turns out to be a multi-tenancy problem, and the part I ended up caring about most is the part most rate limiters quietly get wrong: **limits that stay correct when the gateway itself scales past one replica.** Admission decisions here execute as atomic Lua scripts in shared Redis, so three gateway pods enforcing "300 req/s" admit 300 req/s - not 900. That property is measured, not claimed (see below).

![Issuing a teammate a key, watching the shared credential get swapped in upstream, and watching her run into her own rate limit](docs/demo.gif)

Alice's key goes in, the gateway strips it and attaches the team's shared
credential on the way out, and her fourth request in a minute is her own
problem. Reproduce that recording with `./docs/demo-setup.sh && vhs docs/demo.tape`.

### Spend budgets, not just request rates

A rate limit bounds how many requests a teammate sends. It does not bound what they
cost, and on an LLM upstream those differ by orders of magnitude - one long-context
request can outspend a thousand cheap ones while sitting comfortably inside the rate
limit. Since the problem this gateway exists for is "the shared budget is gone by
judging", rate limiting alone does not actually solve it.

So each tenant can also carry a dollar budget. Before a request is forwarded the
gateway holds a conservative upper bound against that budget, computed from the
model's price and the caller's own `max_tokens`; after the response it settles the
hold against the usage the provider actually reported. Money is integer micros
(1e-6 USD) end to end - never floats, because provider prices are quoted per million
tokens and repeatedly adding IEEE-754 fractions to a running balance loses cents.

```
$ curl -H "Authorization: Bearer tg_..." ... /llm/v1/messages
HTTP/1.1 200 OK
X-Budget-Remaining-Micros: 34934
...
HTTP/1.1 402 Payment Required
X-Budget-Exceeded: 1
{"error":"tenant budget exhausted: this request's maximum cost exceeds the remaining budget"}
```

The parts that are easy to get wrong, and what they do here:

- **Concurrent requests cannot each be admitted against the same headroom.** The
  tenant row is locked `FOR UPDATE` across the check-and-insert. Dropping that lock
  admits 16 reservations against a 10-unit budget in the concurrency test.
- **A retry is not a second charge.** Entries are unique per `(tenant, request_id)`,
  so a replayed reserve or settle is a no-op.
- **A broken stream does not refund.** If the connection dies after bytes went
  upstream the hold is marked `uncertain` and *kept*: the provider may still bill in
  full, and releasing there would let a client buy free tokens by hanging up. Only a
  request that provably never reached the upstream is released.
- **A crash does not lose the hold.** Reservations are rows, so an interrupted
  gateway leaves them open and findable (`OpenOlderThan`) rather than leaked.

Limits of the ceiling, stated rather than hidden: the hold is only as good as the
declared `max_tokens` and the price table. A provider that bills beyond the declared
ceiling settles higher than it held, so a tenant can finish one request above its
limit - visible in the ledger, and the next request is refused, but not prevented.
Requests with no declared ceiling, or on a model with no known price, are tracked and
never refused; refusing on a guessed price would be worse than not enforcing.
A tenant with no budget row is unlimited, so turning this on cannot brick a
running deployment.

Everything interesting is hand-rolled on purpose - the token bucket and sliding-window-log limiters, the circuit breaker, jittered retries, request hedging, and the reverse proxy itself. The only dependencies are the Redis client, the Postgres driver, OpenTelemetry, and the Prometheus client. Router is stdlib `net/http`.

## Run it for your team (the shared-key setup)

Deploy one gateway, then hand out keys from the console. Nobody needs shell
access to the box and nobody but the deployer ever sees the provider key.

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # the shared credential - stays on the gateway host
export ADMIN_TOKEN="$(openssl rand -hex 24)"
make up
open "http://localhost:8080/_admin/"  # paste $ADMIN_TOKEN
```

In the console: add a teammate (id, requests per window), point them at
`https://api.anthropic.com` injecting `x-api-key` from `$ANTHROPIC_API_KEY`,
then hit **Issue key**. The plaintext is shown once. Alice sets it as her SDK
key and changes nothing else:

```python
client = anthropic.Anthropic(
    base_url="http://gateway-host:8080/anthropic",
    api_key="tg_k49c0..._her_key",
)
```

Her key is verified and stripped; the shared `x-api-key` is attached from the
gateway's env on the way out (SSE streaming passes through with eager
flushing). LLM `POST`s are never retried or hedged - a paid token is spent at
most once.

When her agent loop runs away at 3am, the console shows whose 429 count is
climbing, and **Cut off** disables her tenant on every replica within one
reload. **Rotate** hands her a replacement and keeps the old key alive for 24h;
**Revoke** kills it now.

### Deploy it somewhere your team can reach

The console is what makes this deployable by one person for a group, so there
is a real one-click path for it:

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/lgoyal6/tollgate)

That button is the only genuine one-click path. It reads [`render.yaml`](render.yaml)
from this repo's root, provisions Postgres and Redis, generates an `ADMIN_TOKEN`,
and asks you for one thing: the provider key your team is sharing. No fork is
needed, and it deploys into your own Render account, so the shared credential
lives in infrastructure you control. That is the whole security argument: this
gateway is worth running precisely because the provider key stays with the team
that owns it.

| Target | How | One click? |
|---|---|---|
| **Render** | The button above. | Yes |
| [Fly.io](deploy/paas/fly.toml) | `fly launch --copy-config --config deploy/paas/fly.toml`, attach Postgres and Redis, then `fly secrets set ANTHROPIC_API_KEY=... ADMIN_TOKEN=...` | No, Fly has no button |
| [Railway](deploy/paas/railway.json) | Add the Postgres and Redis plugins, deploy from the Dockerfile, set `ADMIN_TOKEN` and the provider key. | No, needs a published Railway template |
| Kubernetes | The Helm chart in `deploy/helm/tollgate`; set `ADMIN_TOKEN` in the secret and the console appears on both listeners. | No |

`$PORT` is honoured when `LISTEN_ADDR` is unset, which is what those platforms
inject. Health and readiness probes stay on `ADMIN_ADDR` (`:9090`) for
orchestrators that can route two ports; single-port platforms can probe
`/_admin/`.

### The console is opt-in, and off by default

Without `ADMIN_TOKEN` the management handler is never constructed, so a gateway
deployed before this existed behaves exactly as it did. With it set, the same
handler is mounted twice: on the admin listener, and on the tenant listener
under `/_admin/`, because a one-container PaaS deploy only routes one public
port. It is matched ahead of route lookup, so no tenant route can shadow it,
and it authenticates with the admin token rather than a tenant key. Tokens
shorter than 16 characters are refused at startup: it is the only thing in
front of key issuance.

The page itself is a static shell with no data baked in. The operator pastes
the token into the tab, it lives in memory for that tab only, and every byte of
config arrives over the authenticated API. The same operations are still
available as a CLI (`tollgate-admin create-tenant|add-route|issue-key|
rotate-key|revoke-key|list`); both surfaces call the same `internal/store`
writers, so they cannot drift.

## Measured behaviour

Measured on the included kind deployment (3 gateway replicas, Apple M-series laptop - see [Methodology](#methodology) for the honest caveats).

**Throughput / latency** (k6 `constant-arrival-rate`, 60s per level, unlimited tenant, demo upstream adds 5–15ms simulated latency):

| Offered load | Achieved | p50 | p95 | p99 | Errors | Dropped iters |
|---|---|---|---|---|---|---|
| 500 rps | 499.9 rps | 11.6 ms | 16.7 ms | 26.8 ms | 0% | 0 |
| 1,000 rps | 999.7 rps | 11.4 ms | 16.5 ms | 46.2 ms | 0% | 0 |
| 2,000 rps | 1,999.5 rps | 11.0 ms | 16.0 ms | 45.7 ms | 0% | 0 |

**Distributed rate limit correctness** - the property the whole design rests on. One tenant limited to 300 req/s (sliding window log), offered 1,200 req/s for 30s, load-balanced across **3 replicas**. Mathematical ceiling: 9,300 admissions (300 × 30 windows, +1 window boundary slack):

| Limiter backend | Admitted | vs. ceiling | Verdict |
|---|---|---|---|
| naive in-memory (per replica) | 26,942 | **+190%** | each replica kept its own counter: quota × 3 |
| Redis Lua (this project) | **9,000** | −3.2% (= exactly 300/s × 30s) | globally correct |

**Tenant isolation** - a noisy tenant offering 4× its quota cannot starve a well-behaved one sharing the same gateway and upstreams (30s run):

| Tenant | Offered | Admitted | 429s | p99 |
|---|---|---|---|---|
| noisy (limit 200/s) | 800 rps | 6,000 (= exactly 200/s × 30s) | 18,001 | - |
| quiet (limit 200/s) | 100 rps | 3,001 of 3,001 | **0** | **25.2 ms** (same as unloaded) |

**HPA on p99 latency** (custom metric via prometheus-adapter, target 150ms/pod): under slow-upstream load, per-pod p99 rose 42ms → 229ms and the HPA scaled 3 → 5 replicas within ~90s of breach, then back to 3 after the 120s scale-down stabilization once load stopped.

**Concurrency atomicity** (Go integration test, 20 workers × 50 requests hammering one tenant): sliding window admitted **exactly** 100 of 1,000 (limit 100); token bucket admitted 103 with a computed refill ceiling of 108. `internal/ratelimit/redis_test.go` is the load-bearing test.

## Architecture

```mermaid
flowchart LR
    C[Client] -->|API key| GW

    subgraph K8S["Kubernetes (3+ replicas, HPA on p99)"]
        GW["tollgate gateway\nRecover → RequestID → AccessLog →\nMetrics → Tracing → Auth → Router →\nRateLimit → Proxy"]
        GW2[gateway replica]
        GW3[gateway replica]
    end

    GW -->|"EVALSHA (atomic Lua)"| R[(Redis\nshared counters)]
    GW2 --> R
    GW3 --> R
    GW -->|snapshot + LISTEN/NOTIFY| PG[(Postgres\ntenants / routes / api_keys)]
    GW -->|"breaker + retry + hedge\nOTel context propagated"| UA[upstream A]
    GW --> UB[upstream B]
    GW -.->|/metrics RED per tenant+route| PROM[Prometheus]
    PROM --> ADPT[prometheus-adapter] --> HPA[HPA: p99 ms/pod]
    GW -.->|OTLP traces| JAE[Jaeger]
```

### Request path

1. **Recover** – request-path code never panics by design; this is the belt-and-suspenders 500.
2. **RequestID** – honours inbound `X-Request-Id`, else generates; echoed on responses, forwarded upstream, stamped on every log line and span.
3. **AccessLog / Metrics** – structured JSON via `log/slog` (sampled under load) and RED metrics per tenant/route/method/status-class.
4. **Tracing** – extracts W3C `traceparent`, opens a server span, propagates to upstreams (visible end-to-end in Jaeger).
5. **Auth** – `tg_<keyid>_<secret>` from `Authorization: Bearer` or `X-API-Key`. SHA-256 of the secret compared in constant time. Key states: `active` → `grace` (rotation window, responses carry `X-Api-Key-Deprecated`) → `revoked`. The gateway credential is stripped before forwarding.
6. **Router** – longest-prefix match over the tenant's routes from the config snapshot; enforces per-route required scope (403); builds the route's ordered upstream plan (primary, then at most one fallback) and checks every candidate against the upstream allowlist.
7. **RateLimit** – one Redis round trip running the tenant's algorithm atomically; sets `X-RateLimit-*`, 429 + `Retry-After` on rejection. Redis outage ⇒ configurable fail-open (default) with an alertable error counter.
8. **Proxy** – hand-rolled forwarder: injects the route's upstream credential from the gateway environment (never from the database, never from the caller), per-upstream circuit breaker, retries with full-jitter backoff for idempotent methods on 502/503/504 and transport errors, optional hedging, streaming with eager flush for unknown-length bodies.

### Hot reload, no restarts

All tenant/route/key config lives in Postgres. Statement-level triggers `pg_notify` on any change; every replica LISTENs, debounces, and atomically swaps an immutable in-memory snapshot (`atomic.Pointer`). A periodic poll backstops dropped connections. Routing, scopes and rate policy use the snapshot. Immediately before a protected action, one bounded targeted query rechecks key revocation and tenant enablement, so a committed removal binds even while another replica is still inside its notification debounce. Measured propagation for the remaining snapshot config: ~1s from `UPDATE` to new limit being enforced.

## Rate limiting design (the core)

Two algorithms, selectable **per tenant** in the `tenants` table:

| | token bucket | sliding window log |
|---|---|---|
| state | hash: `tokens`, `ts` | ZSET of arrival timestamps |
| behaviour | allows bursts up to capacity, refills at `rate`/s | hard cap of `limit` per rolling `window` |
| cost | O(1) | O(log n) + trim |
| choose when | bursty-but-bounded clients | strict SLA windows |

Both are single Lua scripts (`internal/ratelimit/*.lua`) executed via `EVALSHA`:

- **Atomicity**: read-refill-check-decrement happens inside Redis's single execution thread. Two replicas can never both spend the last token, no matter how simultaneous. This is the property the in-memory limiter measurably lacks (+190% over-admission above).
- **One clock**: scripts call Redis `TIME` rather than trusting gateway clocks, so replica clock skew cannot corrupt refill math (safe under Redis ≥ 5 effects replication).
- **Sliding-window member uniqueness**: ZSET members are `<now_us>-<request_id>`, so two replicas admitting in the same microsecond cannot collapse into one entry.
- **Fail-open by default**: a Redis blip degrades to "temporarily unlimited, loudly" (`tollgate_ratelimit_errors_total` feeds an alert) instead of a full outage. `RATE_LIMIT_FAIL_OPEN=false` flips the trade.
- Keys carry TTLs so departed tenants leak nothing.

`RATE_LIMITER=memory` keeps the same interface and algorithms but per-process - it exists so the failure mode is demonstrable, and it doubles as the reference implementation for the algorithm unit tests (deterministic fake clock).

## Resilience

- **Circuit breaker per upstream host** (`internal/resilience/breaker.go`): rolling 10s window in 10 buckets; trips at ≥50% failures over ≥20 samples; 5s cooldown; half-open admits 3 concurrent probes and closes only on 3 consecutive successes. Transitions are logged and exported (`tollgate_circuit_breaker_state`).
- **Retries** (`retry.go`): idempotent methods only (GET/HEAD/OPTIONS - PUT/DELETE deliberately excluded), on transport errors and 502/503/504 (not 500: the upstream *ran*), exponential backoff with **full jitter**, per-route budget.
- **Hedging** (`hedge.go`, behind `HEDGING_ENABLED` + per-route flag): fire one backup request if the primary hasn't answered within the route's hedge delay; first usable response wins, loser is cancelled and drained. Spends upstream capacity only on the slow tail.
- **Graceful shutdown**: SIGTERM ⇒ readiness flips false ⇒ `DRAIN_DELAY` for endpoint propagation ⇒ `http.Server.Shutdown` waits for in-flight requests (bounded by `SHUTDOWN_TIMEOUT`) ⇒ flush traces, close pools. `terminationGracePeriodSeconds` is sized to fit the whole sequence.
- Request bodies up to `MAX_BODY_BUFFER_BYTES` (1 MiB) are buffered so retries/hedges can replay them; larger or unknown-length bodies stream once with no re-send.

### One optional fallback upstream per route

A route may name a second upstream. The router turns the row into an ordered
**route plan** - primary, then at most one fallback - and the proxy walks it.

```bash
tollgate-admin add-route -tenant acme -prefix /api/ -upstream http://upstream-a:9000 \
    -retries 1 -fallback http://upstream-b:9000 \
    -fallback-auth-header x-api-key -fallback-auth-env BACKUP_API_KEY

tollgate-admin set-fallback   -route 3 -upstream http://upstream-b:9000
tollgate-admin clear-fallback -route 3
```

**Router versus proxy.** The plan is routing metadata and nothing else: which
upstreams, in what order, and the *name* of the environment variable each one's
credential comes from. The proxy stays the only thing that reads or buffers a
request body, injects a credential, opens a connection, decides whether bytes
are replayable, retries, fails over, or streams a response. That split is why
the order can be logged and traced without a body or a secret going anywhere
near a log line.

**One fallback, not a routing policy.** No scoring, no weighting, no plugin
point, no arbitrary-length candidate graph. One optional fallback is enough to
survive a single upstream refusing service and small enough that the order is
readable from one database row.

**When it fails over.** All of these, together:

- the method is idempotent (GET/HEAD/OPTIONS) **and** the body was buffered;
- the client is still there and the request is inside its total deadline;
- no response bytes have gone to the client yet;
- an attempt is still available inside the route's existing ceiling;
- and the primary failed with a transport error, an open circuit breaker, or a
  502, 503 or 504.

**When it does not.** POST never fails over - an LLM completion may already have
been generated and billed upstream, and "it returned 503" is not evidence that
it did nothing. Nor does an unbuffered or over-limit body, a 401/403/429 or any
other 4xx, a response that has started streaming, a cancelled client, or a
credential the gateway does not have. Hedging is unchanged and races the primary
only.

**One ceiling, one hold.** A fallback is an attempt spent out of the route's
existing `1 + retry_max` budget, not a second retry budget - one attempt of it
is reserved so the fallback can actually be reached, which is why a fallback
needs `retries >= 1` and is refused without it. Budget is untouched: one spend
hold and one settlement per request, however many upstreams it touched.

**Credentials are per candidate.** The fallback names its own header and
environment variable. A fallback is usually a different provider, and one shared
env var is how one provider's key reaches another one. Existing rows have no
fallback and need no operator action.

**Measured locally** (`go test ./internal/proxy -run TestOrderedRoutePlanEvaluation -v`,
300 requests per arm, written to `results/route-plan-eval.json`):

| arm | success | attempts/req | fallbacks | p50 | p95 | p99 |
|---|---|---|---|---|---|---|
| failing primary, single upstream | 0.00% | 2.00 | 0 | 14.756ms | 25.143ms | 26.273ms |
| failing primary, ordered plan | 100.00% | 2.00 | 300 | 0.151ms | 0.335ms | 0.486ms |
| all healthy, single upstream | 100.00% | 1.00 | 0 | 0.041ms | 0.061ms | 0.183ms |
| all healthy, ordered plan | 100.00% | 1.00 | 0 | 0.040ms | 0.053ms | 0.106ms |

Zero body-integrity failures in every arm. With a healthy primary the fallback
is contacted zero times and costs the same one attempt per request, so the
overhead when it is not needed is nothing measurable. The latency gap in the
failing case is the retry backoff: the single-upstream arm waits and asks the
same dead upstream again, while the plan goes straight to a different one.

Two httptest servers and a proxy in one process on one machine. The "outage" is
a handler that was told to return 503. This is not a datacenter, a provider, a
network partition or a real failover, the success rates are arithmetic about a
scripted condition rather than evidence about availability, and it says nothing
at all about LLM traffic, which is POST and never fails over.

## Abuse limits and backpressure

A rate limit bounds how *often* a tenant calls. It says nothing about how big
each call is, how many are still open, or how long any of them may run - and a
gateway in front of a metered provider is judged on all three. Every number
below was measured before it was picked (`TOLLGATE_MEASURE=1 go test
./internal/middleware/ -run TestMeasure -v`), and every one is an environment
variable where `0` means "not enforced":

| bound | env | default | measured reason |
| --- | --- | --- | --- |
| request body, on the wire | `MAX_REQUEST_BYTES` | 8 MiB | a 256 MiB chunked upload was relayed in 154 ms at no cost to the gateway: unbounded free amplification into a paid upstream |
| request body, decompressed | `MAX_DECOMPRESSED_BYTES` | 8 MiB | padded JSON gzips ~510:1, so a wire cap alone admits 4 GiB of expansion |
| response body | `MAX_RESPONSE_BYTES` | 32 MiB | a 512 MiB response streamed through in 278 ms, all of it egress the gateway pays for and does not choose |
| concurrent per tenant | `MAX_INFLIGHT_PER_TENANT` | 64 | ~1.06 MiB of heap and 3 gateway goroutines per open 1 MiB request; 512 of them cost 542 MiB with nothing refusing any |
| queue depth per tenant | `MAX_QUEUE_PER_TENANT` | 128 | a parked request costs ~62 KiB, so a queue absorbs a burst cheaply - but an unbounded one only converts a retryable 429 into a timeout |
| queue wait | `QUEUE_WAIT` | 1s | |
| total request time | `MAX_REQUEST_DURATION` | 60s | `retry_max=20` at a 200 ms route timeout held a goroutine for 2.2 s; at a realistic 30 s timeout the same row is ten minutes |
| retries | hard-coded | 5 attempts | `retry_max` is a Postgres column; 20 attempts tripped the per-host breaker every tenant on that upstream shares |

Two properties are worth more than the numbers:

- **Concurrency is capped per tenant, not globally.** A global cap lets one
  caller's fan-out refuse everybody else's traffic, which is the starvation the
  cap exists to prevent. A hostile tenant gets `429` with `Retry-After` while a
  well-behaved one is served normally, and the tenant is served again the moment
  it stops (`TestOverloadRejectsPredictablyAndRecovers`).
- **Nothing refused by a limit touches the spend ledger.** `RequestSize`,
  `RateLimit` and `Concurrency` all sit outside `Budget`, so a request rejected
  for size or backpressure cannot leave a hold behind. That invariant is pinned
  against a real PostgreSQL, not a fake
  (`TestSizeRefusalLeavesNoSpendHold`).

A compressed body is inflated for pricing only; the caller's compressed bytes
still go upstream unchanged. Without that, `Content-Encoding: gzip` was a
complete budget bypass: the estimator could not parse the body, so the request
was forwarded with no hold at all. A `Content-Encoding` the gateway cannot
inflate is refused with `415`, because a body whose size cannot be bounded is
the bypass restated.

## Observability

- **RED per tenant and route**: `tollgate_requests_total` / `tollgate_request_duration_seconds{tenant,route,method,code}` - label values come from operator-controlled config, never request data, so cardinality is bounded.
- **Traces**: OTLP export, W3C context propagated in and out; upstream attempts are client spans tagged with attempt number.
- **Logs**: one JSON line per request (sampled 1-in-N under load) carrying request id, trace id, tenant, route, status, duration, upstream, attempts, hedged flag.
- Limiter health (`check duration`, `errors`, decisions by outcome), breaker state, retry/hedge counters, config reload counters, in-flight gauge, plus Go runtime and pprof on the admin port.
- Admin listener (`:9090`) is separate from tenant traffic: `/healthz`, `/readyz`, `/metrics`, `/debug/pprof`.

### Security events, and what happens when one fires

The metrics above say a rate limit was hit 400 times. They cannot say whether
that was one tenant's runaway loop or somebody working through a list of key
ids, and they cannot connect it to the certificate mismatch thirty seconds
earlier or to the spend that followed. So every control that already makes a
security decision now also emits one structured event where it makes it:
a refused credential, a certificate binding that did not match, a token id
arriving from a second peer, a limiter refusal, a key used inside its rotation
grace window, a rotated key spending fast, an upstream target refused for being
a metadata endpoint, an upstream attempt that timed out or was carried by a
hedge.

Each event carries the four fields that make it usable an hour later - tenant,
trace id, which control decided, and what it decided - and goes onto the
request's span as well as into the log, so a decision and the request it was
about are one trace rather than two systems to join by hand.

Three things had nothing to observe, so they were added, and all three are
detection only:

- a bounded in-memory filter that reports a token id presented by a second
  peer inside its lifetime. Whether that request is refused is still decided
  by RFC 8705 certificate binding, which already existed. An unbound token is
  admitted exactly as it was before.
- a detector that joins two facts the gateway already had and never read
  together: a key on its way out of a rotation, and real money in five
  seconds. The budget ledger remains the only thing that can refuse a request
  on spend.
- one allow-list that refuses an upstream which is a cloud instance metadata
  endpoint, at route upsert and again at route resolution. RFC 1918 and
  loopback are deliberately allowed, because compose and kind proxy to both.

There is no ban list, no automatic response and no suppression: the events
observe controls, and `docs/runbooks/` is a page per event saying how to
confirm it and what a person does next.

**What was measured**, on one laptop, in one process, against synthetic
scripted traffic driven through the real middleware chain - no Redis, no
Postgres, no network:

```bash
./scripts/run-security-ops-eval.sh
```

From the run committed in [`results/`](results/):

| | |
|---|---|
| malicious scenarios detected | 6 of 6 |
| alerts on a matched benign replay (same tenants, keys, routes, request count) | 0 |
| incidents carrying tenant, trace, control and outcome | all |
| normalized timeline identical across two runs | yes |
| planted negative control caught | yes |
| detection delay, median / max | 0 ms / 823 ms |

The design was frozen in [`secops/manifest.json`](secops/manifest.json) -
scenarios, rules, thresholds, success marks - and committed before any
detection code existed, so no number here was chosen after seeing a result.
The negative control is a build tag that breaks one correlation edge; the
script requires that build to FAIL, because a linkage check that has never
failed has not been shown to be able to. Results and the full timeline are in
[`results/`](results/).

What this is not: there is no SOC, no on-call rotation and no production
traffic anywhere in it. Every incident in those results was caused on purpose
by the harness seconds earlier, the detection delays are measured inside a
script that controls its own timing, and the whole thing is one process on one
host. The 823 ms is how long a scripted cascade took to produce its own
recovery event, not how fast anybody would notice.

## Running it

### Local (docker compose)

```bash
make up                                             # gateway + redis + postgres + 2 upstreams + prometheus + jaeger
eval "$(scripts/seed.sh compose | grep '^export')"  # demo tenants; puts their API keys in this shell
curl -H "X-API-Key: $TOLLGATE_KEY_LOADTEST" localhost:8080/echo/hello
```

`make seed` is the same thing without the `eval`, for when you only want to look
at the keys rather than use them. Either way the schema is already there: the
compose gateway runs with `AUTO_MIGRATE=true`, because the image is distroless
and a fresh Postgres volume has no tables for it to read at boot. Seeding adds
tenants and routes to a schema that already exists.

The console is at <http://localhost:8080/_admin/>; `make up` prints the local
`ADMIN_TOKEN` it defaulted to. Override it with `export ADMIN_TOKEN=...` before
`make up`.

The API behind the console is specified in `internal/admin/openapi.json`. The
document is checked against the router in both directions on every test run: an
endpoint that is served without being declared fails, and so does a declared
endpoint that nothing serves. Every operation is driven with generated boundary
inputs, and a status code the document does not list fails too.

### Kubernetes (kind) - the full story

```bash
make kind-up              # cluster with NodePort 30080 mapped to localhost
make kind-load            # build images, load into kind
make tf-apply             # Terraform: Redis + Postgres (+ credentials Secret)
make monitoring-install   # Prometheus (5s scrape) + prometheus-adapter
make helm-install         # gateway ×3, HPA on p99, PDB, drain-aware probes
make kind-seed            # migrate + seed + issue keys
make k6-baseline          # or: k6-correctness / k6-fairness
scripts/demo-distributed-vs-memory.sh   # the headline proof, end to end
```

The HPA consumes `tollgate_p99_latency_ms`, computed by prometheus-adapter as `histogram_quantile(0.99, ...)` per pod over 2m, targeting 150ms average.

## Methodology

- Hardware: single Apple M-series laptop running Docker Desktop; kind is one node, so gateway replicas, upstreams, Redis, Postgres, Prometheus **and k6 share the machine**. Numbers demonstrate correctness and relative behaviour, not datacenter capacity.
- Demo upstreams add 5–15ms simulated latency (`BASE_DELAY_MS`/`JITTER_MS`), included in every latency figure above.
- Load enters through kind's NodePort mapping (Docker's port proxy), also included in the figures.
- Access logs sampled 1-in-100 during load tests; RED metrics are always complete.
- Every number in this README is reproducible via `make` targets; raw k6 JSON lands in `loadtest/results/`.

## Testing

```bash
make test               # table-driven unit tests
make test-race          # same, -race
make test-integration   # Lua scripts against real Redis (needs `make up`)
make schemathesis       # 300 boundary cases/operation plus bounded stateful sequences

# Management API against a real Postgres:
TOLLGATE_TEST_POSTGRES=postgres://tollgate:tollgate@localhost:5432/tollgate \
    go test ./internal/admin/
```

- Limiter algorithms: table-driven with a fake clock (burst, refill, window slide, retry-after math, tenant isolation).
- The **atomicity integration test** floods one tenant from 20 goroutines and asserts admissions never exceed the policy ceiling - the property everything else rests on.
- Management surface: every API route is asserted to answer 401 for a missing, wrong, wrong-scheme, empty and trailing-junk token, with a **nil store** behind it, so a leak past the gate would panic rather than pass quietly. The integration test walks the real flow against Postgres: issue, confirm the plaintext is never served again from any endpoint, add a credential-injecting route, rotate into a grace window, refuse to rotate the same key twice, revoke (200 then 404), and flip the kill switch.
- Breaker: full state-machine walk (trip threshold, cooldown, probe budget, failure aging) on a fake clock. Hedge: winner/loser/cancellation semantics against live `httptest` servers. Proxy: forwarding, prefix strip, retry counts, 502/504 mapping, breaker integration, hedge wins. Auth: every rejection reason, plus a regression test for base64url secrets containing `_`.

The management API has two independent generated checks. The native Go corpus
keeps endpoint discovery tied to the operation table that mounts the routes and
checks hostile body and path inputs during the ordinary suite. `make
schemathesis` starts the real gateway over a socket with an isolated disposable
Postgres container, then runs pinned Schemathesis coverage, fuzzing and stateful
phases against all nine OpenAPI operations with complete response schemas. The
native tests separately exercise every route with missing and malformed admin
credentials. The database is destroyed after the run because the generated
sequences create, rotate and delete API objects.

## Repository layout

```
cmd/gateway            main: config → wiring → serve → drain
cmd/tollgate-admin     tenants / routes / issue-key / rotate-key / revoke-key
cmd/upstream           echo backend with tunable latency & failure injection
cmd/tollgate-secops-replay  scripted attack replay behind scripts/run-security-ops-eval.sh
internal/ratelimit     limiter.go, tokenbucket.lua, slidingwindow.lua, redis.go, memory.go
internal/resilience    breaker.go, retry.go, hedge.go
internal/proxy         hand-rolled forwarding engine
internal/middleware    the request pipeline
internal/store         pgx store, immutable snapshots, LISTEN/NOTIFY watcher, config writers
internal/admin         management API + console + openapi.json (only built when ADMIN_TOKEN is set)
internal/auth          key format, hashing, verification, scopes, rotation
internal/jwt           JWS verification, JWKS cache, claims, RFC 8705 binding
internal/secops        security events, append-only timeline, correlator, detectors, replay harness
internal/observability metrics registry, otel setup, slog
migrations/            schema + NOTIFY triggers, parameterized seed
deploy/helm/tollgate   chart: deployment, service, HPA (custom metric), PDB
deploy/terraform       Redis + Postgres + credentials into the cluster
deploy/monitoring      prometheus + adapter values (the p99 metric rule)
deploy/paas            one-click templates: Render blueprint, fly.toml, railway.json
loadtest/              k6: baseline, correctness, fairness
```

## Limitations (known, deliberate)

- No WebSocket/Upgrade passthrough; no gRPC-specific handling.
- Single Redis; a production deployment would use Redis Cluster (keys are already hash-tagged per tenant) or replicas with fail-open covering failover.
- OIDC issuers are configured in the environment and not in Postgres, so adding one restarts the gateway. Deliberate: an issuer entry says which signing keys may mint a credential for which tenant, and in a table the admin API can write, that would be a privilege escalation rather than a configuration change. See [`docs/token-auth.md`](docs/token-auth.md).
- The token path verifies asymmetric signatures only (RS/PS/ES). An identity provider signing with HS256 or EdDSA is not supported, and the first of those is on purpose.
- A verified-token cache is on by default with a 30s TTL. A revoked *signing key* is honoured for at most `OIDC_JWKS_TTL` because a cache hit re-checks key liveness, but a stolen and still-unexpired token keeps working until it expires. Certificate binding is the answer to that, and it needs the issuer to implement RFC 8705.
- API-key secrets use SHA-256, which is correct for 256-bit random secrets (there is nothing to brute-force) but would be wrong for human passwords - that trade-off is documented in `internal/auth`.
- Rate limit check adds one Redis RTT to every admitted request. In the matched 12-pair rerun, the paired Redis-minus-memory p50 delta had a 0.0425..0.1190 ms IQR locally and a 0.0245..0.7025 ms IQR on AWS EKS. The intervals overlap. See [`bench/METHODOLOGY.md`](bench/METHODOLOGY.md) and the committed raw results.
- kind's NodePort path is a single proxy hop; a real deployment would sit behind a proper LB.
- The gateway host is fully trusted: it holds the shared provider credentials in its environment. That's the point (teammates can't leak what they don't have), but it means the box itself must be treated like the secret it carries.
- Rate limits meter *requests*, not tokens; a token-aware budget (parse usage from provider responses) is the natural next step for the LLM use case.
- The security event layer is detection only and per process. The token replay filter and the spend anomaly window live in one gateway's memory, so a replay that lands on a different replica, or after a restart, is a first sighting, and a tenant spread across replicas is a fraction of itself in each window. Correlating across replicas would need the events shipped somewhere, which is a log pipeline this repo does not have.
- The upstream metadata guard reads the host as written and does not resolve names. A hostname whose DNS answer is a metadata address passes it, and always will: resolution happens in the dialer, and an answer that passed a check can change before the connection is made.

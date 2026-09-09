# Runbook: upstream timeout cascade

## What fires

Three or more `event_type: upstream_timeout_cascade` events with
`outcome: timed_out` on one upstream host inside fifteen seconds, followed by
one with `outcome: fell_back`.

The individual events come from three controls that already existed:

| `control` | `outcome` | means |
|---|---|---|
| `retry_budget` | `timed_out` | one attempt ran out of its route timeout. |
| `circuit_breaker` | `rejected` | the breaker refused to make an attempt at all. |
| `request_hedge` | `fell_back` | a backup attempt overtook a slow primary and answered. |

The grouping is by **upstream host, not tenant**, because the breaker is per
host and shared by every tenant routed to it. `affected_tenant_count` on the
incident is the number of tenants one upstream took with it.

The `fell_back` event is the one worth having: the client saw 200, so nothing
in a status code or a RED metric says anything happened.

## Read these fields

| field | what it tells you |
|---|---|
| `evidence.upstream_host` | the upstream. This is the group key. |
| `provider_attempt` | which attempt this was, 1-based. |
| `evidence.attempts_allowed` | how many the route was allowed, after the hard cap of 5. |
| `evidence.route_timeout_ms` | the per-attempt deadline that expired. |
| `evidence.fallback_mechanism` | `hedge` on the `fell_back` event. |
| `hedged`, `fallback` | the flags, so a filter can find the recoveries without parsing evidence. |

## Confirm it

1. `tollgate_circuit_breaker_state{upstream=...}`: 0 closed, 1 open, 2
   half-open. An `outcome: rejected` event and a gauge at 1 are the same
   fact from two directions.
2. `tollgate_circuit_breaker_transitions_total` for when it moved, and the
   gateway's own `circuit breaker transition` log lines.
3. `tollgate_upstream_request_duration_seconds{upstream=...,code="error"}` for
   the shape of the failure over time.
4. Open a `trace_id` from a timed-out event. Each attempt is its own client
   span tagged with its attempt number, so the trace shows the retries
   stacking up inside one request.
5. Count the distinct `tenant_id`s in the incident's evidence. More than one
   means this upstream is taking other people's traffic down with it.

## Recovery action

**Open breaker and fall back** - which is what already happened, without
anybody doing anything. The controls handled it; the events are so that
somebody knows it happened. What is left for a person:

1. Fix or replace the upstream. Everything below is a way of surviving it,
   not of fixing it.
2. If the route's `timeout_ms` is longer than the upstream's realistic worst
   case, shorten it: a long timeout turns a slow upstream into held
   connections, held concurrency slots and held spend holds.
3. If `retry_max` is high, lower it. Attempts are capped at 5 regardless, but
   5 attempts against a dying upstream is 5 breaker samples per request, and
   the breaker is shared by every tenant on that host.
4. If the route can usefully hedge, enable hedging on it: the `fell_back`
   event in this incident is a request that succeeded because it was.

## What this runbook does not cover

- **There is no fallback upstream.** "Fell back" here means a hedge, a second
  attempt at the same upstream, which helps with a slow tail and not at all
  with an upstream that is down. This gateway has no notion of a secondary
  provider.
- **A 500 from an upstream that answered is not in here.** Only timeouts and
  breaker refusals are recorded, because those are the two that compound. An
  upstream returning errors quickly is in the RED metrics and is a different
  problem.
- **Retries are only for idempotent methods.** GET, HEAD and OPTIONS. An LLM
  `POST` is sent exactly once, so a cascade on a route that only carries
  POSTs shows one `timed_out` event per request and never reaches the
  threshold of three from a single request.
- **The thresholds are frozen.** Three timeouts in fifteen seconds is the
  number in `secops/manifest.json`, chosen before any result existed. It is
  not tuned to any deployment's traffic.

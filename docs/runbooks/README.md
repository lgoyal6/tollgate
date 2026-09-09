# Runbooks

One page per security event this gateway emits, for whoever is looking at a
timeline and wondering what to do next.

| runbook | fires when | recovery action |
|---|---|---|
| [stolen-token-replay](stolen-token-replay.md) | one token id arrives from a second peer inside its lifetime | revoke key |
| [cert-binding-mismatch](cert-binding-mismatch.md) | a token bound to one certificate is presented with another | rotate key |
| [provider-key-anomaly](provider-key-anomaly.md) | a key inside its rotation grace window spends fast | revoke key |
| [ssrf-metadata-attempt](ssrf-metadata-attempt.md) | a route's upstream is a cloud instance metadata endpoint | reject route |
| [auth-rate-burst](auth-rate-burst.md) | ten refused credentials or limiter refusals for one tenant in five seconds | disable tenant |
| [upstream-timeout-cascade](upstream-timeout-cascade.md) | an upstream times out repeatedly and something falls back | open breaker and fall back |

## What all of these assume

Events are written by `internal/secops` at the point each control decides.
They reach two places: the gateway's structured log, one line per event with
`event_type`, `control` and `outcome`; and the request's OpenTelemetry span,
as a span event carrying the same fields. Nothing is aggregated, alerted on,
or sent anywhere. There is no pager behind any of this.

Every page below tells you how to confirm the event from the timeline and the
trace, and then what to do by hand. None of them describe an automatic
response, because there is none: this layer observes controls, it does not
act. Deciding to revoke a key is a person's job and the console
(`/_admin/`) or `tollgate-admin` is where it is done.

## Reading a timeline

The evaluation harness writes one at `results/security-ops-timeline.jsonl`;
a running gateway writes the same events into its own log. Either way an
event looks like this, and the four fields that make it useful an hour later
are `tenant_id`, `trace_id`, `control` and `outcome`:

```
{"event_id":41,"timestamp":"...","event_type":"token_replay","request_id":"...",
 "trace_id":"...","span_id":"...","tenant_id":"replay-co","key_id":"oidc:user-replay",
 "route":"/api/","provider_attempt":0,"hedged":false,"fallback":false,
 "control":"oidc_token_replay_detector","outcome":"allowed",
 "evidence":{"token_id":"jti:...","peer":"cert:...","first_seen_peer":"cert:..."}}
```

`tenant_id` is `unauthenticated` on any event for a request that never
resolved to a tenant. That is not a gap in the record: a credential the
gateway refused was never accepted as anybody's, and guessing whose it might
have been is how a rejection turns into an accusation.

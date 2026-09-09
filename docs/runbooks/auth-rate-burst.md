# Runbook: auth and rate burst

## What fires

Ten or more of `event_type: auth_rejected` or `event_type: rate_burst`, for
one tenant, inside five seconds. The individual events come from
`api_key_verification`, `oidc_token_verification` and
`ratelimit_sliding_window`; the burst is the correlator's conclusion, not any
one event's.

Expect two of these at once during a real burst, on two different groups:

- **`tenant_id: unauthenticated`** for refused credentials. A credential the
  gateway refused was never accepted as anybody's, so it has no tenant.
- **A named tenant** for limiter refusals, which by definition happened after
  a credential was accepted.

They are different findings. The first is somebody trying to get in; the
second is somebody who is in, going too fast.

## Read these fields

| field | what it tells you |
|---|---|
| `evidence.reason` on `auth_rejected` | `missing`, `malformed`, `unknown_key`, `bad_secret`, `revoked`, `grace_expired`, `tenant_disabled`, or a `jwt_*` reason. |
| `evidence.credential_type` | `api_key`, `token` or `none`. |
| `evidence.limit`, `evidence.remaining`, `evidence.retry_after_seconds` on `rate_burst` | the policy that refused, as the client saw it. |
| `evidence.algorithm` | `token_bucket` or `sliding_window`. |

`bad_secret` is the interesting reason: it means the key id exists. Somebody
has a real key id and the wrong secret, which is a different situation from
`unknown_key`, where they are guessing.

## Confirm it

1. Bucket the `auth_rejected` events by `evidence.reason`. A wall of
   `unknown_key` is scanning; a wall of `bad_secret` against one key id is
   somebody working on one credential.
2. Check `tollgate_auth_failures_total` for the same window. The metric and
   the events carry the same reason labels, so they should agree; if they do
   not, one of them is sampled and it is not the events.
3. For the limiter half, look at `tollgate_ratelimit_decisions_total` for the
   tenant, and at whether the 429s are one client or the tenant's whole fleet.
4. Open any `trace_id` to see the path and the source address.

## Recovery action

**Disable tenant** - but only for the named-tenant half, and only if the
traffic is actually hostile rather than merely enthusiastic. The tenant kill
switch is **Cut off** in the console at `/_admin/`, which is the management
API's tenant update with `enabled` false. (`tollgate-admin` has
`create-tenant`, `add-route`, `issue-key`, `rotate-key`, `revoke-key`, `list`
and `migrate`; disabling a tenant is a console or API action.) It binds on
every replica before the next protected action, because the gateway rechecks
tenant enablement with a targeted query immediately before acting.

For the `unauthenticated` half there is nothing to disable, because there is
no account. The refusals are already the correct outcome: the limiter and
the auth path are doing their jobs, and the burst is a signal, not damage.
If the source is one address, that belongs in front of the gateway - a load
balancer or firewall rule - because this gateway deliberately has no ban
list.

If the named tenant is legitimate and simply outgrew its policy, the action
is the other one: raise its limit. The console shows whose 429 count is
climbing.

## What this runbook does not cover

- **No ban list, no automatic anything.** Nothing in this gateway blocks a
  source address, and nothing here does anything on its own. Every action
  above is a person deciding.
- **It cannot tell you whose the refused credentials were.** By design: see
  the `unauthenticated` note above.
- **It is per process.** The correlator sees one gateway's events. A burst
  spread across replicas is a fraction of itself on each.
- **Ten in five seconds is a frozen number, not a tuned one.** It was picked
  before any result was produced (`secops/manifest.json`) and has not been
  moved since. A deployment with different traffic would need a different
  number and would need to re-run the evaluation to say what it costs.

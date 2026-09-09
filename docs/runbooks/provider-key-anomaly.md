# Runbook: provider key anomaly

## What fires

`event_type: provider_anomaly`, `control: provider_spend_anomaly_detector`,
`outcome: allowed`.

All three of these were true at once, inside one five-second window, for one
tenant and key:

- the key is in its rotation grace window (`key_rotation` events are being
  emitted for it),
- at least 10 requests settled,
- and they cost at least 2,000,000 micros, which is two dollars.

Each fact alone is ordinary. A rotated key still working is the grace window
doing its job. Money moving is the point of the gateway. The conjunction is a
credential that was supposed to be on its way out, spending fast, and nothing
else in the gateway reads those two columns together.

## Read these fields

| field | what it tells you |
|---|---|
| `evidence.requests_in_window` | how many settled requests were in the window when it fired. |
| `evidence.spend_micros_in_window` | what they cost. Micros are 1e-6 USD, the unit the ledger uses. |
| `evidence.min_requests`, `evidence.min_spend_micros` | the frozen thresholds, so the event says what it was measured against. |
| `key_id` | the rotated key. This is the thing to revoke. |
| `tenant_id` | whose budget is being spent. |
| `outcome` | `allowed`, always. The detector refuses nothing. |

## Confirm it

1. Look for `key_rotation` events on the same `tenant_id` and `key_id`
   immediately before. Those are the requests that made up the window.
2. Check the key's row: `tollgate-admin list` shows its status and
   `grace_until`. If the grace window has hours left, the spend has hours
   left too.
3. Open any of the `trace_id`s. The span carries the route, the upstream and
   the provider attempt, so you can see which model is being called.
4. Compare with the tenant's ledger (`internal/budget`): the settled totals
   are rows, and `OpenOlderThan` shows holds that never closed.

## Recovery action

**Revoke key.** Rotation left the old key alive so a client could migrate; if
it is spending like this, the migration either happened (and something else
is using the old key) or is not going to.

```sh
tollgate-admin revoke-key <key_id>
```

Revocation binds on every replica before the next protected action, not on
the next snapshot reload, because the gateway re-checks key liveness with a
targeted query immediately before acting.

If the spend is legitimate - a client that genuinely has not migrated and
genuinely got busy - the action is the other one: finish the migration and
shorten the grace window, rather than leaving a credential nobody is watching
in a state where it still works.

## What this runbook does not cover

- **It does not refuse anything.** The budget ledger is still the only thing
  that can turn a request down on spend, and it does that against the
  tenant's limit, not against this detector. A tenant with no budget row is
  unlimited and this event will not change that.
- **It is per process.** The window lives in the gateway's memory, so a
  tenant spread across replicas has one window per pod and each sees a
  fraction of the traffic. Multi-replica deployments will fire later than a
  single one, or not at all.
- **It only sees priced, settled requests.** A model with no entry in the
  price table, or a response with no usage block, settles nothing and
  contributes nothing to the window. Spend the gateway cannot price is spend
  this detector cannot see.
- **It says nothing about active keys.** By construction: `require_rotated_key`
  is part of the frozen rule, because an active key spending fast is a busy
  tenant and the rate limiter and budget already have opinions about that.

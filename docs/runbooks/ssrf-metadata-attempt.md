# Runbook: SSRF, upstream is a metadata endpoint

## What fires

`event_type: ssrf_rejected`, `control: upstream_metadata_allowlist`,
`outcome: rejected`.

A request matched a route whose upstream host is a cloud instance metadata
endpoint, and the gateway refused it with 502 before opening a connection.

This matters here more than it would in a plain proxy. A route in this
gateway can carry credential injection: the shared provider key is attached
from the gateway's environment on the way out. So a route pointing at the
metadata service is two things at once, an outbound request from inside your
network to the endpoint that hands out the machine's own role credentials,
and your provider key going with it.

## Read these fields

| field | what it tells you |
|---|---|
| `evidence.upstream_host` | the host that was refused. |
| `evidence.reason` | which rule refused it, in a sentence you can show an operator. |
| `evidence.route_id` | the `routes` row to fix. |
| `tenant_id`, `route` | whose route it is and which prefix. |

## Confirm it

1. Look up the route: `tollgate-admin list` or
   `SELECT * FROM routes WHERE id = <route_id>`.
2. Check `upstream_auth_env` on that row. If it is set, the route was
   configured to attach the shared provider credential to whatever it
   reached, and this refusal is the only reason it did not.
3. Check when the row was written and by whom. The management API refuses
   these at upsert time, so a row that exists at all arrived some other way:
   a migration, a direct `UPDATE`, or before this check existed.
4. Open `trace_id` for the request that hit it, to see who was calling the
   prefix.

## Recovery action

**Reject route.** Delete the row, or repoint it:

```sh
tollgate-admin list                  # find the route id
# then remove it through the console, or:
DELETE FROM routes WHERE id = <route_id>;
```

Every replica picks the change up through `LISTEN/NOTIFY` without a restart.

Then work out how it got there. If somebody typed it, the management API
would have refused it, so it did not come from there.

## What this runbook does not cover

- **Names are not resolved.** The check reads the host as written. A hostname
  whose DNS answer is a metadata address passes it, and always will:
  resolution happens in the dialer, and an answer that passed a check can
  change before the connection is made. DNS rebinding is out of scope for a
  check at this layer.
- **Private addresses are deliberately allowed.** RFC 1918, carrier NAT and
  loopback are not refused, because this repo's own compose stack proxies to
  localhost and its kind deployment proxies to a private pod network.
  Refusing those would break every self-hosted deployment and teach the first
  person who hit it to disable the guard.
- **It is a host check, not an egress policy.** Anything else reachable from
  the gateway is still reachable. If the deployment needs a real egress
  boundary, that belongs in the network, not in a route validator.
- **The config-time half emits no event.** `store.RouteSpec.Validate`
  refuses the same hosts at upsert time and answers 400, but it has no
  request, no tenant and no trace to attach an event to, so the management
  API's own response is the record there. Only the request-time refusal
  produces `ssrf_rejected`.

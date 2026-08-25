# Contributing to tollgate

Thanks for looking. tollgate sits in front of somebody's real provider credential
and hands out revocable keys instead, so the two areas below get scrutinised
harder than the rest of the codebase. Everything else is a normal Go project.

## The two properties that have to hold

**Admission is correct across replicas.** Rate-limit decisions execute as atomic
Lua in shared Redis, so three gateway pods enforcing "300 req/s" admit 300 req/s
and not 900. The integration test that floods one tenant from 20 goroutines and
asserts admissions never exceed the ceiling is the property everything else rests
on. If a change makes that flaky, it is not flaky, it is broken.

**The upstream credential never leaves the gateway.** It lives in the gateway's
environment and is injected on the way out. A teammate's key is a different
object entirely: hashed at rest, and the plaintext is served exactly once at
issue time and never again from any endpoint. There is a test asserting that
second part; do not weaken it for debugging convenience.

The management API is tested with a **nil store** behind it, so anything that
slips past auth panics rather than quietly succeeding. Keep new routes inside
that pattern.

## Getting oriented

| Path | What lives there |
|---|---|
| `internal/ratelimit/` | `limiter.go` plus `tokenbucket.lua` and `slidingwindow.lua`, the atomic scripts |
| `internal/resilience/` | Breaker, retry, hedge |
| `internal/proxy/` | The hand-rolled forwarding engine |
| `internal/auth/` | Key format, hashing, verification, scopes, rotation |
| `internal/store/` | pgx store, immutable snapshots, LISTEN/NOTIFY watcher |
| `internal/admin/` | Management API and console, built only when `ADMIN_TOKEN` is set |
| `deploy/` | Helm chart, Terraform, monitoring values, one-click PaaS templates |
| `loadtest/` | k6 scenarios: baseline, correctness, fairness |

## Building and testing

```bash
make build
make test
make test-race
make up                 # local compose stack: Redis + Postgres
make test-integration   # Lua against real Redis; needs make up
make seed               # demo tenants, prints API key exports
```

The management API tests need a real Postgres:

```bash
TOLLGATE_TEST_POSTGRES=postgres://tollgate:tollgate@localhost:5432/tollgate \
    go test ./internal/admin/
```

For anything touching multi-replica behaviour there is a full local cluster path:
`make kind-up`, `make tf-apply`, `make monitoring-install`, `make helm-install`.

## What makes a good PR here

- One concern per PR, with a test that fails before and passes after.
- Changes to either `.lua` script need an integration-test case, not just a unit
  test with a fake clock. The whole point of those scripts is what happens under
  real concurrent Redis, which a fake clock cannot show you.
- New limiter algorithms are welcome, but they must be expressible as a single
  atomic script. A read-then-write split in Go is exactly the bug this project
  exists to avoid.
- Auth changes need the full rejection matrix extended: missing, wrong,
  wrong-scheme, empty and trailing-junk tokens.
- Numbers in the README come from `loadtest/` under k6. If your change moves them,
  include before and after output rather than editing the tables.
- New config keys need a migration in `migrations/` if they are per-tenant, and
  the NOTIFY trigger updated so running gateways pick them up without a restart.

## Good first areas

- `cmd/upstream` has tunable latency and failure injection but no scripted
  scenarios; a small library of them would make the resilience tests easier to
  read.
- The Helm chart exposes one custom HPA metric. A second, on admission-rejection
  rate, is a self-contained addition in `deploy/`.
- Deploy templates: `deploy/paas` covers Fly and Railway, and `render.yaml` at the
  repo root drives the Render deploy button. Another platform is a contained,
  verifiable contribution.

## Conduct

Be decent. Disagree about the code, not about the person.

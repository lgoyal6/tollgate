#!/usr/bin/env bash
# Apply migrations and seed demo tenants + API keys.
#
# Usage:
#   scripts/seed.sh compose   # docker compose stack (default)
#   scripts/seed.sh kind      # kind cluster (runs psql inside the postgres pod)
#
# Prints one export line per tenant API key; eval the output to use them:
#   eval "$(scripts/seed.sh compose | grep '^export')"
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-compose}"

case "$MODE" in
  compose)
    UPSTREAM_A="upstream-a:9000"
    UPSTREAM_B="upstream-b:9000"
    PSQL=(docker compose exec -T postgres psql -q -U tollgate -d tollgate)
    ADMIN=(docker compose exec -T -e DATABASE_URL=postgres://tollgate:tollgate@postgres:5432/tollgate gateway /tollgate-admin)
    ;;
  kind)
    UPSTREAM_A="upstream-a.tollgate.svc.cluster.local:9000"
    UPSTREAM_B="upstream-b.tollgate.svc.cluster.local:9000"
    PG_POD=$(kubectl -n tollgate get pod -l app=postgres -o jsonpath='{.items[0].metadata.name}')
    PSQL=(kubectl -n tollgate exec -i "$PG_POD" -- env PGPASSWORD="$(kubectl -n tollgate get secret postgres-credentials -o jsonpath='{.data.password}' | base64 -d)" psql -q -U tollgate -d tollgate)
    GW_POD=$(kubectl -n tollgate get pod -l app.kubernetes.io/name=tollgate -o jsonpath='{.items[0].metadata.name}')
    ADMIN=(kubectl -n tollgate exec -i "$GW_POD" -- /tollgate-admin)
    ;;
  *)
    echo "unknown mode: $MODE (want compose|kind)" >&2; exit 1 ;;
esac

echo "==> applying migrations" >&2
for m in migrations/0*.sql; do
  echo "    $m" >&2
  "${PSQL[@]}" < "$m" >/dev/null
done

echo "==> seeding tenants and routes" >&2
sed -e "s|__UPSTREAM_A__|$UPSTREAM_A|g" -e "s|__UPSTREAM_B__|$UPSTREAM_B|g" \
  migrations/seed.sql | "${PSQL[@]}" >/dev/null

echo "==> issuing API keys" >&2
for tenant in loadtest metered bursty noisy quiet; do
  out=$("${ADMIN[@]}" issue-key -tenant "$tenant" -scopes read,write)
  key=$(echo "$out" | tail -1)
  var="TOLLGATE_KEY_$(echo "$tenant" | tr '[:lower:]' '[:upper:]')"
  echo "export $var=$key"
done
echo "==> done" >&2

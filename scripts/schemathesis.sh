#!/bin/bash
# Run the pinned Schemathesis client against Tollgate's real management API
# over a socket. The generated corpus is isolated in a disposable Postgres
# container because it creates, rotates and deletes API objects.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-18731}"
ADMIN_PORT="${ADMIN_PORT:-19091}"
DB_PORT="${DB_PORT:-15543}"
EXAMPLES="${EXAMPLES:-300}"
STATEFUL_EXAMPLES="${STATEFUL_EXAMPLES:-50}"
SEED="${SEED:-20260905}"
TOKEN="${TOKEN:-test-admin-token-0123456789}"
CONTAINER="tollgate-schemathesis-$$"
TMP="$(mktemp -d)"

cleanup() {
    kill "${SERVER:-}" 2>/dev/null || true
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT

docker run -d --name "$CONTAINER" \
    -e POSTGRES_USER=tollgate -e POSTGRES_PASSWORD=tollgate \
    -e POSTGRES_DB=tollgate -p "$DB_PORT":5432 postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do
    docker exec "$CONTAINER" pg_isready -U tollgate >/dev/null 2>&1 && break
    sleep 0.5
done

DATABASE_URL="postgres://tollgate:tollgate@127.0.0.1:$DB_PORT/tollgate" \
RATE_LIMITER=none AUTO_MIGRATE=true ADMIN_TOKEN="$TOKEN" \
LISTEN_ADDR="127.0.0.1:$PORT" ADMIN_ADDR="127.0.0.1:$ADMIN_PORT" \
ACCESS_LOG=false LOG_LEVEL=error \
go run "$ROOT/cmd/gateway" >"$TMP/server.log" 2>&1 &
SERVER=$!

ready=false
for _ in $(seq 1 120); do
    if curl -sf "http://127.0.0.1:$PORT/_admin/" >/dev/null 2>&1; then
        ready=true
        break
    fi
    if ! kill -0 "$SERVER" 2>/dev/null; then
        cat "$TMP/server.log" >&2
        exit 1
    fi
    sleep 0.25
done
if [[ "$ready" != true ]]; then
    cat "$TMP/server.log" >&2
    exit 1
fi

run_schemathesis() {
    local phases="$1"
    local examples="$2"
    shift 2
    uvx schemathesis@4.25.2 run "$ROOT/internal/admin/openapi.json" \
        --url "http://127.0.0.1:$PORT/_admin" \
        --header "Authorization: Bearer $TOKEN" \
        --checks all \
        --phases "$phases" \
        --generation-database none \
        -n "$examples" \
        --seed "$SEED" \
        --continue-on-failure \
        "$@"
}

if [[ -n "${PHASES:-}" ]]; then
    run_schemathesis "$PHASES" "$EXAMPLES" "$@"
else
    # Keep the boundary corpus deep while bounding the much more expensive
    # state-machine search. At 300 stateful examples, the growing overview
    # payload makes a local run take tens of minutes without adding operations.
    run_schemathesis examples,coverage,fuzzing "$EXAMPLES" "$@"
    run_schemathesis stateful "$STATEFUL_EXAMPLES" "$@"
fi

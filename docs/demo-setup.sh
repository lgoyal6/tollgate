#!/usr/bin/env bash
# Stands up everything docs/demo.tape records against: the compose backing
# stores, a gateway holding a (fake) shared provider key, the bundled demo
# upstream, and an "alice" tenant capped at 3 requests per 60s.
#
# The point of the recording is that alice's own key never reaches the
# upstream and the shared credential is attached from the gateway's
# environment, so the "shared key" here is deliberately a fake string.
set -euo pipefail
cd "$(dirname "$0")/.."

export ADMIN_TOKEN="${ADMIN_TOKEN:-demo-admin-token-0123456789}"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-sk-ant-THE-TEAMS-SHARED-KEY}"

docker compose up -d postgres redis >/dev/null
for _ in $(seq 1 30); do
    docker compose exec -T postgres pg_isready -U tollgate >/dev/null 2>&1 && break
    sleep 1
done
for f in migrations/001_init.sql migrations/002_upstream_auth.sql; do
    docker compose exec -T postgres psql -q -U tollgate -d tollgate \
        -v ON_ERROR_STOP=1 -c "SET client_min_messages = warning" -f - <"$f" >/dev/null
done

go build -o /tmp/tg-gateway ./cmd/gateway
go build -o /tmp/tg-upstream ./cmd/upstream

pkill -f /tmp/tg-upstream >/dev/null 2>&1 || true
pkill -f /tmp/tg-gateway >/dev/null 2>&1 || true
BASE_DELAY_MS=4 JITTER_MS=3 /tmp/tg-upstream >/tmp/tg-upstream.log 2>&1 &
sleep 1
DATABASE_URL="postgres://tollgate:tollgate@localhost:5432/tollgate" \
REDIS_ADDR="localhost:6379" LISTEN_ADDR=":8080" ADMIN_ADDR=":9090" \
ACCESS_LOG=false LOG_LEVEL=error \
/tmp/tg-gateway >/tmp/tg-gateway.log 2>&1 &
sleep 3

api() { curl -s -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" "$@"; }
B="http://localhost:8080/_admin/api"

docker compose exec -T postgres psql -q -U tollgate -d tollgate \
    -c "DELETE FROM tenants WHERE id='alice';" >/dev/null
api -X POST "$B/tenants" -d '{"id":"alice","name":"Alice","algorithm":"sliding_window","limit":3,"window_ms":60000,"rate":1,"burst":3}' >/dev/null
api -X POST "$B/tenants/alice/routes" -d '{"path_prefix":"/anthropic/","upstream":"http://127.0.0.1:9000","strip_prefix":true,"auth_header":"X-Provider-Key","auth_env":"ANTHROPIC_API_KEY"}' >/dev/null

# Clear limiter state so the recording always starts from a full window.
docker compose exec -T redis redis-cli FLUSHALL >/dev/null

echo "ready: console at http://localhost:8080/_admin/ (token: $ADMIN_TOKEN)"
echo "now run: vhs docs/demo.tape"

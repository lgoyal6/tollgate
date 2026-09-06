#!/usr/bin/env bash
# Kills the relay for real, between the transaction that commits a usage window
# and the delivery that reports it, and counts what the consumer ended up with.
#
# Nothing here mocks a failure. Every "crash" below is syscall.Kill(getpid(),
# SIGKILL) inside the process under test, so no deferred function runs, no
# buffer flushes, and no connection is closed politely. What survives is only
# what Postgres had already committed.
#
# Needs two databases. scripts/outbox-crash.sh expects them to exist and to be
# migrated; see RECORD_c13_outbox.md for the two commands that make them.
set -uo pipefail

DB="${DATABASE_URL:?set DATABASE_URL to the gateway database}"
BILLING="${BILLING_URL:?set BILLING_URL to the consumer database}"
SINK_ADDR="${SINK_ADDR:-127.0.0.1:9411}"
SINK_URL="http://${SINK_ADDR}"
# Built here rather than assumed, so a run can never exercise a binary older
# than the source it is meant to be testing.
BIN="${BIN:-}"
PGC="${PGCONTAINER:-c13-pg-tollgate}"
PGUSER="${PGUSER:-tollgate}"

if [ -z "$BIN" ]; then
  BIN="$(mktemp -d)/tollgate-outbox"
  go build -o "$BIN" ./cmd/tollgate-outbox || exit 1
  echo "built $BIN  sha256 $(shasum -a 256 "$BIN" | cut -d' ' -f1)"
fi

pass=0; fail=0
sink_pid=""

q()  { docker exec "$PGC" psql -qtAX -U "$PGUSER" -d tollgate -c "$1"; }
qb() { docker exec "$PGC" psql -qtAX -U "$PGUSER" -d billing  -c "$1"; }

start_sink() { # $1 = dedupe true|false
  stop_sink
  $BIN sink -db "$BILLING" -addr "$SINK_ADDR" -dedupe="$1" >/tmp/c13-sink.log 2>&1 &
  sink_pid=$!
  for _ in $(seq 1 50); do
    curl -fsS -o /dev/null "${SINK_URL}/v1/charges/probe" 2>/dev/null && break
    curl -sS -o /dev/null -w '%{http_code}' "${SINK_URL}/v1/charges/probe" 2>/dev/null | grep -q 404 && break
    sleep 0.1
  done
}
stop_sink() { [ -n "$sink_pid" ] && kill "$sink_pid" 2>/dev/null; wait "$sink_pid" 2>/dev/null; sink_pid=""; }
trap stop_sink EXIT

reset() {
  q "TRUNCATE outbox, usage_ledger" >/dev/null
  qb "TRUNCATE billing_charges, inbox CASCADE" >/dev/null
}

# Runs a command, reports its exit status, and says plainly whether the kernel
# killed it. 137 is 128+SIGKILL and is what a real kill looks like from here.
run_and_report() {
  local label="$1"; shift
  "$@" >/tmp/c13-cmd.log 2>&1
  local rc=$?
  printf '    %-28s exit=%s%s\n' "$label" "$rc" \
    "$( [ $rc -eq 137 ] && echo '  (SIGKILL: 128+9)' )"
  sed 's/^/      | /' /tmp/c13-cmd.log
  return $rc
}

check() { # name expected actual
  if [ "$2" = "$3" ]; then printf '    PASS  %s: %s\n' "$1" "$3"; pass=$((pass+1));
  else printf '    FAIL  %s: expected %s, got %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}

charges() { qb "SELECT count(*) FROM billing_charges WHERE idempotency_key='$1'"; }
obstate() { q  "SELECT state FROM outbox WHERE idempotency_key='$1'"; }
obres()   { q  "SELECT coalesce(resolution,'-') FROM outbox WHERE idempotency_key='$1'"; }
obatt()   { q  "SELECT attempts FROM outbox WHERE idempotency_key='$1'"; }
deliv()   { qb "SELECT coalesce(max(deliveries)::text,'0') FROM inbox WHERE idempotency_key='$1'"; }

W() { date -u -r $((1750000000 + $1 * 60)) +%Y-%m-%dT%H:%M:%SZ; }

banner() { echo; echo "=================================================================="; echo "$1"; echo "=================================================================="; }

# ---------------------------------------------------------------- CONTROL 1 --
# No outbox. The ledger commits, then delivery is attempted separately. Killing
# the process between them is the bug the outbox exists to remove; if this does
# NOT lose the charge, the crash is not landing where it claims to.
banner "CONTROL 1  dual write, no outbox: SIGKILL between commit and delivery"
reset; start_sink true
KEY="usage:acme:$((1750000000 + 60))"
run_and_report "seal -mode=dual-write" $BIN seal -db "$DB" -tenant acme -window "$(W 1)" -requests 120 -mode dual-write -sink "$SINK_URL" -crash after_commit
check "ledger row committed" 1 "$(q "SELECT count(*) FROM usage_ledger WHERE tenant_id='acme'")"
check "outbox rows"          0 "$(q "SELECT count(*) FROM outbox")"
echo "    restarting: nothing recorded that a charge was owed, so there is nothing to relay"
run_and_report "relay (recovery attempt)" $BIN relay -db "$DB" -sink "$SINK_URL" -once
check "charges after recovery" 0 "$(charges "$KEY")"
echo "    -> the side effect is lost permanently. This is the control."

# ------------------------------------------------------------------ TEST 1 ---
banner "TEST 1  outbox: SIGKILL right after the sealing transaction commits"
reset
KEY="usage:acme:$((1750000000 + 120))"
run_and_report "seal -crash=after_commit" $BIN seal -db "$DB" -tenant acme -window "$(W 2)" -requests 200 -mode outbox -crash after_commit
check "ledger row committed"   1 "$(q "SELECT count(*) FROM usage_ledger WHERE window_start='$(W 2)'")"
check "outbox row committed"   1 "$(q "SELECT count(*) FROM outbox WHERE idempotency_key='$KEY'")"
check "outbox state"     PENDING "$(obstate "$KEY")"
check "charges before relay"   0 "$(charges "$KEY")"
run_and_report "relay (restart)" $BIN relay -db "$DB" -sink "$SINK_URL" -once
check "outbox state"   DELIVERED "$(obstate "$KEY")"
check "charges"                1 "$(charges "$KEY")"

# ------------------------------------------------------------------ TEST 2 ---
# The relay recorded that attempt 1 began, then died before the request left.
# From the gateway database alone this is indistinguishable from TEST 3.
banner "TEST 2  SIGKILL after the attempt is recorded, before the request is sent"
KEY="usage:acme:$((1750000000 + 180))"
run_and_report "seal" $BIN seal -db "$DB" -tenant acme -window "$(W 3)" -requests 300
run_and_report "relay -crash=before_send" $BIN relay -db "$DB" -sink "$SINK_URL" -once -lease 1ms -crash before_send
check "outbox state"    INFLIGHT "$(obstate "$KEY")"
check "attempts recorded"      1 "$(obatt "$KEY")"
check "charges"                0 "$(charges "$KEY")"
echo "    the row says attempt 1 began and nothing else. That is all that is true."
run_and_report "reconcile (lease=0)" $BIN reconcile -db "$DB" -sink "$SINK_URL" -lease 0s
check "outbox state after reconcile" PENDING "$(obstate "$KEY")"
check "resolution" absent_at_consumer_after_crash "$(obres "$KEY")"
run_and_report "relay (redeliver)" $BIN relay -db "$DB" -sink "$SINK_URL" -once
check "outbox state"   DELIVERED "$(obstate "$KEY")"
check "charges"                1 "$(charges "$KEY")"

# ------------------------------------------------------------------ TEST 3 ---
# The genuinely ambiguous one: the consumer has the effect, the producer does
# not know it. Same INFLIGHT row as TEST 2, opposite truth.
banner "TEST 3  SIGKILL after the consumer applied, before the producer recorded it"
KEY="usage:acme:$((1750000000 + 240))"
run_and_report "seal" $BIN seal -db "$DB" -tenant acme -window "$(W 4)" -requests 400
run_and_report "relay -crash=after_send" $BIN relay -db "$DB" -sink "$SINK_URL" -once -lease 1ms -crash after_send
check "outbox state"    INFLIGHT "$(obstate "$KEY")"
check "charges (consumer already has it)" 1 "$(charges "$KEY")"
echo "    the producer's row is byte-for-byte the TEST 2 shape, and the truth is the opposite."
run_and_report "reconcile (lease=0)" $BIN reconcile -db "$DB" -sink "$SINK_URL" -lease 0s
check "outbox state"   DELIVERED "$(obstate "$KEY")"
check "resolution" confirmed_by_consumer_after_crash "$(obres "$KEY")"
check "charges (still one)"    1 "$(charges "$KEY")"

# ------------------------------------------------------------------ TEST 4 ---
banner "TEST 4  replay: force every delivered row back to PENDING and rerun the relay"
before=$(qb "SELECT count(*) FROM billing_charges")
q "UPDATE outbox SET state='PENDING', next_attempt_at=now(), receipt=NULL, delivered_at=NULL WHERE state='DELIVERED'" >/dev/null
run_and_report "relay pass 1" $BIN relay -db "$DB" -sink "$SINK_URL" -once
q "UPDATE outbox SET state='PENDING', next_attempt_at=now(), receipt=NULL, delivered_at=NULL WHERE state='DELIVERED'" >/dev/null
run_and_report "relay pass 2" $BIN relay -db "$DB" -sink "$SINK_URL" -once
q "UPDATE outbox SET state='PENDING', next_attempt_at=now(), receipt=NULL, delivered_at=NULL WHERE state='DELIVERED'" >/dev/null
run_and_report "relay pass 3" $BIN relay -db "$DB" -sink "$SINK_URL" -once
after=$(qb "SELECT count(*) FROM billing_charges")
check "charges unchanged by 3 replays" "$before" "$after"
check "deliveries counted at the consumer (at-least-once is real)" 4 "$(deliv "$KEY")"

# ---------------------------------------------------------------- CONTROL 2 --
# Turn the inbox off and replay the same messages. If the count does not double,
# the dedupe being measured is coming from somewhere other than the inbox.
banner "CONTROL 2  inbox off: the same replay duplicates every charge"
start_sink false
before=$(qb "SELECT count(*) FROM billing_charges")
q "UPDATE outbox SET state='PENDING', next_attempt_at=now(), receipt=NULL, delivered_at=NULL WHERE state='DELIVERED'" >/dev/null
run_and_report "relay (dedupe=off)" $BIN relay -db "$DB" -sink "$SINK_URL" -once
after=$(qb "SELECT count(*) FROM billing_charges")
check "charges doubled" "$((before * 2))" "$after"
echo "    -> the inbox, not the schema and not the relay, is what makes the effect land once."
start_sink true

# ---------------------------------------------------------------- CONTROL 3 --
# A downstream that cannot be asked. Reconciliation must leave the row alone.
banner "CONTROL 3  a consumer with no lookup: the row stays UNKNOWN, unresolved"
reset
KEY="usage:acme:$((1750000000 + 300))"
run_and_report "seal" $BIN seal -db "$DB" -tenant acme -window "$(W 5)" -requests 500
run_and_report "relay -crash=before_send" $BIN relay -db "$DB" -sink "$SINK_URL" -once -lease 1ms -crash before_send
run_and_report "reconcile -no-lookup" $BIN reconcile -db "$DB" -sink "$SINK_URL" -lease 0s -no-lookup
check "state stays UNKNOWN" UNKNOWN "$(obstate "$KEY")"
check "charges still zero"        0 "$(charges "$KEY")"
echo "    last_error: $(q "SELECT last_error FROM outbox WHERE idempotency_key='$KEY'")"
echo "    -> nothing was guessed in either direction."

# ---------------------------------------------------------------- CONTROL 4 --
# What the two silent resolutions actually cost, shown rather than argued.
banner "CONTROL 4  the two ways of guessing, and what each one costs"
echo "  (a) assume delivered: mark the UNKNOWN row DELIVERED without asking"
q "UPDATE outbox SET state='DELIVERED', receipt='assumed', resolution='ASSUMED_DELIVERED' WHERE idempotency_key='$KEY'" >/dev/null
check "outbox says delivered" DELIVERED "$(obstate "$KEY")"
check "charges the consumer actually holds" 0 "$(charges "$KEY")"
echo "      -> a charge the ledger says was billed and nobody was billed for. Silent loss."
echo "  (b) assume not delivered, with the inbox off: redeliver TEST 3's key"
start_sink false
K3="usage:acme:$((1750000000 + 240))"
qb "TRUNCATE billing_charges, inbox CASCADE" >/dev/null
q "TRUNCATE outbox, usage_ledger" >/dev/null
run_and_report "seal" $BIN seal -db "$DB" -tenant acme -window "$(W 4)" -requests 400
run_and_report "relay -crash=after_send" $BIN relay -db "$DB" -sink "$SINK_URL" -once -lease 1ms -crash after_send
c1=$(charges "$K3")
q "UPDATE outbox SET state='PENDING', next_attempt_at=now() WHERE idempotency_key='$K3'" >/dev/null
run_and_report "relay (assumed not delivered)" $BIN relay -db "$DB" -sink "$SINK_URL" -once
check "charges after guessing wrong" 2 "$(charges "$K3")"
echo "      -> the tenant is billed twice. Silent duplication."
start_sink true

banner "RESULT  pass=$pass fail=$fail"
[ "$fail" -eq 0 ]

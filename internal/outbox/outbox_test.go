package outbox_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lgoyal6/tollgate/internal/outbox"
	"github.com/lgoyal6/tollgate/migrations"
)

// These need two real databases, because "the effect and the inbox row commit
// together" is a claim about a transaction and there is nothing to test without
// one. The crash half of C13 is scripts/outbox-crash.sh, which kills real
// processes; a test binary cannot SIGKILL itself and keep asserting.
//
//	TOLLGATE_TEST_POSTGRES=postgres://.../tollgate \
//	TOLLGATE_TEST_BILLING=postgres://.../billing  go test ./internal/outbox/
func dbs(t *testing.T) (producer, consumer *pgxpool.Pool) {
	t.Helper()
	pURL, cURL := os.Getenv("TOLLGATE_TEST_POSTGRES"), os.Getenv("TOLLGATE_TEST_BILLING")
	if pURL == "" || cURL == "" {
		t.Skip("set TOLLGATE_TEST_POSTGRES and TOLLGATE_TEST_BILLING")
	}
	ctx := context.Background()
	open := func(url string) *pgxpool.Pool {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			t.Fatalf("connecting to %s: %v", url, err)
		}
		if err := pool.Ping(ctx); err != nil {
			t.Fatalf("pinging %s: %v", url, err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	producer, consumer = open(pURL), open(cURL)
	body, err := migrations.FS.ReadFile("004_outbox.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.Exec(ctx, string(body)); err != nil {
		t.Fatalf("applying 004_outbox.sql: %v", err)
	}
	if err := outbox.MigrateSink(ctx, consumer); err != nil {
		t.Fatal(err)
	}
	if _, err := producer.Exec(ctx, `TRUNCATE outbox, usage_ledger`); err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Exec(ctx, `TRUNCATE billing_charges, inbox CASCADE`); err != nil {
		t.Fatal(err)
	}
	return producer, consumer
}

func window(n int) outbox.Window {
	start := time.Unix(1_700_000_000, 0).UTC().Add(time.Duration(n) * time.Minute)
	return outbox.Window{
		TenantID: "acme", WindowStart: start, WindowEnd: start.Add(time.Minute),
		Requests: int64(100 * n), Admitted: int64(100 * n), Limited: 0,
	}
}

func charges(t *testing.T, consumer *pgxpool.Pool, key string) int {
	t.Helper()
	var n int
	if err := consumer.QueryRow(context.Background(),
		`SELECT count(*) FROM billing_charges WHERE idempotency_key = $1`, key).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func state(t *testing.T, producer *pgxpool.Pool, key string) (string, string) {
	t.Helper()
	var s, res string
	if err := producer.QueryRow(context.Background(),
		`SELECT state, coalesce(resolution, '') FROM outbox WHERE idempotency_key = $1`, key).Scan(&s, &res); err != nil {
		t.Fatal(err)
	}
	return s, res
}

func harness(t *testing.T) (context.Context, *pgxpool.Pool, *pgxpool.Pool, *outbox.Relay, *httptest.Server) {
	t.Helper()
	ctx := context.Background()
	producer, consumer := dbs(t)
	sink := &outbox.BillingSink{Pool: consumer, Dedupe: true}
	srv := httptest.NewServer(sink.Handler())
	t.Cleanup(srv.Close)
	relay := &outbox.Relay{
		Pool: producer, Sink: outbox.HTTPSink{BaseURL: srv.URL}, Owner: t.Name(),
		Lease: time.Minute, Batch: 16, Backoff: func(int) time.Duration { return 0 },
	}
	return ctx, producer, consumer, relay, srv
}

// The ledger row and the message that reports it are one write. Rolling the
// transaction back must leave neither behind.
func TestSealIsAtomic(t *testing.T) {
	ctx, producer, _, _, _ := harness(t)
	w := window(1)

	tx, err := producer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO usage_ledger (tenant_id, window_start, window_end, requests)
		VALUES ($1,$2,$3,$4)`, w.TenantID, w.WindowStart, w.WindowEnd, w.Requests); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Enqueue(ctx, tx, outbox.UsageKey(w.TenantID, w.WindowStart), outbox.TopicUsageSealed, outbox.UsageEvent{TenantID: w.TenantID}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	var ledger, msgs int
	if err := producer.QueryRow(ctx, `SELECT count(*) FROM usage_ledger`).Scan(&ledger); err != nil {
		t.Fatal(err)
	}
	if err := producer.QueryRow(ctx, `SELECT count(*) FROM outbox`).Scan(&msgs); err != nil {
		t.Fatal(err)
	}
	if ledger != 0 || msgs != 0 {
		t.Fatalf("rollback left %d ledger rows and %d messages; both must be 0", ledger, msgs)
	}
}

// Replay is the property the crash tests depend on: however many times the same
// message is delivered, the consumer charges once.
func TestReplayDoesNotDuplicateTheEffect(t *testing.T) {
	ctx, producer, consumer, relay, _ := harness(t)
	w := window(2)
	key := outbox.UsageKey(w.TenantID, w.WindowStart)
	if _, err := outbox.SealWindows(ctx, producer, []outbox.Window{w}, nil); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err := relay.Once(ctx); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		if _, err := producer.Exec(ctx, `
			UPDATE outbox SET state='PENDING', next_attempt_at=now(), receipt=NULL, delivered_at=NULL
			 WHERE idempotency_key=$1 AND state='DELIVERED'`, key); err != nil {
			t.Fatal(err)
		}
	}
	if got := charges(t, consumer, key); got != 1 {
		t.Fatalf("5 deliveries produced %d charges, want 1", got)
	}
	var deliveries int
	if err := consumer.QueryRow(ctx, `SELECT deliveries FROM inbox WHERE idempotency_key=$1`, key).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	// If this were 1 the test would be passing because nothing was redelivered,
	// not because the inbox suppressed anything.
	if deliveries != 5 {
		t.Fatalf("the consumer saw %d deliveries; the replay did not actually happen", deliveries)
	}
}

// Sealing the same window again must not queue a second charge, whatever the
// caller believes about the first attempt.
func TestResealIsIdempotent(t *testing.T) {
	ctx, producer, consumer, relay, _ := harness(t)
	w := window(3)
	key := outbox.UsageKey(w.TenantID, w.WindowStart)
	for range 3 {
		if _, err := outbox.SealWindows(ctx, producer, []outbox.Window{w}, nil); err != nil {
			t.Fatal(err)
		}
	}
	var msgs int
	if err := producer.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE idempotency_key=$1`, key).Scan(&msgs); err != nil {
		t.Fatal(err)
	}
	if msgs != 1 {
		t.Fatalf("3 seals produced %d messages, want 1", msgs)
	}
	if _, err := relay.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if got := charges(t, consumer, key); got != 1 {
		t.Fatalf("charges = %d, want 1", got)
	}
}

// An attempt whose process vanished becomes UNKNOWN and stays there until
// something asks the consumer. It must never be silently resolved either way.
func TestExpiredLeaseBecomesUnknownNotPending(t *testing.T) {
	ctx, producer, _, relay, _ := harness(t)
	w := window(4)
	key := outbox.UsageKey(w.TenantID, w.WindowStart)
	if _, err := outbox.SealWindows(ctx, producer, []outbox.Window{w}, nil); err != nil {
		t.Fatal(err)
	}
	// Stand in for the claim a killed relay committed before it died.
	if _, err := producer.Exec(ctx, `
		UPDATE outbox SET state='INFLIGHT', attempts=1, lease_owner='ghost',
		       lease_expires_at = now() - interval '1 second' WHERE idempotency_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	n, err := relay.ExpireLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expired %d leases, want 1", n)
	}
	if s, _ := state(t, producer, key); s != outbox.StateUnknown {
		t.Fatalf("state = %s, want UNKNOWN; PENDING would be asserting the consumer did not get it", s)
	}
}

// The two ambiguous crashes leave identical rows in the producer's database.
// Only the consumer can tell them apart, and reconcile must reach the opposite
// conclusion in each case.
func TestReconcileSettlesBothDirections(t *testing.T) {
	ctx, producer, consumer, relay, _ := harness(t)

	// (a) the consumer never got it.
	wa := window(5)
	ka := outbox.UsageKey(wa.TenantID, wa.WindowStart)
	// (b) the consumer got it and the acknowledgement was lost.
	wb := window(6)
	kb := outbox.UsageKey(wb.TenantID, wb.WindowStart)
	if _, err := outbox.SealWindows(ctx, producer, []outbox.Window{wa, wb}, nil); err != nil {
		t.Fatal(err)
	}
	sink := &outbox.BillingSink{Pool: consumer, Dedupe: true}
	payload, _ := json.Marshal(outbox.UsageEvent{TenantID: wb.TenantID, WindowStart: wb.WindowStart, WindowEnd: wb.WindowEnd, Requests: wb.Requests})
	if _, err := sink.Apply(ctx, kb, outbox.TopicUsageSealed, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := producer.Exec(ctx, `
		UPDATE outbox SET state='UNKNOWN', attempts=1 WHERE idempotency_key = ANY($1)`,
		[]string{ka, kb}); err != nil {
		t.Fatal(err)
	}

	res, err := relay.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Examined != 2 || res.Absent != 1 || res.Confirmed != 1 || res.Unresolved != 0 {
		t.Fatalf("reconcile = %+v, want 2 examined / 1 absent / 1 confirmed / 0 unresolved", res)
	}
	if s, r := state(t, producer, ka); s != outbox.StatePending || r != "absent_at_consumer_after_crash" {
		t.Fatalf("never-received message settled as %s/%s", s, r)
	}
	if s, r := state(t, producer, kb); s != outbox.StateDelivered || r != "confirmed_by_consumer_after_crash" {
		t.Fatalf("already-applied message settled as %s/%s", s, r)
	}

	if _, err := relay.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if got := charges(t, consumer, ka); got != 1 {
		t.Fatalf("charges for the redelivered message = %d, want 1", got)
	}
	if got := charges(t, consumer, kb); got != 1 {
		t.Fatalf("charges for the confirmed message = %d, want 1", got)
	}
}

// A downstream that cannot answer leaves the row unresolved. Reconciliation is
// allowed to fail; it is not allowed to guess.
func TestReconcileLeavesUnknownWhenTheSinkCannotAnswer(t *testing.T) {
	ctx, producer, _, relay, srv := harness(t)
	w := window(7)
	key := outbox.UsageKey(w.TenantID, w.WindowStart)
	if _, err := outbox.SealWindows(ctx, producer, []outbox.Window{w}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := producer.Exec(ctx, `
		UPDATE outbox SET state='UNKNOWN', attempts=1 WHERE idempotency_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	relay.Sink = outbox.HTTPSink{BaseURL: srv.URL, LookupDisabled: true}

	res, err := relay.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Unresolved != 1 || res.Confirmed != 0 || res.Absent != 0 {
		t.Fatalf("reconcile = %+v, want 1 unresolved and nothing settled", res)
	}
	if s, _ := state(t, producer, key); s != outbox.StateUnknown {
		t.Fatalf("state = %s, want UNKNOWN", s)
	}
	var lastErr string
	if err := producer.QueryRow(ctx, `SELECT coalesce(last_error,'') FROM outbox WHERE idempotency_key=$1`, key).Scan(&lastErr); err != nil {
		t.Fatal(err)
	}
	if lastErr == "" {
		t.Fatal("an unresolved row must say why")
	}
}

// The key is a function of the state change. If it ever becomes a function of
// the attempt, every retry looks like a new charge and the whole mechanism is
// decorative.
func TestIdempotencyKeyIsStableAcrossAttempts(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	first := outbox.UsageKey("acme", start)
	second := outbox.UsageKey("acme", start.In(time.FixedZone("elsewhere", 3600)))
	if first != second {
		t.Fatalf("the same window produced two keys: %q and %q", first, second)
	}
	if outbox.UsageKey("acme", start) == outbox.UsageKey("acme", start.Add(time.Minute)) {
		t.Fatal("two different windows produced the same key")
	}
}

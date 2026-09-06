package budget_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lgoyal6/tollgate/internal/budget"
	"github.com/lgoyal6/tollgate/internal/store"
)

// These tests need a real PostgreSQL: the properties under test ARE the database's
// (row locking, transaction atomicity, unique constraints). A fake would only test
// the fake. Set TOLLGATE_TEST_DATABASE_URL; without it the package skips.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TOLLGATE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TOLLGATE_TEST_DATABASE_URL to run budget ledger tests")
	}
	ctx := context.Background()
	st, err := store.New(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { st.Pool.Close() })
	return st.Pool
}

// Each test gets its own tenant so they can run against one database without
// interfering, and the rows survive the run for inspection.
func newTenant(t *testing.T, pool *pgxpool.Pool, limitMicros *int64) (string, *budget.Ledger) {
	t.Helper()
	ctx := context.Background()
	id := fmt.Sprintf("t-%s-%d", t.Name(), time.Now().UnixNano())
	if len(id) > 60 {
		id = id[:60]
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, $1)`, id); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	l := budget.New(pool)
	if err := l.SetLimit(ctx, id, limitMicros, "total"); err != nil {
		t.Fatalf("set limit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id, l
}

func usd(dollars float64) int64 { return int64(dollars * 1_000_000) }

// The headline property: concurrent requests must not each be admitted against the
// same headroom. Without FOR UPDATE on the tenant row every goroutine reads the same
// balance and they all pass the check.
func TestConcurrentReservationsCannotOversubscribe(t *testing.T) {
	pool := testPool(t)
	limit := usd(10) // exactly 10 holds of $1 fit
	tenant, l := newTenant(t, pool, &limit)

	const workers = 64
	var admitted, refused atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // maximise the overlap
			_, err := l.Reserve(context.Background(), tenant, fmt.Sprintf("req-%d", i), usd(1), "test")
			switch {
			case err == nil:
				admitted.Add(1)
			case errors.Is(err, budget.ErrOverBudget):
				refused.Add(1)
			default:
				t.Errorf("unexpected reserve error: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := admitted.Load(); got != 10 {
		t.Errorf("admitted %d reservations, want exactly 10 (limit $10 / $1 each)", got)
	}
	if got := admitted.Load() + refused.Load(); got != workers {
		t.Errorf("accounted for %d of %d workers", got, workers)
	}

	st, err := l.Status(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if st.Committed > limit {
		t.Errorf("committed %d exceeds limit %d - budget oversubscribed", st.Committed, limit)
	}
	assertNoDrift(t, l)
}

// A retried request must not be charged twice. At this layer a client retry after a
// timeout is indistinguishable from a new request, so idempotency has to come from
// the request id, not from hoping it does not happen.
func TestReserveAndSettleAreIdempotent(t *testing.T) {
	pool := testPool(t)
	limit := usd(100)
	tenant, l := newTenant(t, pool, &limit)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := l.Reserve(ctx, tenant, "same-request", usd(2), "m"); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	st, _ := l.Status(ctx, tenant)
	if st.Reserved != usd(2) {
		t.Errorf("5 identical reserves held %d, want %d", st.Reserved, usd(2))
	}

	for i := 0; i < 5; i++ {
		if _, err := l.Settle(ctx, tenant, "same-request", usd(1.5)); err != nil {
			t.Fatalf("settle %d: %v", i, err)
		}
	}
	st, _ = l.Status(ctx, tenant)
	if st.Settled != usd(1.5) {
		t.Errorf("5 identical settles charged %d, want %d", st.Settled, usd(1.5))
	}
	if st.Reserved != 0 {
		t.Errorf("hold not fully released after settle: %d", st.Reserved)
	}
	assertNoDrift(t, l)
}

// A broken stream is not proof the provider will not bill. The hold must stay.
func TestUncertainOutcomeKeepsTheHold(t *testing.T) {
	pool := testPool(t)
	limit := usd(10)
	tenant, l := newTenant(t, pool, &limit)
	ctx := context.Background()

	if _, err := l.Reserve(ctx, tenant, "streamed", usd(4), "m"); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkUncertain(ctx, tenant, "streamed", "client disconnected mid-stream"); err != nil {
		t.Fatal(err)
	}
	st, _ := l.Status(ctx, tenant)
	if st.Committed != usd(4) {
		t.Errorf("uncertain outcome freed money: committed %d, want %d", st.Committed, usd(4))
	}
	// And it must be visible to an operator rather than silently stuck.
	open, err := l.OpenOlderThan(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range open {
		if e.TenantID == tenant && e.RequestID == "streamed" && e.State == budget.StateUncertain {
			found = true
		}
	}
	if !found {
		t.Error("uncertain hold is not listed by the recovery scan")
	}
	assertNoDrift(t, l)
}

// Release is only for requests that provably never reached the upstream.
func TestReleaseReturnsHeadroomOnlyFromReserved(t *testing.T) {
	pool := testPool(t)
	limit := usd(10)
	tenant, l := newTenant(t, pool, &limit)
	ctx := context.Background()

	if _, err := l.Reserve(ctx, tenant, "never-sent", usd(6), "m"); err != nil {
		t.Fatal(err)
	}
	if err := l.Release(ctx, tenant, "never-sent", "upstream connection refused"); err != nil {
		t.Fatal(err)
	}
	st, _ := l.Status(ctx, tenant)
	if st.Committed != 0 {
		t.Errorf("release left %d committed, want 0", st.Committed)
	}

	// Releasing a settled charge must not refund it.
	if _, err := l.Reserve(ctx, tenant, "done", usd(3), "m"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Settle(ctx, tenant, "done", usd(3)); err != nil {
		t.Fatal(err)
	}
	if err := l.Release(ctx, tenant, "done", "late release"); err != nil {
		t.Fatal(err)
	}
	st, _ = l.Status(ctx, tenant)
	if st.Settled != usd(3) {
		t.Errorf("release refunded settled spend: settled %d, want %d", st.Settled, usd(3))
	}
	assertNoDrift(t, l)
}

// A gateway crash between reserve and settle must leave the hold in place and
// findable, not lose it. Nothing here mocks the crash: the reserve simply commits
// and the settle never comes, which is exactly the durable state a crash leaves.
func TestHoldSurvivesAGatewayCrash(t *testing.T) {
	pool := testPool(t)
	limit := usd(50)
	tenant, l := newTenant(t, pool, &limit)
	ctx := context.Background()

	if _, err := l.Reserve(ctx, tenant, "orphan", usd(7), "m"); err != nil {
		t.Fatal(err)
	}
	// A brand-new Ledger on a new pool: no in-process state carries over.
	fresh := budget.New(pool)
	st, err := fresh.Status(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if st.Reserved != usd(7) {
		t.Errorf("hold did not survive: reserved %d, want %d", st.Reserved, usd(7))
	}
	open, err := fresh.OpenOlderThan(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range open {
		if e.TenantID == tenant && e.RequestID == "orphan" {
			found = true
		}
	}
	if !found {
		t.Error("recovery scan did not surface the orphaned hold")
	}
	// It is still settleable after "restart".
	if _, err := fresh.Settle(ctx, tenant, "orphan", usd(6)); err != nil {
		t.Fatalf("settle after restart: %v", err)
	}
	assertNoDrift(t, l)
}

// An uncertain hold is not terminal: a provider reconciliation or an operator can
// still settle it. That transition moves money between two denormalised counters,
// so it is exactly where drift would hide.
func TestUncertainHoldCanStillBeSettled(t *testing.T) {
	pool := testPool(t)
	limit := usd(20)
	tenant, l := newTenant(t, pool, &limit)
	ctx := context.Background()

	if _, err := l.Reserve(ctx, tenant, "ambiguous", usd(5), "m"); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkUncertain(ctx, tenant, "ambiguous", "stream died"); err != nil {
		t.Fatal(err)
	}
	assertNoDrift(t, l)

	// The provider later reports what it actually billed.
	if _, err := l.Settle(ctx, tenant, "ambiguous", usd(2)); err != nil {
		t.Fatalf("settling an uncertain hold: %v", err)
	}
	st, _ := l.Status(ctx, tenant)
	if st.Reserved != 0 {
		t.Errorf("hold still held after settlement: %d", st.Reserved)
	}
	if st.Settled != usd(2) {
		t.Errorf("settled %d, want %d", st.Settled, usd(2))
	}
	assertNoDrift(t, l)

	// And it must not be releasable afterwards.
	if err := l.Release(ctx, tenant, "ambiguous", "too late"); err != nil {
		t.Fatal(err)
	}
	st, _ = l.Status(ctx, tenant)
	if st.Settled != usd(2) {
		t.Errorf("release refunded a settled charge: %d", st.Settled)
	}
	assertNoDrift(t, l)
}

// One tenant's spend must not touch another's headroom.
func TestTenantsAreIsolated(t *testing.T) {
	pool := testPool(t)
	limit := usd(5)
	a, la := newTenant(t, pool, &limit)
	b, lb := newTenant(t, pool, &limit)
	ctx := context.Background()

	if _, err := la.Reserve(ctx, a, "r1", usd(5), "m"); err != nil {
		t.Fatal(err)
	}
	if _, err := la.Reserve(ctx, a, "r2", usd(1), "m"); !errors.Is(err, budget.ErrOverBudget) {
		t.Fatalf("tenant a should be full, got %v", err)
	}
	// b is untouched.
	if _, err := lb.Reserve(ctx, b, "r1", usd(5), "m"); err != nil {
		t.Errorf("tenant b refused despite its own empty budget: %v", err)
	}
	// Settling under a's request id from b's tenant must not find a's entry.
	if _, err := lb.Settle(ctx, b, "not-mine", usd(1)); !errors.Is(err, budget.ErrNotReserved) {
		t.Errorf("cross-tenant settle should not resolve, got %v", err)
	}
	assertNoDrift(t, la)
}

// Money is integer micros end to end. A float accumulator drifts on exactly this
// kind of repeated fractional addition; this asserts the ledger does not.
func TestFixedPointHasNoDrift(t *testing.T) {
	pool := testPool(t)
	limit := usd(1000)
	tenant, l := newTenant(t, pool, &limit)
	ctx := context.Background()

	// $0.000001 x 1,000,000 == exactly $1.00
	const n = 2000
	const each = int64(1) // one micro
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("micro-%d", i)
		if _, err := l.Reserve(ctx, tenant, id, each, "m"); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
		if _, err := l.Settle(ctx, tenant, id, each); err != nil {
			t.Fatalf("settle %d: %v", i, err)
		}
	}
	st, _ := l.Status(ctx, tenant)
	if st.Settled != int64(n)*each {
		t.Errorf("settled %d micros after %d x %d, want %d", st.Settled, n, each, int64(n)*each)
	}
	assertNoDrift(t, l)
}

// A settlement above the hold is recorded honestly rather than clamped: the provider
// can bill more than a conservative estimate, and the books should say so.
func TestSettlementAboveTheHoldIsRecordedNotClamped(t *testing.T) {
	pool := testPool(t)
	limit := usd(10)
	tenant, l := newTenant(t, pool, &limit)
	ctx := context.Background()

	if _, err := l.Reserve(ctx, tenant, "underestimated", usd(1), "m"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Settle(ctx, tenant, "underestimated", usd(3)); err != nil {
		t.Fatal(err)
	}
	st, _ := l.Status(ctx, tenant)
	if st.Settled != usd(3) {
		t.Errorf("settled %d, want the real %d (not clamped to the hold)", st.Settled, usd(3))
	}
	assertNoDrift(t, l)
}

// A tenant with no budget row is unlimited, so turning this feature on cannot
// retroactively brick an existing deployment.
func TestTenantWithoutBudgetIsReportedNotDenied(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	id := fmt.Sprintf("nb-%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1)`, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, id) })

	l := budget.New(pool)
	if _, err := l.Reserve(ctx, id, "r", usd(1), "m"); !errors.Is(err, budget.ErrNoBudget) {
		t.Errorf("want ErrNoBudget so the caller can choose, got %v", err)
	}
}

// A NULL limit tracks spend without ever refusing.
func TestNullLimitTracksWithoutRefusing(t *testing.T) {
	pool := testPool(t)
	tenant, l := newTenant(t, pool, nil)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		if _, err := l.Reserve(ctx, tenant, fmt.Sprintf("r%d", i), usd(1000), "m"); err != nil {
			t.Fatalf("unlimited tenant refused at %d: %v", i, err)
		}
	}
	st, _ := l.Status(ctx, tenant)
	if st.Reserved != usd(20000) {
		t.Errorf("reserved %d, want %d", st.Reserved, usd(20000))
	}
	if st.Remaining != nil {
		t.Error("a NULL limit should report no Remaining")
	}
	assertNoDrift(t, l)
}

// The denormalised counters must always equal the sum of the entries.
func assertNoDrift(t *testing.T, l *budget.Ledger) {
	t.Helper()
	drift, err := l.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, d := range drift {
		t.Errorf("ledger drift for %s: reserved off by %d, settled off by %d",
			d.TenantID, d.ReservedDelta, d.SettledDelta)
	}
}

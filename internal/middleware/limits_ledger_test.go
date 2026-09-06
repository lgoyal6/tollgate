package middleware

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lgoyal6/tollgate/internal/budget"
	"github.com/lgoyal6/tollgate/internal/store"
)

// The invariant this file exists for spans two packages that never call each
// other: a request refused by an abuse limit must leave nothing behind in the
// spend ledger. A fake ledger can show the middleware did not CALL Reserve; it
// cannot show that no row survived, and a leaked hold is money a tenant cannot
// spend until an operator finds it.
//
// Needs a real PostgreSQL, same as internal/budget: set
// TOLLGATE_TEST_DATABASE_URL or the package skips.
func ledgerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TOLLGATE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TOLLGATE_TEST_DATABASE_URL to run the ledger interaction tests")
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

func ledgerTenant(t *testing.T, pool *pgxpool.Pool) (string, *budget.Ledger) {
	t.Helper()
	ctx := context.Background()
	id := fmt.Sprintf("lim-%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, id); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	l := budget.New(pool)
	limit := int64(100_000_000) // $100, far more than any request here costs
	if err := l.SetLimit(ctx, id, &limit, "total"); err != nil {
		t.Fatalf("set limit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id, l
}

func openHolds(t *testing.T, pool *pgxpool.Pool, tenant string) (rows int, reserved int64) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM spend_entries WHERE tenant_id = $1`, tenant).Scan(&rows); err != nil {
		t.Fatalf("count entries: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT reserved_micros FROM tenant_budgets WHERE tenant_id = $1`, tenant).Scan(&reserved); err != nil {
		t.Fatalf("read reserved: %v", err)
	}
	return rows, reserved
}

func TestSizeRefusalLeavesNoSpendHold(t *testing.T) {
	pool := ledgerPool(t)
	tenant, ledger := ledgerTenant(t, pool)

	up := &countingUpstream{}
	h := newHarness(t, up.handler(), ledger, testLimits(), nil, tenant)

	// Control: a priceable request under the cap does take a hold and settle,
	// so a zero count below means the limit worked rather than that the ledger
	// was never wired up.
	size := 4096
	resp, err := h.post(chatBody(size), chatBodySize(size), nil)
	if err != nil {
		t.Fatalf("control post: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control status = %d, want 200", resp.StatusCode)
	}
	rows, reserved := openHolds(t, pool, tenant)
	if rows != 1 {
		t.Fatalf("control wrote %d ledger rows, want 1: the ledger is not on this path", rows)
	}
	if reserved != 0 {
		t.Errorf("control left %d micros reserved, want 0 after settlement", reserved)
	}

	// The actual invariant, across every way a request can be refused for size.
	oversize := 1 << 20
	gzipBomb := gzipBody(t, 8<<20)
	cases := []struct {
		name   string
		body   func() (io.Reader, int64, map[string]string)
		status int
	}{
		{"declared length over the cap", func() (io.Reader, int64, map[string]string) {
			return chatBody(oversize), chatBodySize(oversize), nil
		}, http.StatusRequestEntityTooLarge},
		{"chunked body over the cap", func() (io.Reader, int64, map[string]string) {
			return chatBody(oversize), -1, nil
		}, http.StatusRequestEntityTooLarge},
		{"gzip bomb", func() (io.Reader, int64, map[string]string) {
			return bytesReader(gzipBomb), int64(len(gzipBomb)), map[string]string{"Content-Encoding": "gzip"}
		}, http.StatusRequestEntityTooLarge},
		{"unsupported encoding", func() (io.Reader, int64, map[string]string) {
			return bytesReader([]byte("x")), 1, map[string]string{"Content-Encoding": "br"}
		}, http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, _ := openHolds(t, pool, tenant)
			body, length, hdr := tc.body()
			resp, err := h.post(body, length, hdr)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			after, reserved := openHolds(t, pool, tenant)
			if after != before {
				t.Errorf("ledger grew by %d rows on a refused request", after-before)
			}
			if reserved != 0 {
				t.Errorf("reserved_micros = %d after a refused request, want 0", reserved)
			}
		})
	}

	// And the ledger's own books still balance.
	drift, err := ledger.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, d := range drift {
		if d.TenantID == tenant {
			t.Errorf("drift after size refusals: reserved %+d settled %+d", d.ReservedDelta, d.SettledDelta)
		}
	}
}

// A request refused for CONCURRENCY must not leave a hold either: the gate is
// outside Budget for exactly this reason.
func TestConcurrencyRefusalLeavesNoSpendHold(t *testing.T) {
	pool := ledgerPool(t)
	tenant, ledger := ledgerTenant(t, pool)

	up := newBlockingUpstream(64)
	cfg := testLimits()
	h := newHarness(t, up.handler(), ledger, cfg, nil, tenant)

	type result struct{ status int }
	results := make(chan result, 16)
	for i := 0; i < 16; i++ {
		go func() {
			resp, err := h.post(chatBody(256), chatBodySize(256), nil)
			if err != nil {
				results <- result{-1}
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			results <- result{resp.StatusCode}
		}()
	}
	<-up.arrived
	time.Sleep(300 * time.Millisecond) // past QueueWait, so the queue refuses
	close(up.release)

	var refused int
	for i := 0; i < 16; i++ {
		if (<-results).status == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("no request was refused for concurrency; nothing to assert about")
	}

	rows, reserved := openHolds(t, pool, tenant)
	if rows > 16-refused {
		t.Errorf("%d ledger rows for %d admitted requests: a refused request took a hold", rows, 16-refused)
	}
	if reserved != 0 {
		t.Errorf("reserved_micros = %d, want 0 once every admitted request has settled", reserved)
	}
}

func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b []byte
	i int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.i >= len(s.b) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.i:])
	s.i += n
	return n, nil
}

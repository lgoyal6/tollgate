package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/proxy"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

// The route plan can make one request touch two upstreams. The ledger must not
// notice: a request is one hold and one settlement however many attempts it
// took, or a tenant whose primary provider is having a bad afternoon is billed
// twice for the same answer.

func planFixture(t *testing.T, primary, fallback string) *store.RoutePlan {
	t.Helper()
	p, err := url.Parse(primary)
	if err != nil {
		t.Fatalf("parsing %q: %v", primary, err)
	}
	f, err := url.Parse(fallback)
	if err != nil {
		t.Fatalf("parsing %q: %v", fallback, err)
	}
	return store.PlanFor(&store.Route{
		ID: 1, TenantID: "acme", PathPrefix: "/v1/",
		Upstream: p, Timeout: 2 * time.Second, RetryMax: 1,
		FallbackUpstream: f,
	})
}

func TestOneHoldAndOneSettlementSurviveASuccessfulFallback(t *testing.T) {
	const usage = `{"usage":{"input_tokens":1000,"output_tokens":2000}}`
	var fallbackHits atomic.Int64

	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(primaryServer.Close)
	fallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, usage)
	}))
	t.Cleanup(fallbackServer.Close)

	f := &fakeLedger{remaining: 100_000_000}
	fwd := proxy.New(proxy.Options{
		Breakers:       resilience.NewBreakerGroup(resilience.DefaultBreakerConfig()),
		MaxBodyBuffer:  1 << 20,
		MaxIdlePerHost: 4,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:        observability.NewMetrics(),
	})
	h := Budget(f, false, slog.Default())(fwd)

	// A GET with a priced body: idempotent and replayable, so it is the one
	// shape that both reaches failover and has a cost to settle.
	req := httptest.NewRequest(http.MethodGet, "/v1/messages", strings.NewReader(pricedReq))
	req.ContentLength = int64(len(pricedReq))
	req = withTenant(req)
	plan := planFixture(t, primaryServer.URL, fallbackServer.URL)
	ctx := reqctx.WithRoute(req.Context(), plan.Route)
	ctx = reqctx.WithPlan(ctx, plan)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the fallback; body %s", rec.Code, rec.Body)
	}
	if got := fallbackHits.Load(); got != 1 {
		t.Fatalf("fallback hits = %d, want exactly 1", got)
	}
	calls := f.seen()
	if len(calls) != 2 || calls[0] != "reserve" || calls[1] != "settle" {
		t.Fatalf("ledger calls = %v, want exactly [reserve settle]", calls)
	}
}

func TestAFailedFallbackStillClosesTheHoldExactlyOnce(t *testing.T) {
	// Both upstreams refuse. The hold still has to be closed out once, and as
	// the gateway's own refusal rather than as spend: nothing was consumed.
	refuse := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	primaryServer := httptest.NewServer(http.HandlerFunc(refuse))
	t.Cleanup(primaryServer.Close)
	fallbackServer := httptest.NewServer(http.HandlerFunc(refuse))
	t.Cleanup(fallbackServer.Close)

	f := &fakeLedger{remaining: 100_000_000}
	fwd := proxy.New(proxy.Options{
		Breakers:       resilience.NewBreakerGroup(resilience.DefaultBreakerConfig()),
		MaxBodyBuffer:  1 << 20,
		MaxIdlePerHost: 4,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:        observability.NewMetrics(),
	})
	h := Budget(f, false, slog.Default())(fwd)

	req := httptest.NewRequest(http.MethodGet, "/v1/messages", strings.NewReader(pricedReq))
	req.ContentLength = int64(len(pricedReq))
	req = withTenant(req)
	plan := planFixture(t, primaryServer.URL, fallbackServer.URL)
	ctx := reqctx.WithRoute(req.Context(), plan.Route)
	ctx = reqctx.WithPlan(ctx, plan)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))

	calls := f.seen()
	if len(calls) != 2 {
		t.Fatalf("ledger calls = %v, want exactly two (one hold, one close-out)", calls)
	}
	if calls[0] != "reserve" {
		t.Fatalf("ledger calls = %v, want the hold first", calls)
	}
	if calls[1] == "settle" {
		t.Errorf("ledger calls = %v: a request no upstream served was billed", calls)
	}
}

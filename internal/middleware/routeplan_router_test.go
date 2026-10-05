package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/store"
)

// The router is where the plan is decided. Two properties matter here: the
// order comes from the snapshot rather than from the request, and every
// candidate passes the upstream check - a fallback is the second place this
// gateway would attach the shared credential and open a connection.

func snapshotWithFallback(t *testing.T, fallback string) (*store.Snapshot, string) {
	t.Helper()
	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	route := &store.Route{
		ID: 1, TenantID: "acme", PathPrefix: "/api/",
		Upstream: mustURL(t, "http://up:9000"), Timeout: time.Second, RetryMax: 1,
	}
	if fallback != "" {
		route.FallbackUpstream = mustURL(t, fallback)
	}
	snap := store.SnapshotForTest(
		[]*store.Tenant{{
			ID: "acme", Name: "Acme", Enabled: true,
			RLAlgorithm: store.AlgoTokenBucket, RLRate: 1000, RLBurst: 1000,
		}},
		[]*store.Route{route},
		[]*store.APIKey{{
			ID: gen.ID, TenantID: "acme", SecretHash: gen.SecretHash,
			Scopes: []string{"read"}, Status: store.KeyActive,
		}},
	)
	return snap, gen.Plaintext
}

func routeThrough(t *testing.T, snap *store.Snapshot, key string, inner http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	m := observability.NewMetrics()
	snapshots := func() *store.Snapshot { return snap }
	h := Chain(inner, RequestID(), Auth(snapshots, m, nil), Router(snapshots))
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestTheRouterInstallsThePlanForTheMatchedRoute(t *testing.T) {
	snap, key := snapshotWithFallback(t, "http://backup:9000")
	var plan *store.RoutePlan
	rec := routeThrough(t, snap, key, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		plan = reqctx.PlanFrom(r.Context())
	}))

	if rec.Code != http.StatusOK && rec.Code != 0 {
		t.Fatalf("status = %d", rec.Code)
	}
	if plan == nil {
		t.Fatal("no plan reached the proxy")
	}
	if !plan.HasFallback() {
		t.Error("the plan lost the route's fallback")
	}
	if got := plan.Order(); got != "up:9000,backup:9000" {
		t.Errorf("order = %q", got)
	}
}

func TestTheRouterStillInstallsTheRouteForOlderReaders(t *testing.T) {
	// The proxy is not the only thing that reads the route out of the context.
	snap, key := snapshotWithFallback(t, "http://backup:9000")
	var route *store.Route
	routeThrough(t, snap, key, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		route = reqctx.RouteFrom(r.Context())
	}))

	if route == nil {
		t.Fatal("no route reached the proxy")
	}
	if route.PathPrefix != "/api/" {
		t.Errorf("route prefix = %q", route.PathPrefix)
	}
}

func TestASingleUpstreamRouteStillPlansOneCandidate(t *testing.T) {
	snap, key := snapshotWithFallback(t, "")
	var plan *store.RoutePlan
	routeThrough(t, snap, key, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		plan = reqctx.PlanFrom(r.Context())
	}))

	if plan == nil {
		t.Fatal("no plan reached the proxy")
	}
	if plan.HasFallback() {
		t.Error("a route with no fallback was planned with one")
	}
}

func TestAForbiddenFallbackUpstreamRefusesTheWholeRoute(t *testing.T) {
	// The primary is fine and the fallback points at the cloud metadata
	// service. Serving the request anyway would hide the misconfiguration
	// until the day the fallback was actually needed, which is the worst
	// possible day to discover it.
	snap, key := snapshotWithFallback(t, "http://169.254.169.254/latest/meta-data/")
	var reached bool
	rec := routeThrough(t, snap, key, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	if reached {
		t.Error("a route with a refused fallback reached the proxy")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

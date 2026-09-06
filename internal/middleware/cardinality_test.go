package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/store"
)

// labelValues collects the distinct values a metric family carries for one
// label, which is the only thing that actually matters about cardinality: a
// Prometheus time series exists per combination, and every one of them costs
// memory in this process and in the scraper forever.
func labelValues(t *testing.T, m *observability.Metrics, family, label string) map[string]bool {
	t.Helper()
	gathered, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	seen := map[string]bool{}
	for _, mf := range gathered {
		if mf.GetName() != family {
			continue
		}
		for _, metric := range mf.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if lp.GetName() == label {
					seen[lp.GetValue()] = true
				}
			}
		}
	}
	return seen
}

// meteredChain is the outer half of the real chain: Metrics sits outside Auth,
// so everything below is reachable by a caller with no credential at all.
func meteredChain(snap *store.Snapshot, m *observability.Metrics) http.Handler {
	snapshots := func() *store.Snapshot { return snap }
	return Chain(okHandler,
		Recover(testLogger),
		RequestID(),
		Metrics(m),
		Auth(snapshots, m, nil),
		Router(snapshots),
	)
}

// TestMetricMethodLabelIsBounded is the cardinality property of the RED
// metrics: every label on tollgate_requests_total must come from a bounded
// set, and the HTTP method does not, because RFC 9110 methods are arbitrary
// tokens and net/http hands the handler whatever token arrived.
//
// Unauthenticated on purpose. Metrics is outside Auth, so an attacker who
// has no key at all can still write one new time series per invented method
// and grow the gateway's metric map without limit.
func TestMetricMethodLabelIsBounded(t *testing.T) {
	snap, _ := testSnapshot(t)
	m := observability.NewMetrics()
	srv := httptest.NewServer(meteredChain(snap, m))
	t.Cleanup(srv.Close)

	const invented = 50
	for i := range invented {
		req, err := http.NewRequest(fmt.Sprintf("CARD%03d", i), srv.URL+"/api/widgets", nil)
		if err != nil {
			t.Fatalf("building request %d: %v", i, err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("sending request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("request %d: status = %d, want 401 (no credential was sent)", i, resp.StatusCode)
		}
	}

	methods := labelValues(t, m, "tollgate_requests_total", "method")
	// Nine RFC 9110 methods plus PATCH plus the catch-all is the whole set a
	// bounded label can produce, so anything above that is caller-controlled
	// cardinality that leaked through.
	const maxDistinct = 11
	if len(methods) > maxDistinct {
		t.Fatalf("tollgate_requests_total has %d distinct method label values after %d invented methods, want at most %d; a caller can mint unbounded time series. Sample: %v",
			len(methods), invented, maxDistinct, sampleKeys(methods, 5))
	}
}

// TestMetricMethodLabelKeepsRealMethods guards the other direction: clamping
// the label must not collapse the methods an operator actually splits on.
func TestMetricMethodLabelKeepsRealMethods(t *testing.T) {
	snap, _ := testSnapshot(t)
	m := observability.NewMetrics()
	srv := httptest.NewServer(meteredChain(snap, m))
	t.Cleanup(srv.Close)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		req, err := http.NewRequest(method, srv.URL+"/api/widgets", nil)
		if err != nil {
			t.Fatalf("building %s: %v", method, err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("sending %s: %v", method, err)
		}
		resp.Body.Close()
	}

	methods := labelValues(t, m, "tollgate_requests_total", "method")
	for _, want := range []string{"GET", "POST", "DELETE"} {
		if !methods[want] {
			t.Errorf("method label lost %q; got %v", want, sampleKeys(methods, 10))
		}
	}
}

// TestMetricTenantLabelIsBounded pins the label that is legitimately
// per-tenant: an unauthenticated flood must all land on one series, not on
// one per credential the attacker guesses.
func TestMetricTenantLabelIsBounded(t *testing.T) {
	snap, _ := testSnapshot(t)
	m := observability.NewMetrics()
	srv := httptest.NewServer(meteredChain(snap, m))
	t.Cleanup(srv.Close)

	for i := range 20 {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/widgets", nil)
		if err != nil {
			t.Fatalf("building request %d: %v", i, err)
		}
		req.Header.Set("X-API-Key", fmt.Sprintf("tg_k%012d_guess%d", i, i))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("sending request %d: %v", i, err)
		}
		resp.Body.Close()
	}

	tenants := labelValues(t, m, "tollgate_requests_total", "tenant")
	if len(tenants) != 1 || !tenants["unauthenticated"] {
		t.Fatalf("tenant label = %v, want exactly {unauthenticated}", sampleKeys(tenants, 10))
	}
	reasons := labelValues(t, m, "tollgate_auth_failures_total", "reason")
	if len(reasons) > 8 {
		t.Fatalf("auth failure reason label has %d values, want a small constant set: %v", len(reasons), sampleKeys(reasons, 10))
	}
}

// TestNoRequestScopedIdentifierIsAMetricLabel is the general form of the two
// checks above: nothing minted per request or per credential may appear as a
// label anywhere on the registry, because those are unbounded by definition.
func TestNoRequestScopedIdentifierIsAMetricLabel(t *testing.T) {
	m := observability.NewMetrics()
	gathered, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	banned := map[string]bool{
		"request_id": true, "requestid": true,
		"key": true, "key_id": true, "api_key": true, "keyid": true,
		"trace_id": true, "traceid": true, "span_id": true,
		"path": true, "url": true, "user": true, "subject": true, "sub": true,
	}
	for _, mf := range gathered {
		for _, metric := range mf.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if banned[lp.GetName()] {
					t.Errorf("%s carries label %q, which is unbounded per request or per credential", mf.GetName(), lp.GetName())
				}
			}
		}
	}
}

func sampleKeys(set map[string]bool, n int) []string {
	out := make([]string, 0, n)
	for k := range set {
		if len(out) == n {
			break
		}
		out = append(out, k)
	}
	return out
}

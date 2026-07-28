package proxy

import (
	"encoding/json"
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
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

func testProxy(t *testing.T, opts Options) *Proxy {
	t.Helper()
	if opts.Breakers == nil {
		opts.Breakers = resilience.NewBreakerGroup(resilience.DefaultBreakerConfig())
	}
	if opts.MaxBodyBuffer == 0 {
		opts.MaxBodyBuffer = 1 << 20
	}
	opts.MaxIdlePerHost = 4
	opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	opts.Metrics = observability.NewMetrics()
	return New(opts)
}

func routeTo(t *testing.T, rawURL string, mutate func(*store.Route)) *store.Route {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing %q: %v", rawURL, err)
	}
	r := &store.Route{
		ID: 1, TenantID: "acme", PathPrefix: "/api/",
		Upstream: u, Timeout: 2 * time.Second,
	}
	if mutate != nil {
		mutate(r)
	}
	return r
}

// send drives the proxy with route+info installed, as the middleware would.
func send(p *Proxy, route *store.Route, req *http.Request) (*httptest.ResponseRecorder, *reqctx.Info) {
	info := &reqctx.Info{RequestID: "req-test-1", TenantID: "acme"}
	ctx := reqctx.WithInfo(req.Context(), info)
	ctx = reqctx.WithRoute(ctx, route)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req.WithContext(ctx))
	return rec, info
}

func TestProxyForwardsRequest(t *testing.T) {
	var seen struct {
		path, query, xff, xfh, reqID, tenant, hopHeader string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.path = r.URL.Path
		seen.query = r.URL.RawQuery
		seen.xff = r.Header.Get("X-Forwarded-For")
		seen.xfh = r.Header.Get("X-Forwarded-Host")
		seen.reqID = r.Header.Get("X-Request-Id")
		seen.tenant = r.Header.Get("X-Tollgate-Tenant")
		seen.hopHeader = r.Header.Get("Keep-Alive")
		w.Header().Set("X-From-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "payload") //nolint:errcheck
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/widgets?a=1", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("Keep-Alive", "timeout=5") // hop-by-hop: must not be forwarded

	rec, info := send(p, routeTo(t, upstream.URL, nil), req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if got := rec.Body.String(); got != "payload" {
		t.Errorf("body = %q", got)
	}
	if rec.Header().Get("X-From-Upstream") != "yes" {
		t.Error("upstream response header lost")
	}
	if seen.path != "/api/widgets" {
		t.Errorf("upstream path = %q, want /api/widgets (no strip)", seen.path)
	}
	if seen.query != "a=1" {
		t.Errorf("query = %q, want a=1", seen.query)
	}
	if seen.xff != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q", seen.xff)
	}
	if seen.xfh != "gw.example" {
		t.Errorf("X-Forwarded-Host = %q", seen.xfh)
	}
	if seen.reqID != "req-test-1" {
		t.Errorf("X-Request-Id = %q", seen.reqID)
	}
	if seen.tenant != "acme" {
		t.Errorf("X-Tollgate-Tenant = %q", seen.tenant)
	}
	if seen.hopHeader != "" {
		t.Errorf("hop-by-hop Keep-Alive leaked to upstream: %q", seen.hopHeader)
	}
	if info.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", info.Attempts)
	}
}

// TestProxyInjectsUpstreamCredential covers the shared-LLM-key use case: the
// caller's gateway key was stripped by auth middleware; the proxy attaches
// the real provider credential from the gateway's environment.
func TestProxyInjectsUpstreamCredential(t *testing.T) {
	var got struct{ auth, clientKey string }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.auth = r.Header.Get("Authorization")
		got.clientKey = r.Header.Get("X-Api-Key")
	}))
	t.Cleanup(upstream.Close)

	t.Setenv("TEST_PROVIDER_KEY", "sk-real-provider-secret")
	p := testProxy(t, Options{})

	t.Run("injects prefix + secret", func(t *testing.T) {
		route := routeTo(t, upstream.URL, func(r *store.Route) {
			r.UpstreamAuthHeader = "Authorization"
			r.UpstreamAuthEnv = "TEST_PROVIDER_KEY"
			r.UpstreamAuthPrefix = "Bearer "
		})
		rec, _ := send(p, route, httptest.NewRequest(http.MethodGet, "/api/v1/messages", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if got.auth != "Bearer sk-real-provider-secret" {
			t.Errorf("upstream Authorization = %q, want injected bearer credential", got.auth)
		}
		if got.clientKey != "" {
			t.Errorf("client key leaked upstream: %q", got.clientKey)
		}
	})

	t.Run("missing env fails loud, not unauthenticated", func(t *testing.T) {
		route := routeTo(t, upstream.URL, func(r *store.Route) {
			r.UpstreamAuthHeader = "x-api-key"
			r.UpstreamAuthEnv = "TEST_PROVIDER_KEY_UNSET"
		})
		got.auth = "sentinel-not-called"
		rec, _ := send(p, route, httptest.NewRequest(http.MethodGet, "/api/x", nil))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502 for unconfigured credential", rec.Code)
		}
		if got.auth != "sentinel-not-called" {
			t.Error("request must not reach upstream without its credential")
		}
	})

	t.Run("no injection configured leaves headers alone", func(t *testing.T) {
		route := routeTo(t, upstream.URL, nil)
		rec, _ := send(p, route, httptest.NewRequest(http.MethodGet, "/api/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if got.auth != "" {
			t.Errorf("unexpected Authorization upstream: %q", got.auth)
		}
	})
}

func TestProxyStripPrefix(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	t.Cleanup(upstream.Close)

	tests := []struct {
		name     string
		prefix   string
		reqPath  string
		upBase   string
		wantPath string
	}{
		{"strip to root", "/api/", "/api/widgets", "", "/widgets"},
		{"strip whole prefix path", "/api/", "/api/", "", "/"},
		{"strip onto upstream base", "/svc/", "/svc/x", "/base", "/base/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProxy(t, Options{})
			route := routeTo(t, upstream.URL+tt.upBase, func(r *store.Route) {
				r.PathPrefix = tt.prefix
				r.StripPrefix = true
			})
			req := httptest.NewRequest(http.MethodGet, tt.reqPath, nil)
			rec, _ := send(p, route, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			if gotPath != tt.wantPath {
				t.Errorf("upstream path = %q, want %q", gotPath, tt.wantPath)
			}
		})
	}
}

func TestProxyRetriesTransient503(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "recovered") //nolint:errcheck
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{})
	route := routeTo(t, upstream.URL, func(r *store.Route) { r.RetryMax = 2 })
	rec, info := send(p, route, httptest.NewRequest(http.MethodGet, "/api/x", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 after retries", rec.Code)
	}
	if calls.Load() != 3 {
		t.Errorf("upstream calls = %d, want 3", calls.Load())
	}
	if info.Attempts != 3 {
		t.Errorf("info.Attempts = %d, want 3", info.Attempts)
	}
}

func TestProxyDoesNotRetryPOST(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{})
	route := routeTo(t, upstream.URL, func(r *store.Route) { r.RetryMax = 3 })
	req := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(`{"op":"charge"}`))
	rec, _ := send(p, route, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want the 503 passed through", rec.Code)
	}
	if calls.Load() != 1 {
		t.Errorf("upstream calls = %d, want exactly 1 for POST", calls.Load())
	}
}

func TestProxyDoesNotRetryNonRetryableStatus(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{})
	route := routeTo(t, upstream.URL, func(r *store.Route) { r.RetryMax = 3 })
	rec, _ := send(p, route, httptest.NewRequest(http.MethodGet, "/api/x", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 passed through", rec.Code)
	}
	if calls.Load() != 1 {
		t.Errorf("upstream calls = %d, want 1 (500 is not retryable)", calls.Load())
	}
}

func TestProxyTimeoutMapsTo504(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{})
	route := routeTo(t, upstream.URL, func(r *store.Route) { r.Timeout = 50 * time.Millisecond })
	rec, _ := send(p, route, httptest.NewRequest(http.MethodGet, "/api/slow", nil))

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", rec.Code)
	}
}

func TestProxyUnreachableUpstreamMapsTo502(t *testing.T) {
	p := testProxy(t, Options{})
	// Reserved TEST-NET address: connection refused / unroutable fast.
	route := routeTo(t, "http://127.0.0.1:1", nil)
	rec, _ := send(p, route, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if body["request_id"] != "req-test-1" {
		t.Errorf("error body request_id = %q", body["request_id"])
	}
}

func TestProxyCircuitBreakerOpens(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(upstream.Close)

	breakers := resilience.NewBreakerGroup(resilience.BreakerConfig{
		Window: 10 * time.Second, Buckets: 10, MinRequests: 3,
		FailureRatio: 0.5, Cooldown: time.Minute, HalfOpenProbes: 1,
	})
	p := testProxy(t, Options{Breakers: breakers})
	route := routeTo(t, upstream.URL, nil)

	// Three 500s trip the breaker.
	for i := 0; i < 3; i++ {
		rec, _ := send(p, route, httptest.NewRequest(http.MethodGet, "/api/x", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("warmup %d: status %d", i, rec.Code)
		}
	}
	rec, _ := send(p, route, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 from open breaker", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "circuit open") {
		t.Errorf("body should say circuit open: %s", rec.Body)
	}
}

func TestProxyHedgingWinsOnSlowPrimary(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			select {
			case <-time.After(400 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		io.WriteString(w, "fast") //nolint:errcheck
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{HedgingEnabled: true})
	route := routeTo(t, upstream.URL, func(r *store.Route) {
		r.HedgeEnabled = true
		r.HedgeDelay = 30 * time.Millisecond
	})

	start := time.Now()
	rec, info := send(p, route, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !info.Hedged {
		t.Error("request should have hedged")
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("took %v; hedge should have finished around 35ms", elapsed)
	}
}

func TestProxyHedgingDisabledPerRoute(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(80 * time.Millisecond)
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{HedgingEnabled: true}) // global on
	route := routeTo(t, upstream.URL, nil)           // route off
	rec, info := send(p, route, httptest.NewRequest(http.MethodGet, "/api/x", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if info.Hedged || calls.Load() != 1 {
		t.Errorf("hedged=%v calls=%d; route without hedge_enabled must not hedge", info.Hedged, calls.Load())
	}
}

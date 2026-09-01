package middleware

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/ratelimit"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/store"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func testSnapshot(t *testing.T) (*store.Snapshot, string) {
	t.Helper()
	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	snap := store.SnapshotForTest(
		[]*store.Tenant{{
			ID: "acme", Name: "Acme", Enabled: true,
			RLAlgorithm: store.AlgoTokenBucket, RLRate: 1000, RLBurst: 1000,
		}},
		[]*store.Route{
			{ID: 1, TenantID: "acme", PathPrefix: "/api/", Timeout: time.Second, Upstream: mustURL(t, "http://up:9000")},
			{ID: 2, TenantID: "acme", PathPrefix: "/admin/", RequiredScope: "admin", Timeout: time.Second, Upstream: mustURL(t, "http://up:9000")},
		},
		[]*store.APIKey{{
			ID: gen.ID, TenantID: "acme", SecretHash: gen.SecretHash,
			Scopes: []string{"read"}, Status: store.KeyActive,
		}},
	)
	return snap, gen.Plaintext
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

// okHandler is the innermost handler standing in for the proxy.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "ok") //nolint:errcheck
})

func chainFor(snap *store.Snapshot, limiter ratelimit.Limiter, failOpen bool) http.Handler {
	m := observability.NewMetrics()
	snapshots := func() *store.Snapshot { return snap }
	return Chain(okHandler,
		Recover(testLogger),
		RequestID(),
		Metrics(m),
		Auth(snapshots, m, nil),
		Router(snapshots),
		RateLimit(limiter, failOpen, m, testLogger),
	)
}

func TestAuthMiddleware(t *testing.T) {
	snap, key := testSnapshot(t)
	h := chainFor(snap, ratelimit.NewMemoryLimiter(), true)

	tests := []struct {
		name       string
		header     string
		value      string
		wantStatus int
	}{
		{"valid bearer key", "Authorization", "Bearer " + key, http.StatusOK},
		{"valid x-api-key", "X-API-Key", key, http.StatusOK},
		{"missing credential", "", "", http.StatusUnauthorized},
		{"garbage credential", "X-API-Key", "tg_bogus_bogus", http.StatusUnauthorized},
		{"basic auth is not bearer", "Authorization", "Basic dXNlcjpwYXNz", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
			if tt.header != "" {
				req.Header.Set(tt.header, tt.value)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
		})
	}
}

func TestScopeEnforcement(t *testing.T) {
	snap, key := testSnapshot(t)
	h := chainFor(snap, ratelimit.NewMemoryLimiter(), true)

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (key lacks admin scope)", rec.Code)
	}
}

func TestUnroutedPathIs404(t *testing.T) {
	snap, key := testSnapshot(t)
	h := chainFor(snap, ratelimit.NewMemoryLimiter(), true)

	req := httptest.NewRequest(http.MethodGet, "/nowhere", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestRateLimitMiddleware429(t *testing.T) {
	gen, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	snap := store.SnapshotForTest(
		[]*store.Tenant{{
			ID: "tiny", Name: "Tiny", Enabled: true,
			RLAlgorithm: store.AlgoSlidingWindow, RLLimit: 2, RLWindow: time.Minute,
		}},
		[]*store.Route{{ID: 1, TenantID: "tiny", PathPrefix: "/", Timeout: time.Second, Upstream: mustURL(t, "http://up:9000")}},
		[]*store.APIKey{{ID: gen.ID, TenantID: "tiny", SecretHash: gen.SecretHash, Status: store.KeyActive}},
	)
	h := chainFor(snap, ratelimit.NewMemoryLimiter(), true)

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("X-API-Key", gen.Plaintext)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := do(); rec.Code != http.StatusOK {
		t.Fatalf("request 1: %d", rec.Code)
	}
	if rec := do(); rec.Code != http.StatusOK {
		t.Fatalf("request 2: %d", rec.Code)
	}
	rec := do()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 must carry Retry-After")
	}
	if rec.Header().Get("X-RateLimit-Limit") != "2" {
		t.Errorf("X-RateLimit-Limit = %q, want 2", rec.Header().Get("X-RateLimit-Limit"))
	}
}

// erroringLimiter simulates a Redis outage.
type erroringLimiter struct{}

func (erroringLimiter) Allow(context.Context, string, ratelimit.Policy, string) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("redis: connection refused")
}
func (erroringLimiter) Name() string { return "erroring" }

func TestRateLimiterOutage(t *testing.T) {
	tests := []struct {
		name       string
		failOpen   bool
		wantStatus int
	}{
		{"fail open admits traffic", true, http.StatusOK},
		{"fail closed rejects with 503", false, http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap, key := testSnapshot(t)
			h := chainFor(snap, erroringLimiter{}, tt.failOpen)
			req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
			req.Header.Set("X-API-Key", key)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestRequestIDEchoAndPropagation(t *testing.T) {
	snap, key := testSnapshot(t)
	var seenInProxy string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenInProxy = reqctx.InfoFrom(r.Context()).RequestID
	})
	m := observability.NewMetrics()
	snapshots := func() *store.Snapshot { return snap }
	h := Chain(inner, RequestID(), Auth(snapshots, m, nil), Router(snapshots))

	t.Run("generates an id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		req.Header.Set("X-API-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("X-Request-Id") == "" {
			t.Error("response missing X-Request-Id")
		}
		if seenInProxy == "" {
			t.Error("request id not in context")
		}
	})

	t.Run("honours inbound id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		req.Header.Set("X-API-Key", key)
		req.Header.Set("X-Request-Id", "caller-chosen-42")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("X-Request-Id"); got != "caller-chosen-42" {
			t.Errorf("X-Request-Id = %q, want caller-chosen-42", got)
		}
	})
}

func TestAuthHeaderStrippedBeforeProxy(t *testing.T) {
	snap, key := testSnapshot(t)
	var leaked string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") + r.Header.Get("X-API-Key")
	})
	m := observability.NewMetrics()
	snapshots := func() *store.Snapshot { return snap }
	h := Chain(inner, RequestID(), Auth(snapshots, m, nil), Router(snapshots))

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if leaked != "" {
		t.Errorf("gateway credential leaked toward upstream: %q", leaked)
	}
}

func TestRecoverTurnsPanicInto500(t *testing.T) {
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}), Recover(testLogger), RequestID())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestKeyRotationGraceHeader(t *testing.T) {
	gen, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	graceUntil := time.Now().Add(time.Hour)
	snap := store.SnapshotForTest(
		[]*store.Tenant{{ID: "acme", Name: "Acme", Enabled: true, RLAlgorithm: store.AlgoTokenBucket, RLRate: 100, RLBurst: 100}},
		[]*store.Route{{ID: 1, TenantID: "acme", PathPrefix: "/", Timeout: time.Second, Upstream: mustURL(t, "http://up:9000")}},
		[]*store.APIKey{{
			ID: gen.ID, TenantID: "acme", SecretHash: gen.SecretHash,
			Status: store.KeyGrace, GraceUntil: &graceUntil,
		}},
	)
	h := chainFor(snap, ratelimit.NewMemoryLimiter(), true)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-API-Key", gen.Plaintext)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("grace-window key rejected: %d", rec.Code)
	}
	if rec.Header().Get("X-Api-Key-Deprecated") != "true" {
		t.Error("grace-window responses must set X-Api-Key-Deprecated")
	}
}

func TestCORSAllowsOnlyListedOrigins(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := CORS([]string{"https://lgoyal6.github.io"})(next)

	t.Run("listed origin is echoed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
		req.Header.Set("Origin", "https://lgoyal6.github.io")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://lgoyal6.github.io" {
			t.Fatalf("allow-origin = %q, want the request origin", got)
		}
		if rec.Code != http.StatusTeapot {
			t.Fatalf("status = %d, want the handler to still run", rec.Code)
		}
	})

	t.Run("unlisted origin gets no header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("allow-origin = %q, want empty for an unlisted origin", got)
		}
	})

	// A preflight carries no Authorization header, so it has to be answered
	// before Auth ever sees it.
	t.Run("preflight is answered without reaching the handler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/v1/x", nil)
		req.Header.Set("Origin", "https://lgoyal6.github.io")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("preflight status = %d, want 204", rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
			t.Fatal("preflight must allow the Authorization header")
		}
	})
}

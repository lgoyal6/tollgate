package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/limits"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

// limitsOff zeroes a limits.Config when TOLLGATE_LIMITS_OFF is set, which is
// the gateway as it behaved before these bounds existed, because 0 means "not
// enforced" for every field. Running this file in that mode is how the
// before/after evidence in RECORD_tollgate_limits.md was produced.
func limitsOff(c limits.Config) limits.Config {
	if os.Getenv("TOLLGATE_LIMITS_OFF") != "" {
		return limits.Config{}
	}
	return c
}

// An upstream that declares an oversize length can be refused cleanly, because
// nothing has been written to the client yet.
func TestProxyRefusesDeclaredOversizeResponse(t *testing.T) {
	payload := strings.Repeat("y", 4<<20)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4194304")
		io.WriteString(w, payload) //nolint:errcheck
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{Limits: limitsOff(limits.Config{MaxResponseBytes: 1 << 20})})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", nil)
	rec, info := send(p, routeTo(t, upstream.URL, nil), req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if rec.Body.Len() > 1<<10 {
		t.Errorf("relayed %d bytes of an oversize response", rec.Body.Len())
	}
	if info.Error == "" {
		t.Error("info.Error empty: the refusal must be attributable in the access log")
	}
}

// A streamed response declares no length, so the cap can only fire mid-stream.
// The client keeps what it got; the gateway stops paying for the rest.
func TestProxyTruncatesOversizeStreamedResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("z", 64<<10)
		for i := 0; i < 128; i++ { // 8 MiB if nothing stops it
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	t.Cleanup(upstream.Close)

	const capBytes = 1 << 20
	p := testProxy(t, Options{Limits: limitsOff(limits.Config{MaxResponseBytes: capBytes})})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", nil)
	rec, info := send(p, routeTo(t, upstream.URL, nil), req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: the header was already sent", rec.Code)
	}
	if int64(rec.Body.Len()) > capBytes {
		t.Errorf("relayed %d bytes, more than the %d cap", rec.Body.Len(), capBytes)
	}
	if info.Error == "" {
		t.Error("a truncated response must be recorded, not silently dropped")
	}
}

func TestProxyRelaysAResponseUnderTheCap(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("k", 4096)) //nolint:errcheck
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{Limits: limitsOff(limits.Config{MaxResponseBytes: 1 << 20})})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", nil)
	rec, info := send(p, routeTo(t, upstream.URL, nil), req)

	if rec.Code != http.StatusOK || rec.Body.Len() != 4096 {
		t.Errorf("status = %d, body = %d bytes; want 200 and 4096", rec.Code, rec.Body.Len())
	}
	if info.Error != "" {
		t.Errorf("info.Error = %q on a response well under the cap", info.Error)
	}
}

// RetryMax is a database column, so the proxy has to have its own ceiling.
// Without one, a route row of 50 is 50 requests to a paid upstream and enough
// failures to trip a circuit breaker every other tenant on that host shares.
func TestProxyClampsRouteRetryCount(t *testing.T) {
	var attempts atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(upstream.Close)

	// A breaker that never trips, so this test measures the retry ceiling and
	// nothing else. With the default config the breaker would stop the flood
	// at 20 attempts and hide whether the clamp works at all.
	cfg := resilience.DefaultBreakerConfig()
	cfg.MinRequests = 10000
	p := testProxy(t, Options{Breakers: resilience.NewBreakerGroup(cfg)})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", nil)
	route := routeTo(t, upstream.URL, func(r *store.Route) { r.RetryMax = 50 })
	rec, _ := send(p, route, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want the upstream's 503 relayed", rec.Code)
	}
	// The bound is written out rather than compared against
	// maxAttemptsHardCap: an assertion that reads the same constant the code
	// reads moves whenever the constant does, and would pass with the clamp
	// raised to 500.
	if got := attempts.Load(); got > 5 {
		t.Errorf("upstream saw %d attempts for a route asking for 51; want at most 5", got)
	}
}

// The route timeout bounds one attempt. Without a total deadline the real
// ceiling is that timeout times the retry count, on one goroutine, one
// connection and one spend hold.
func TestProxyTotalRequestDurationBoundsRetries(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // longer than any single attempt is allowed
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{Limits: limitsOff(limits.Config{MaxRequestDuration: 300 * time.Millisecond})})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", nil)
	route := routeTo(t, upstream.URL, func(r *store.Route) {
		r.Timeout = 200 * time.Millisecond
		r.RetryMax = 4 // 5 attempts would be a second without the total bound
	})

	start := time.Now()
	rec, _ := send(p, route, req)
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Errorf("request took %s, past the 300ms total deadline by more than the slack", elapsed)
	}
	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504", rec.Code)
	}
}

// A chunked upload has no declared length, so the cap fires while the body is
// being sent upstream. The client must still be told 413 and not 502.
func TestProxyMapsRequestTooLargeTo413(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	p := testProxy(t, Options{})
	body := limits.NewCappedBody(io.NopCloser(strings.NewReader(strings.Repeat("q", 1<<20))), 4096)
	req := httptest.NewRequest(http.MethodPost, "http://gw.example/api/x", body)
	req.ContentLength = -1
	rec, _ := send(p, routeTo(t, upstream.URL, nil), req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

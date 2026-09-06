package middleware

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/limits"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/proxy"
	"github.com/lgoyal6/tollgate/internal/ratelimit"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

// This file measures what one in-flight request costs the gateway. It exists
// because the limits in limits.go are only defensible if the numbers behind
// them can be re-derived: an operator raising MAX_INFLIGHT_PER_TENANT wants to
// know what each extra slot buys in bytes and goroutines.
//
// It is opt-in (TOLLGATE_MEASURE=1) because it deliberately holds requests
// open and reads runtime.MemStats, which is slow and noisy under -race and in
// parallel with other tests.

func measureOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("TOLLGATE_MEASURE") == "" {
		t.Skip("set TOLLGATE_MEASURE=1 to run the cost measurements")
	}
}

// padReader emits n copies of 'a' without the harness holding them, so what a
// measurement sees is the gateway's footprint and not the client's.
type padReader struct{ n int }

func (p *padReader) Read(b []byte) (int, error) {
	if p.n == 0 {
		return 0, io.EOF
	}
	n := len(b)
	if n > p.n {
		n = p.n
	}
	for i := 0; i < n; i++ {
		b[i] = 'a'
	}
	p.n -= n
	return n, nil
}

const bodyHead = `{"model":"claude-sonnet-5","max_tokens":100,"pad":"`
const bodyTail = `"}`

// chatBody streams a priceable chat-completions body of exactly size bytes.
func chatBody(size int) io.Reader {
	pad := size - len(bodyHead) - len(bodyTail)
	if pad < 0 {
		pad = 0
	}
	return io.MultiReader(strings.NewReader(bodyHead), &padReader{n: pad}, strings.NewReader(bodyTail))
}

func chatBodySize(size int) int64 {
	pad := size - len(bodyHead) - len(bodyTail)
	if pad < 0 {
		pad = 0
	}
	return int64(len(bodyHead) + pad + len(bodyTail))
}

// costHarness is the real request path: the gateway's middleware chain
// terminating in the real proxy, in front of a real upstream server.
type costHarness struct {
	gateway *httptest.Server
	key     string
	keys    map[string]string
	metrics *observability.Metrics
	client  *http.Client
}

func newCostHarness(t *testing.T, upstream http.Handler, ledger budgetLedger, route func(*store.Route)) *costHarness {
	// The measurements run against the unbounded gateway on purpose: they are
	// what the limits were chosen from, so they must not be taken under them.
	return newHarness(t, upstream, ledger, limits.Config{}, route, "acme")
}

// newHarness builds the real request path - the gateway's own middleware order
// terminating in the real proxy - in front of a real upstream server.
func newHarness(t *testing.T, upstream http.Handler, ledger budgetLedger, cfg limits.Config,
	route func(*store.Route), tenants ...string) *costHarness {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	var (
		tt   []*store.Tenant
		rr   []*store.Route
		kk   []*store.APIKey
		keys = map[string]string{}
	)
	for i, id := range tenants {
		gen, err := auth.Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		rt := &store.Route{
			ID: int64(i + 1), TenantID: id, PathPrefix: "/api/",
			Upstream: mustURL(t, up.URL), Timeout: 30 * time.Second,
		}
		if route != nil {
			route(rt)
		}
		tt = append(tt, &store.Tenant{
			ID: id, Name: id, Enabled: true,
			RLAlgorithm: store.AlgoTokenBucket, RLRate: 1e6, RLBurst: 1e6,
		})
		rr = append(rr, rt)
		kk = append(kk, &store.APIKey{ID: gen.ID, TenantID: id, SecretHash: gen.SecretHash, Status: store.KeyActive})
		keys[id] = gen.Plaintext
	}
	snap := store.SnapshotForTest(tt, rr, kk)

	m := observability.NewMetrics()
	px := proxy.New(proxy.Options{
		Breakers:       resilience.NewBreakerGroup(resilience.DefaultBreakerConfig()),
		MaxBodyBuffer:  1 << 20,
		MaxIdlePerHost: 256,
		Limits:         cfg,
		Logger:         testLogger,
		Metrics:        m,
	})
	snapshots := func() *store.Snapshot { return snap }
	h := Chain(px,
		Recover(testLogger),
		RequestID(),
		Metrics(m),
		Auth(snapshots, m, nil),
		Router(snapshots),
		RequestSize(cfg, m),
		RateLimit(ratelimit.NewMemoryLimiter(), true, m, testLogger),
		Concurrency(cfg, m),
		Budget(ledger, true, testLogger),
	)
	gw := httptest.NewServer(h)
	t.Cleanup(gw.Close)
	return &costHarness{
		gateway: gw,
		key:     keys[tenants[0]],
		keys:    keys,
		metrics: m,
		client: &http.Client{Transport: &http.Transport{
			MaxIdleConnsPerHost: 512,
			DisableCompression:  true,
		}},
	}
}

// postAs sends as a named tenant, which is what the isolation tests need.
func (h *costHarness) postAs(tenant string, body io.Reader, length int64) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, h.gateway.URL+"/api/messages", body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = length
	req.Header.Set("X-API-Key", h.keys[tenant])
	req.Header.Set("Content-Type", "application/json")
	return h.client.Do(req)
}

func (h *costHarness) post(body io.Reader, length int64, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, h.gateway.URL+"/api/messages", body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = length
	req.Header.Set("X-API-Key", h.key)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return h.client.Do(req)
}

func heapNow() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// TestMeasureInFlightCost reports the bytes and goroutines the gateway holds
// per concurrent request, as a function of request body size. Those two curves
// are what a concurrency cap has to be chosen against.
func TestMeasureInFlightCost(t *testing.T) {
	measureOnly(t)

	sizes := []int{1 << 10, 64 << 10, 1 << 20, 8 << 20, 32 << 20}
	const conc = 32

	for _, size := range sizes {
		arrived := make(chan struct{}, conc)
		release := make(chan struct{})
		up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body) //nolint:errcheck
			arrived <- struct{}{}
			<-release
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"usage":{"input_tokens":10,"output_tokens":10}}`) //nolint:errcheck
		})
		h := newCostHarness(t, up, &fakeLedger{remaining: 1 << 62}, nil)

		baseHeap := heapNow()
		baseGo := runtime.NumGoroutine()

		var wg sync.WaitGroup
		start := time.Now()
		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := h.post(chatBody(size), chatBodySize(size), nil)
				if err != nil {
					return
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
			}()
		}
		for i := 0; i < conc; i++ {
			<-arrived
		}
		peakGo := runtime.NumGoroutine()
		peakHeap := heapNow()
		close(release)
		wg.Wait()
		elapsed := time.Since(start)

		t.Logf("body=%-9s conc=%d  heap_held=%.1f MiB  per_request=%.0f KiB  goroutines=+%d (%.1f/req)  wall=%s",
			humanBytes(int64(size)), conc,
			float64(peakHeap-baseHeap)/(1<<20),
			float64(peakHeap-baseHeap)/float64(conc)/1024,
			peakGo-baseGo, float64(peakGo-baseGo)/float64(conc), elapsed.Round(time.Millisecond))
	}
}

// TestMeasureUnboundedBody reports what the gateway does today with a body of
// no declared length: what it buffers, and how many bytes reach the upstream.
func TestMeasureUnboundedBody(t *testing.T) {
	measureOnly(t)

	for _, size := range []int{1 << 20, 64 << 20, 256 << 20} {
		var got int64
		up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n, _ := io.Copy(io.Discard, r.Body)
			got = n
			io.WriteString(w, `{"usage":{"input_tokens":1,"output_tokens":1}}`) //nolint:errcheck
		})
		h := newCostHarness(t, up, &fakeLedger{remaining: 1 << 62}, nil)

		baseHeap := heapNow()
		// ContentLength -1 is a chunked upload: the proxy will not buffer it,
		// but nothing stops it either.
		start := time.Now()
		resp, err := h.post(chatBody(size), -1, nil)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		peakHeap := heapNow()
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()

		t.Logf("chunked body=%-9s -> status=%d  upstream_received=%s  gateway_heap_delta=%.1f MiB  wall=%s",
			humanBytes(int64(size)), resp.StatusCode, humanBytes(got),
			float64(peakHeap-baseHeap)/(1<<20), time.Since(start).Round(time.Millisecond))
	}
}

// TestMeasureGzipExpansion reports the expansion ratio an attacker gets for
// free, and what the gateway currently does with the compressed body.
func TestMeasureGzipExpansion(t *testing.T) {
	measureOnly(t)

	for _, plain := range []int{1 << 20, 64 << 20, 512 << 20} {
		var buf strings.Builder
		zw := gzip.NewWriter(&countingWriter{w: &buf})
		if _, err := io.Copy(zw, chatBody(plain)); err != nil {
			t.Fatalf("gzip: %v", err)
		}
		zw.Close()
		wire := len(buf.String())
		t.Logf("plaintext=%-9s gzip_wire=%-9s ratio=%.0fx",
			humanBytes(int64(plain)), humanBytes(int64(wire)), float64(plain)/float64(wire))
	}
}

type countingWriter struct{ w *strings.Builder }

func (c *countingWriter) Write(p []byte) (int, error) { return c.w.Write(p) }

// TestMeasureGzipBudgetBypass shows what a Content-Encoding header does to
// budget enforcement today: the estimator cannot read a compressed body, so
// the request is forwarded with no hold at all.
func TestMeasureGzipBudgetBypass(t *testing.T) {
	measureOnly(t)

	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		io.WriteString(w, `{}`)     //nolint:errcheck
	})
	for _, enc := range []string{"", "gzip"} {
		ledger := &fakeLedger{remaining: 1 << 62}
		h := newCostHarness(t, up, ledger, nil)
		var body io.Reader = chatBody(4096)
		length := chatBodySize(4096)
		hdr := map[string]string{}
		if enc != "" {
			var sb strings.Builder
			zw := gzip.NewWriter(&countingWriter{w: &sb})
			io.Copy(zw, chatBody(4096)) //nolint:errcheck
			zw.Close()
			body = strings.NewReader(sb.String())
			length = int64(len(sb.String()))
			hdr["Content-Encoding"] = "gzip"
		}
		resp, err := h.post(body, length, hdr)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		t.Logf("content-encoding=%-6q status=%d ledger_calls=%v", enc, resp.StatusCode, ledger.seen())
	}
}

// TestMeasureRetryWallClock reports how long one request can occupy a
// goroutine, which is the per-attempt route timeout multiplied by the retry
// count the database happens to hold.
func TestMeasureRetryWallClock(t *testing.T) {
	measureOnly(t)

	for _, retries := range []int{0, 3, 20} {
		var attempts int
		up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		h := newCostHarness(t, up, &fakeLedger{remaining: 1 << 62}, func(rt *store.Route) {
			rt.RetryMax = retries
			rt.Timeout = 200 * time.Millisecond
		})
		req, _ := http.NewRequest(http.MethodGet, h.gateway.URL+"/api/messages", nil)
		req.Header.Set("X-API-Key", h.key)
		start := time.Now()
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		t.Logf("route.retry_max=%-3d attempts=%-3d status=%d wall=%s",
			retries, attempts, resp.StatusCode, time.Since(start).Round(time.Millisecond))
	}
}

// TestMeasureResponseSize reports what the gateway holds while relaying a
// large upstream response.
func TestMeasureResponseSize(t *testing.T) {
	measureOnly(t)

	for _, size := range []int{1 << 20, 64 << 20, 512 << 20} {
		up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body) //nolint:errcheck
			w.Header().Set("Content-Type", "application/json")
			io.Copy(w, chatBody(size)) //nolint:errcheck
		})
		h := newCostHarness(t, up, &fakeLedger{remaining: 1 << 62}, nil)
		baseHeap := heapNow()
		start := time.Now()
		resp, err := h.post(chatBody(512), chatBodySize(512), nil)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		peakHeap := heapNow()
		resp.Body.Close()
		t.Logf("upstream_response=%-9s client_received=%-9s status=%d heap_delta=%.1f MiB wall=%s",
			humanBytes(int64(size)), humanBytes(n), resp.StatusCode,
			float64(peakHeap-baseHeap)/(1<<20), time.Since(start).Round(time.Millisecond))
	}
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// goroutinesByRole counts in-flight goroutines by the role their stack shows,
// so the per-request goroutine number can be split between the gateway and
// the client and upstream that share this test process.
func goroutinesByRole() map[string]int {
	buf := make([]byte, 1<<22)
	n := runtime.Stack(buf, true)
	out := map[string]int{}
	for _, g := range strings.Split(string(buf[:n]), "\n\ngoroutine ") {
		switch {
		case strings.Contains(g, "net/http.(*conn).serve"):
			out["http_server_conn"]++
		case strings.Contains(g, "net/http.(*persistConn).readLoop"):
			out["http_client_readloop"]++
		case strings.Contains(g, "net/http.(*persistConn).writeLoop"):
			out["http_client_writeloop"]++
		}
	}
	return out
}

// TestMeasureGoroutineRoles splits the per-request goroutine count by role.
// The gateway's own share is one server connection goroutine plus the
// transport's read and write loops for the upstream connection; the rest
// belongs to the client and the upstream, which only share this process
// because the harness does.
func TestMeasureGoroutineRoles(t *testing.T) {
	measureOnly(t)

	const conc = 32
	arrived := make(chan struct{}, conc)
	release := make(chan struct{})
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		arrived <- struct{}{}
		<-release
		io.WriteString(w, `{"usage":{"input_tokens":1,"output_tokens":1}}`) //nolint:errcheck
	})
	h := newCostHarness(t, up, &fakeLedger{remaining: 1 << 62}, nil)

	base := goroutinesByRole()
	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := h.post(chatBody(1024), chatBodySize(1024), nil)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}()
	}
	for i := 0; i < conc; i++ {
		<-arrived
	}
	peak := goroutinesByRole()
	close(release)
	wg.Wait()

	for _, role := range []string{"http_server_conn", "http_client_readloop", "http_client_writeloop"} {
		t.Logf("%-22s +%d over %d in-flight (%.2f/req)",
			role, peak[role]-base[role], conc, float64(peak[role]-base[role])/float64(conc))
	}
}

// TestMeasureOverloadFootprint is the "before" picture of overload: nothing in
// the chain caps concurrency, so a single tenant's fan-out is answered by
// linear growth in resident memory rather than by a rejection.
func TestMeasureOverloadFootprint(t *testing.T) {
	measureOnly(t)

	for _, conc := range []int{32, 128, 512} {
		arrived := make(chan struct{}, conc)
		release := make(chan struct{})
		up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body) //nolint:errcheck
			arrived <- struct{}{}
			<-release
			io.WriteString(w, `{"usage":{"input_tokens":1,"output_tokens":1}}`) //nolint:errcheck
		})
		h := newCostHarness(t, up, &fakeLedger{remaining: 1 << 62}, nil)

		baseHeap := heapNow()
		baseGo := runtime.NumGoroutine()
		var wg sync.WaitGroup
		var rejected int64
		var mu sync.Mutex
		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := h.post(chatBody(1<<20), chatBodySize(1<<20), nil)
				if err != nil {
					return
				}
				if resp.StatusCode != http.StatusOK {
					mu.Lock()
					rejected++
					mu.Unlock()
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
			}()
		}
		for i := 0; i < conc; i++ {
			<-arrived
		}
		peakGo := runtime.NumGoroutine()
		peakHeap := heapNow()
		close(release)
		wg.Wait()

		t.Logf("hostile_concurrency=%-4d heap=%6.1f MiB  goroutines=+%-5d  rejected=%d",
			conc, float64(peakHeap-baseHeap)/(1<<20), peakGo-baseGo, rejected)
	}
}

// TestMeasureOverloadUnderLimits is the same flood as
// TestMeasureOverloadFootprint, run with the production default bounds. It is
// the "after" half of the before/after: the curve has to stop being linear and
// the refusals have to be counted rather than absorbed.
func TestMeasureOverloadUnderLimits(t *testing.T) {
	measureOnly(t)

	cfg := limits.Config{
		MaxRequestBytes:      8 << 20,
		MaxDecompressedBytes: 8 << 20,
		MaxResponseBytes:     32 << 20,
		MaxInFlightPerTenant: 64,
		MaxQueuePerTenant:    128,
		QueueWait:            time.Second,
		MaxRequestDuration:   60 * time.Second,
	}
	for _, conc := range []int{32, 128, 512} {
		arrived := make(chan struct{}, conc)
		release := make(chan struct{})
		up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body) //nolint:errcheck
			arrived <- struct{}{}
			<-release
			io.WriteString(w, `{"usage":{"input_tokens":1,"output_tokens":1}}`) //nolint:errcheck
		})
		h := newHarness(t, up, &fakeLedger{remaining: 1 << 62}, cfg, nil, "acme")

		baseHeap := heapNow()
		baseGo := runtime.NumGoroutine()
		var wg sync.WaitGroup
		var rejected, served atomic.Int64
		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := h.post(chatBody(1<<20), chatBodySize(1<<20), nil)
				if err != nil {
					return
				}
				if resp.StatusCode == http.StatusTooManyRequests {
					rejected.Add(1)
				} else {
					served.Add(1)
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
			}()
		}
		admitted := min(conc, cfg.MaxInFlightPerTenant)
		for i := 0; i < admitted; i++ {
			<-arrived
		}
		peakGo := runtime.NumGoroutine()
		peakHeap := heapNow()
		close(release)
		wg.Wait()

		t.Logf("hostile_concurrency=%-4d heap=%6.1f MiB  goroutines=+%-5d  served=%-4d rejected=%d",
			conc, float64(peakHeap-baseHeap)/(1<<20), peakGo-baseGo, served.Load(), rejected.Load())
	}
}

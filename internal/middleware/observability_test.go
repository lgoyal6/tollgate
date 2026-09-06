package middleware

// A controlled run of the full chain against three upstreams, one of which is
// deliberately slow and one of which is deliberately dead. The point is not
// that counters move - synthetic counters always move - but that the signals
// the gateway actually emits are enough to name WHICH dependency was slow and
// WHICH one failed, and that one request's identifiers join up across the log,
// the trace and the spend ledger.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/budget"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/proxy"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

// syncBuffer collects log output written from the server's goroutines and
// read from the test's, so -race has a lock to reason about rather than an
// ordering argument about when a response was flushed.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// injectedDelay is long enough to be unambiguous against the 250ms histogram
// bucket boundary and short enough not to slow the suite down.
const injectedDelay = 300 * time.Millisecond

// ledgerCall is the identifying half of a ledger operation, which is the half
// this test is about.
type ledgerCall struct{ op, tenant, request string }

type recordingLedger struct {
	mu    sync.Mutex
	calls []ledgerCall
}

func (l *recordingLedger) record(op, tenant, request string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, ledgerCall{op, tenant, request})
}

func (l *recordingLedger) Reserve(_ context.Context, tenant, request string, _ int64, _ string) (budget.Status, error) {
	l.record("reserve", tenant, request)
	remaining := int64(1_000_000)
	return budget.Status{Remaining: &remaining}, nil
}

func (l *recordingLedger) Settle(_ context.Context, tenant, request string, _ int64) (budget.Status, error) {
	l.record("settle", tenant, request)
	return budget.Status{}, nil
}

func (l *recordingLedger) Release(_ context.Context, tenant, request, _ string) error {
	l.record("release", tenant, request)
	return nil
}

func (l *recordingLedger) MarkUncertain(_ context.Context, tenant, request, _ string) error {
	l.record("uncertain", tenant, request)
	return nil
}

func (l *recordingLedger) seen() []ledgerCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]ledgerCall(nil), l.calls...)
}

// histogram returns the observation count and total seconds for the one series
// of a histogram family whose labels all match want.
func histogram(t *testing.T, m *observability.Metrics, family string, want map[string]string) (uint64, float64) {
	t.Helper()
	gathered, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	var count uint64
	var sum float64
	for _, mf := range gathered {
		if mf.GetName() != family {
			continue
		}
		for _, metric := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range metric.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			matched := true
			for k, v := range want {
				if labels[k] != v {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			count += metric.GetHistogram().GetSampleCount()
			sum += metric.GetHistogram().GetSampleSum()
		}
	}
	return count, sum
}

// deadAddress returns a host:port that nothing is listening on, by opening a
// listener and closing it. Injecting a connection failure this way needs no
// fault library and no privileged port.
func deadAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a dead address: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("closing the dead listener: %v", err)
	}
	return addr
}

// TestObservabilityNamesTheFaultyDependency is the controlled run.
func TestObservabilityNamesTheFaultyDependency(t *testing.T) {
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spans),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	// Set before anything captures a tracer: the global provider hands out
	// delegating tracers, and their delegate is wired the first time it is set.
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":"hi","usage":{"input_tokens":12,"output_tokens":34}}`) //nolint:errcheck
	}))
	t.Cleanup(healthy.Close)

	// Injected dependency delay. Nothing else about this upstream differs.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(injectedDelay)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":"slow","usage":{"input_tokens":12,"output_tokens":34}}`) //nolint:errcheck
	}))
	t.Cleanup(slow.Close)

	// Injected dependency failure: the connection is refused outright.
	deadHost := deadAddress(t)

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
			{ID: 1, TenantID: "acme", PathPrefix: "/healthy/", Timeout: 5 * time.Second, StripPrefix: true, Upstream: mustURL(t, healthy.URL)},
			{ID: 2, TenantID: "acme", PathPrefix: "/slow/", Timeout: 5 * time.Second, StripPrefix: true, Upstream: mustURL(t, slow.URL)},
			{ID: 3, TenantID: "acme", PathPrefix: "/dead/", Timeout: 5 * time.Second, StripPrefix: true, Upstream: mustURL(t, "http://"+deadHost)},
		},
		[]*store.APIKey{{
			ID: gen.ID, TenantID: "acme", SecretHash: gen.SecretHash, Status: store.KeyActive,
		}},
	)
	snapshots := func() *store.Snapshot { return snap }

	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := observability.NewMetrics()
	ledger := &recordingLedger{}

	px := proxy.New(proxy.Options{
		Breakers:       resilience.NewBreakerGroup(resilience.DefaultBreakerConfig()),
		MaxBodyBuffer:  1 << 20,
		MaxIdlePerHost: 4,
		Logger:         logger,
		Metrics:        m,
	})
	chain := Chain(px,
		Recover(logger),
		RequestID(),
		AccessLog(logger, true, 1),
		Metrics(m),
		Tracing("tollgate-observability-test"),
		Auth(snapshots, m, nil),
		Router(snapshots),
		Budget(ledger, true, logger),
	)
	srv := httptest.NewServer(chain)
	t.Cleanup(srv.Close)

	// An enforceable shape, so the ledger is exercised rather than skipped.
	const body = `{"model":"claude-sonnet-5","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`
	call := func(t *testing.T, path, requestID string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+gen.Plaintext)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", requestID)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("sending request: %v", err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		return resp.StatusCode
	}

	const healthyID = "corr-healthy-0001"
	if code := call(t, "/healthy/v1/messages", healthyID); code != http.StatusOK {
		t.Fatalf("healthy upstream: status = %d, want 200", code)
	}
	if code := call(t, "/slow/v1/messages", "corr-slow-0002"); code != http.StatusOK {
		t.Fatalf("slow upstream: status = %d, want 200", code)
	}
	if code := call(t, "/dead/v1/messages", "corr-dead-0003"); code != http.StatusBadGateway {
		t.Fatalf("dead upstream: status = %d, want 502", code)
	}

	healthyHost := mustURL(t, healthy.URL).Host
	slowHost := mustURL(t, slow.URL).Host

	// --- the delay is attributable to one upstream, from metrics alone ---
	healthyCount, healthySum := histogram(t, m, "tollgate_upstream_request_duration_seconds",
		map[string]string{"upstream": healthyHost, "code": "2xx"})
	slowCount, slowSum := histogram(t, m, "tollgate_upstream_request_duration_seconds",
		map[string]string{"upstream": slowHost, "code": "2xx"})
	deadCount, deadSum := histogram(t, m, "tollgate_upstream_request_duration_seconds",
		map[string]string{"upstream": deadHost, "code": "error"})
	t.Logf("tollgate_upstream_request_duration_seconds: healthy(%s) count=%d sum=%.4fs | slow(%s) count=%d sum=%.4fs | dead(%s,code=error) count=%d sum=%.4fs",
		healthyHost, healthyCount, healthySum, slowHost, slowCount, slowSum, deadHost, deadCount, deadSum)

	if healthyCount != 1 || slowCount != 1 {
		t.Fatalf("upstream attempt counts = healthy %d, slow %d; want 1 each", healthyCount, slowCount)
	}
	if slowSum < injectedDelay.Seconds() {
		t.Errorf("slow upstream observed %.4fs, want at least the %v injected delay", slowSum, injectedDelay)
	}
	if healthySum >= injectedDelay.Seconds() {
		t.Errorf("healthy upstream observed %.4fs, which is as slow as the injected delay; the metric does not separate them", healthySum)
	}

	// --- the failure is attributable to one upstream, from metrics alone ---
	if deadCount != 1 {
		t.Errorf("dead upstream error observations = %d, want 1", deadCount)
	}
	if c, _ := histogram(t, m, "tollgate_upstream_request_duration_seconds",
		map[string]string{"upstream": healthyHost, "code": "error"}); c != 0 {
		t.Errorf("healthy upstream has %d error observations; the failure is being smeared across dependencies", c)
	}

	// --- the trace says the same thing, and says why ---
	var deadSpan, slowSpan sdktrace.ReadOnlySpan
	for _, s := range spans.Ended() {
		for _, kv := range s.Attributes() {
			if kv.Key != "tollgate.upstream" {
				continue
			}
			switch kv.Value.AsString() {
			case deadHost:
				deadSpan = s
			case slowHost:
				slowSpan = s
			}
		}
	}
	if deadSpan == nil {
		t.Fatal("no client span names the dead upstream; a trace could not attribute the 502")
	}
	if deadSpan.Status().Code.String() != "Error" {
		t.Errorf("dead upstream span status = %s, want Error", deadSpan.Status().Code)
	}
	t.Logf("dead upstream span: name=%q status=%s description=%q",
		deadSpan.Name(), deadSpan.Status().Code, deadSpan.Status().Description)
	if slowSpan == nil {
		t.Fatal("no client span names the slow upstream")
	}
	slowSpanDur := slowSpan.EndTime().Sub(slowSpan.StartTime())
	t.Logf("slow upstream span: name=%q duration=%v", slowSpan.Name(), slowSpanDur)
	if slowSpanDur < injectedDelay {
		t.Errorf("slow upstream span lasted %v, want at least the %v injected delay", slowSpanDur, injectedDelay)
	}

	// --- one request's identifiers join up across log, trace and ledger ---
	var accessLine map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry["msg"] == "request" && entry["request_id"] == healthyID {
			accessLine = entry
		}
	}
	if accessLine == nil {
		t.Fatalf("no access log line for request %s:\n%s", healthyID, logs.String())
	}
	traceID, _ := accessLine["trace_id"].(string)
	if traceID == "" {
		t.Error("access log line carries no trace_id; a log cannot be pivoted to its trace")
	}
	if accessLine["tenant"] != "acme" {
		t.Errorf("access log tenant = %v, want acme", accessLine["tenant"])
	}
	t.Logf("access log: request_id=%v trace_id=%v tenant=%v route=%v upstream=%v status=%v",
		accessLine["request_id"], accessLine["trace_id"], accessLine["tenant"],
		accessLine["route"], accessLine["upstream"], accessLine["status"])

	var serverSpan sdktrace.ReadOnlySpan
	for _, s := range spans.Ended() {
		for _, kv := range s.Attributes() {
			if kv.Key == "tollgate.request_id" && kv.Value.AsString() == healthyID {
				serverSpan = s
			}
		}
	}
	if serverSpan == nil {
		t.Fatalf("no server span carries tollgate.request_id=%s", healthyID)
	}
	if got := serverSpan.SpanContext().TraceID().String(); got != traceID {
		t.Errorf("trace_id in the log = %s, but the span carrying the request id has trace %s", traceID, got)
	}

	var settled bool
	for _, c := range ledger.seen() {
		if c.request == healthyID && c.tenant == "acme" && c.op == "settle" {
			settled = true
		}
	}
	if !settled {
		t.Errorf("ledger never settled request %s for tenant acme; spend cannot be joined to the request that caused it. calls: %v",
			healthyID, ledger.seen())
	}
	t.Logf("ledger calls: %v", ledger.seen())

	// The upstream must also be able to join up: the request id goes out on
	// the wire, so the provider's own logs line up with the gateway's.
	if !strings.Contains(fmt.Sprint(accessLine["upstream"]), healthyHost) {
		t.Errorf("access log upstream = %v, want %s", accessLine["upstream"], healthyHost)
	}
}

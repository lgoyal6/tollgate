package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/secops"
	"github.com/lgoyal6/tollgate/internal/store"
)

type cascadeLog struct{ events []secops.Event }

func (l *cascadeLog) Record(e secops.Event) { l.events = append(l.events, e) }

func (l *cascadeLog) withOutcome(want secops.Outcome) []secops.Event {
	var out []secops.Event
	for _, e := range l.events {
		if e.Type == secops.EventUpstreamTimeoutCascade && e.Outcome == want {
			out = append(out, e)
		}
	}
	return out
}

// sendObserved drives the proxy with a recorder installed, as the chain does.
func sendObserved(p *Proxy, route *store.Route, req *http.Request, rec *secops.Recorder) *httptest.ResponseRecorder {
	info := &reqctx.Info{RequestID: "req-cascade-1", TenantID: "acme", TraceID: "trace-cascade-1"}
	ctx := reqctx.WithInfo(req.Context(), info)
	ctx = reqctx.WithRoute(ctx, route)
	ctx = secops.WithRecorder(ctx, rec)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req.WithContext(ctx))
	return w
}

func TestEveryTimedOutAttemptIsRecorded(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(slow.Close)

	log := &cascadeLog{}
	p := testProxy(t, Options{})
	route := routeTo(t, slow.URL, func(r *store.Route) {
		r.Timeout = 40 * time.Millisecond
		r.RetryMax = 2
	})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", nil)

	if got := sendObserved(p, route, req, secops.NewRecorder(secops.Options{Sinks: []secops.Sink{log}})); got.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", got.Code)
	}
	timedOut := log.withOutcome(secops.OutcomeTimedOut)
	if len(timedOut) != 3 {
		t.Fatalf("recorded %d timed_out events, want one per attempt (3)", len(timedOut))
	}
	for i, e := range timedOut {
		if e.Attempt != i+1 {
			t.Errorf("event %d carries attempt %d, want %d", i, e.Attempt, i+1)
		}
		if e.Control != secops.ControlRetryBudget {
			t.Errorf("control = %q, want %q", e.Control, secops.ControlRetryBudget)
		}
		if e.Evidence["upstream_host"] == "" {
			t.Errorf("event has no upstream host: %+v", e)
		}
	}
}

func TestAnOpenBreakerRefusalIsRecorded(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(dead.Close)

	// A breaker that trips on the second failure, so the test does not have
	// to spend twenty attempts getting there.
	cfg := resilience.DefaultBreakerConfig()
	cfg.MinRequests = 2
	log := &cascadeLog{}
	p := testProxy(t, Options{Breakers: resilience.NewBreakerGroup(cfg)})
	route := routeTo(t, dead.URL, func(r *store.Route) {
		r.Timeout = 30 * time.Millisecond
		r.RetryMax = 3
	})
	rec := secops.NewRecorder(secops.Options{Sinks: []secops.Sink{log}})

	sendObserved(p, route, httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", nil), rec)
	got := sendObserved(p, route, httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", nil), rec)

	if got.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 once the breaker is open", got.Code)
	}
	refused := log.withOutcome(secops.OutcomeRejected)
	if len(refused) == 0 {
		t.Fatal("the breaker refused an attempt and nothing recorded it")
	}
	if refused[0].Control != secops.ControlCircuitBreaker {
		t.Errorf("control = %q, want %q", refused[0].Control, secops.ControlCircuitBreaker)
	}
}

// The recovery half of a cascade: the client saw 200, so a status code says
// nothing happened. The event is the only place the fallback is visible.
func TestAHedgeWinCarriesTheFallbackOutcome(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			// The primary: slow enough that the hedge always overtakes it.
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	log := &cascadeLog{}
	p := testProxy(t, Options{HedgingEnabled: true})
	route := routeTo(t, upstream.URL, func(r *store.Route) {
		r.HedgeEnabled = true
		r.HedgeDelay = 20 * time.Millisecond
		r.Timeout = 3 * time.Second
	})

	got := sendObserved(p, route, httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", nil),
		secops.NewRecorder(secops.Options{Sinks: []secops.Sink{log}}))
	if got.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the hedge", got.Code)
	}
	fellBack := log.withOutcome(secops.OutcomeFellBack)
	if len(fellBack) != 1 {
		t.Fatalf("recorded %d fell_back events, want 1", len(fellBack))
	}
	e := fellBack[0]
	if !e.Fallback || !e.Hedged {
		t.Errorf("event does not carry the fallback flags: %+v", e)
	}
	if e.Evidence["fallback_mechanism"] != "hedge" {
		t.Errorf("fallback_mechanism = %q, want hedge", e.Evidence["fallback_mechanism"])
	}
}

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/ratelimit"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/secops"
	"github.com/lgoyal6/tollgate/internal/store"
)

// realTracer installs a tracer provider for the test, because the linkage
// assertion below is about the event carrying the trace id of the request's
// own span, and the global default provider hands out invalid span contexts.
func realTracer(t *testing.T) {
	t.Helper()
	prev := otel.GetTracerProvider()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(t.Context())
	})
}

type eventLog struct{ events []secops.Event }

func (l *eventLog) Record(e secops.Event) { l.events = append(l.events, e) }

func (l *eventLog) ofType(want secops.EventType) []secops.Event {
	var out []secops.Event
	for _, e := range l.events {
		if e.Type == want {
			out = append(out, e)
		}
	}
	return out
}

// secSnapshot has the three key states this file needs and a limiter policy
// tight enough to refuse the third request in a window.
func secSnapshot(t *testing.T) (*store.Snapshot, string, string) {
	t.Helper()
	active, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rotated, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	grace := time.Now().Add(time.Hour)
	snap := store.SnapshotForTest(
		[]*store.Tenant{{
			ID: "acme", Name: "Acme", Enabled: true,
			RLAlgorithm: store.AlgoSlidingWindow, RLWindow: time.Second, RLLimit: 2,
		}},
		[]*store.Route{{
			ID: 1, TenantID: "acme", PathPrefix: "/api/",
			Timeout: time.Second, Upstream: mustURL(t, "http://up.example:9000"),
		}},
		[]*store.APIKey{
			{ID: active.ID, TenantID: "acme", SecretHash: active.SecretHash, Status: store.KeyActive},
			{ID: rotated.ID, TenantID: "acme", SecretHash: rotated.SecretHash, Status: store.KeyGrace, GraceUntil: &grace},
		},
	)
	return snap, active.Plaintext, rotated.Plaintext
}

func secChain(snap *store.Snapshot, rec *secops.Recorder) http.Handler {
	m := observability.NewMetrics()
	snapshots := func() *store.Snapshot { return snap }
	return Chain(okHandler,
		Recover(testLogger),
		secops.Observe(rec),
		RequestID(),
		Metrics(m),
		Tracing("tollgate-test"),
		Auth(snapshots, m, nil),
		Router(snapshots),
		RateLimit(ratelimit.NewMemoryLimiter(), true, m, testLogger),
	)
}

func secRequest(h http.Handler, credential string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	if credential != "" {
		req.Header.Set("X-API-Key", credential)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestARefusedCredentialBecomesOneLinkedEvent(t *testing.T) {
	realTracer(t)
	snap, _, _ := secSnapshot(t)

	tests := []struct {
		name       string
		credential string
		wantReason string
	}{
		{"no credential at all", "", "missing"},
		{"a credential in the wrong shape", "not-a-key", "malformed"},
		{"a key id nothing issued", "tg_kdeadbeef_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "unknown_key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &eventLog{}
			h := secChain(snap, secops.NewRecorder(secops.Options{Sinks: []secops.Sink{log}}))

			if got := secRequest(h, tt.credential).Code; got != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", got)
			}
			events := log.ofType(secops.EventAuthRejected)
			if len(events) != 1 {
				t.Fatalf("emitted %d auth_rejected events, want 1", len(events))
			}
			e := events[0]
			if e.Evidence["reason"] != tt.wantReason {
				t.Errorf("reason = %q, want %q", e.Evidence["reason"], tt.wantReason)
			}
			if e.TenantID != reqctx.UnauthenticatedTenant {
				t.Errorf("tenant = %q, want %q", e.TenantID, reqctx.UnauthenticatedTenant)
			}
			if !e.LinkageComplete() {
				t.Errorf("event is not linkage complete: %+v", e)
			}
			if e.TraceID == "" || e.SpanID == "" {
				t.Errorf("event has no trace linkage: trace=%q span=%q", e.TraceID, e.SpanID)
			}
		})
	}
}

func TestAKeyInItsRotationGraceWindowIsRecorded(t *testing.T) {
	realTracer(t)
	snap, active, rotated := secSnapshot(t)

	log := &eventLog{}
	h := secChain(snap, secops.NewRecorder(secops.Options{Sinks: []secops.Sink{log}}))

	if got := secRequest(h, rotated).Code; got != http.StatusOK {
		t.Fatalf("a grace-window key must still work, got %d", got)
	}
	events := log.ofType(secops.EventKeyRotation)
	if len(events) != 1 {
		t.Fatalf("emitted %d key_rotation events, want 1", len(events))
	}
	if events[0].Outcome != secops.OutcomeAllowed {
		t.Errorf("outcome = %q, want allowed: the grace window admitted it", events[0].Outcome)
	}
	if events[0].TenantID != "acme" || !events[0].LinkageComplete() {
		t.Errorf("event is not linked to the tenant: %+v", events[0])
	}

	// An active key must not look like a rotation.
	if got := secRequest(h, active).Code; got != http.StatusOK {
		t.Fatalf("active key: got %d, want 200", got)
	}
	if got := len(log.ofType(secops.EventKeyRotation)); got != 1 {
		t.Fatalf("an active key produced a key_rotation event (%d total)", got)
	}
}

func TestEachLimiterRefusalIsOneRateBurstEvent(t *testing.T) {
	realTracer(t)
	snap, active, _ := secSnapshot(t)

	log := &eventLog{}
	h := secChain(snap, secops.NewRecorder(secops.Options{Sinks: []secops.Sink{log}}))

	// The policy is 2 per second, so requests three, four and five inside
	// the same window are refused.
	var refused int
	for i := 0; i < 5; i++ {
		if secRequest(h, active).Code == http.StatusTooManyRequests {
			refused++
		}
	}
	events := log.ofType(secops.EventRateBurst)
	if len(events) != refused || refused != 3 {
		t.Fatalf("refused %d requests and emitted %d rate_burst events, want 3 and 3", refused, len(events))
	}
	for _, e := range events {
		if e.Outcome != secops.OutcomeRejected || e.TenantID != "acme" {
			t.Errorf("unexpected event %+v", e)
		}
		if e.Evidence["limit"] != "2" {
			t.Errorf("limit evidence = %q, want 2", e.Evidence["limit"])
		}
		if !e.LinkageComplete() {
			t.Errorf("event is not linkage complete: %+v", e)
		}
	}
}

// The chain must behave identically with no recorder installed: this layer is
// evidence, not policy, and a gateway that had never heard of it answers the
// same way.
func TestTheChainIsUnchangedWithoutARecorder(t *testing.T) {
	realTracer(t)
	snap, active, _ := secSnapshot(t)
	h := secChain(snap, nil)

	if got := secRequest(h, "").Code; got != http.StatusUnauthorized {
		t.Errorf("missing credential = %d, want 401", got)
	}
	if got := secRequest(h, active).Code; got != http.StatusOK {
		t.Errorf("valid key = %d, want 200", got)
	}
}

// A route already in the snapshot pointing at the instance metadata endpoint
// is the case the upsert check cannot cover: the row may predate the check,
// or have arrived by migration or a direct UPDATE. This is the last point
// before the gateway would attach the shared provider credential and send it
// there.
func TestARouteToTheMetadataEndpointIsRefusedAtRequestTime(t *testing.T) {
	realTracer(t)
	active, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	snap := store.SnapshotForTest(
		[]*store.Tenant{{
			ID: "acme", Name: "Acme", Enabled: true,
			RLAlgorithm: store.AlgoSlidingWindow, RLWindow: time.Second, RLLimit: 100,
		}},
		[]*store.Route{
			{ID: 7, TenantID: "acme", PathPrefix: "/meta/", Timeout: time.Second,
				Upstream: mustURL(t, "http://169.254.169.254")},
			{ID: 8, TenantID: "acme", PathPrefix: "/private/", Timeout: time.Second,
				Upstream: mustURL(t, "http://10.4.0.11:8080")},
		},
		[]*store.APIKey{{ID: active.ID, TenantID: "acme", SecretHash: active.SecretHash, Status: store.KeyActive}},
	)

	log := &eventLog{}
	h := secChain(snap, secops.NewRecorder(secops.Options{Sinks: []secops.Sink{log}}))

	req := httptest.NewRequest(http.MethodGet, "/meta/latest/meta-data/", nil)
	req.Header.Set("X-API-Key", active.Plaintext)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body %s", rec.Code, rec.Body)
	}
	events := log.ofType(secops.EventSSRFRejected)
	if len(events) != 1 {
		t.Fatalf("emitted %d ssrf_rejected events, want 1", len(events))
	}
	if events[0].Evidence["upstream_host"] != "169.254.169.254" || !events[0].LinkageComplete() {
		t.Errorf("unexpected event %+v", events[0])
	}

	// A private upstream must not be refused: the kind deployment and the
	// compose stack both proxy to one, and a guard that broke those would be
	// turned off by the first person who hit it.
	req = httptest.NewRequest(http.MethodGet, "/private/thing", nil)
	req.Header.Set("X-API-Key", active.Plaintext)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusBadGateway {
		t.Errorf("a private upstream was refused by the metadata guard")
	}
	if got := len(log.ofType(secops.EventSSRFRejected)); got != 1 {
		t.Errorf("a private upstream produced an ssrf_rejected event (%d total)", got)
	}
}

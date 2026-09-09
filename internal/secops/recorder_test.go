package secops

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/lgoyal6/tollgate/internal/reqctx"
)

// collect is a sink that keeps everything, which is what a test wants and a
// gateway does not.
type collect struct{ events []Event }

func (c *collect) Record(e Event) { c.events = append(c.events, e) }

// tracedContext gives the test a real span, because the thing under test is
// that an event picks up the trace and span id from the live span rather than
// from anywhere else.
func tracedContext(t *testing.T, info *reqctx.Info) (context.Context, oteltrace.Span) {
	t.Helper()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(reqctx.WithInfo(context.Background(), info), "req")
	t.Cleanup(func() { span.End() })
	return ctx, span
}

func fixedClock(start time.Time) func() time.Time {
	return func() time.Time { return start }
}

func TestEmitFillsTheLinkageFieldsFromTheRequest(t *testing.T) {
	sink := &collect{}
	rec := NewRecorder(Options{Sinks: []Sink{sink}, Now: fixedClock(time.Unix(1, 0).UTC())})
	info := &reqctx.Info{RequestID: "req-1", TenantID: "acme", KeyID: "k1", RoutePrefix: "/api/"}
	ctx, span := tracedContext(t, info)

	got := rec.Emit(ctx, Event{Type: EventAuthRejected, Control: ControlAPIKeyVerification, Outcome: OutcomeRejected})

	if len(sink.events) != 1 {
		t.Fatalf("sink got %d events, want 1", len(sink.events))
	}
	if got.ID != 1 {
		t.Errorf("event id = %d, want 1", got.ID)
	}
	if got.RequestID != "req-1" || got.TenantID != "acme" || got.KeyID != "k1" || got.Route != "/api/" {
		t.Errorf("request fields not filled from reqctx: %+v", got)
	}
	if want := span.SpanContext().TraceID().String(); got.TraceID != want {
		t.Errorf("trace_id = %q, want the active span's %q", got.TraceID, want)
	}
	if want := span.SpanContext().SpanID().String(); got.SpanID != want {
		t.Errorf("span_id = %q, want the active span's %q", got.SpanID, want)
	}
	if !got.LinkageComplete() {
		t.Errorf("linkage incomplete on a fully populated event: %+v", got)
	}
}

// A request that never authenticated still has to produce a usable event: a
// burst of refused credentials has no tenant by definition, and an event with
// an empty tenant would be dropped by the linkage check.
func TestAnUnauthenticatedRequestGetsTheLabelNotAnEmptyTenant(t *testing.T) {
	sink := &collect{}
	rec := NewRecorder(Options{Sinks: []Sink{sink}})
	ctx, _ := tracedContext(t, &reqctx.Info{RequestID: "req-2"})

	got := rec.Emit(ctx, Event{Type: EventAuthRejected, Control: ControlAPIKeyVerification, Outcome: OutcomeRejected})
	if got.TenantID != UnauthenticatedTenant {
		t.Fatalf("tenant = %q, want %q", got.TenantID, UnauthenticatedTenant)
	}
	if !got.LinkageComplete() {
		t.Fatalf("an unauthenticated event must still be linkage complete: %+v", got)
	}
}

func TestNilRecorderIsUsable(t *testing.T) {
	var rec *Recorder
	// The whole point of the nil-safety: call sites in the request path are
	// one line with no branch, and a chain built without a recorder records
	// nothing instead of panicking.
	rec.Emit(context.Background(), Event{Type: EventRateBurst})
	rec.NoteTokenUse(context.Background(), "jti:x", "cert:a", time.Now().Add(time.Minute), false)
	rec.NoteSpend(context.Background(), 1, true)
	if got := From(context.Background()); got != nil {
		t.Fatalf("From on a bare context = %v, want nil", got)
	}
}

func TestRecordersShareOneEventIDSequence(t *testing.T) {
	var counter atomic.Int64
	a := NewRecorder(Options{Counter: &counter})
	b := NewRecorder(Options{Counter: &counter})
	ctx := context.Background()

	ids := []int64{
		a.Emit(ctx, Event{Type: EventRateBurst}).ID,
		b.Emit(ctx, Event{Type: EventRateBurst}).ID,
		a.Emit(ctx, Event{Type: EventRateBurst}).ID,
	}
	for i, want := range []int64{1, 2, 3} {
		if ids[i] != want {
			t.Fatalf("ids = %v, want strictly increasing 1,2,3 across both recorders", ids)
		}
	}
}

func TestTheNormalBuildCarriesNoPlantedFault(t *testing.T) {
	if PlantedFaultActive {
		t.Fatal("PlantedFaultActive is true without the secops_planted_fault build tag")
	}
	sink := &collect{}
	rec := NewRecorder(Options{Sinks: []Sink{sink}})
	ctx, _ := tracedContext(t, &reqctx.Info{RequestID: "req-3", TenantID: "acme"})
	got := rec.Emit(ctx, Event{Type: EventCertMismatch, Control: ControlCertificateBinding, Outcome: OutcomeRejected})
	if got.TraceID == "" {
		t.Fatal("cert_mismatch lost its trace id in a build with no planted fault")
	}
}

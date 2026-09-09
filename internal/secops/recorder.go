package secops

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/lgoyal6/tollgate/internal/reqctx"
)

// Sink is somewhere a recorded event goes. Sinks are called in order, on the
// goroutine that emitted, so a sink must be cheap and must not block the
// request path.
type Sink interface {
	Record(Event)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(Event)

func (f SinkFunc) Record(e Event) { f(e) }

// Options configures a Recorder.
type Options struct {
	// Sinks receive every event. A recorder with no sinks still runs its
	// detectors and still writes span events, which is what the gateway wants
	// when nothing is collecting a timeline.
	Sinks []Sink
	// Counter is the shared event-id sequence. Several recorders in one
	// process must share one, or their ids collide in a merged timeline.
	// Nil means this recorder allocates its own.
	Counter *atomic.Int64
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
	// ReplayCapacity bounds the token replay filter. Zero means the package
	// default; see NewReplayFilter.
	ReplayCapacity int
	// Spend configures the provider spend anomaly detector. A zero value
	// disables it, because a detector with no thresholds would fire on
	// everything or nothing depending on which.
	Spend SpendThresholds
}

// Recorder mints events and fans them out. Every method is nil-safe, so a
// call site can be one line with no branch: a request served without a
// recorder installed simply records nothing.
type Recorder struct {
	sinks   []Sink
	counter *atomic.Int64
	own     atomic.Int64
	now     func() time.Time

	replay *ReplayFilter
	spend  *SpendWindows
}

// NewRecorder builds a recorder. The detectors are constructed here rather
// than injected because their state has to live exactly as long as the
// recorder does: a replay filter that outlives its process would be a
// persistence claim this package does not make.
func NewRecorder(opts Options) *Recorder {
	r := &Recorder{sinks: opts.Sinks, now: opts.Now}
	if r.now == nil {
		// UTC, not local. These timestamps end up in a committed artifact and
		// in logs correlated against other hosts' logs, and a local offset in
		// either is one more thing to get wrong at three in the morning.
		r.now = func() time.Time { return time.Now().UTC() }
	}
	r.counter = opts.Counter
	if r.counter == nil {
		r.counter = &r.own
	}
	r.replay = NewReplayFilter(opts.ReplayCapacity)
	if opts.Spend.Enabled() {
		r.spend = NewSpendWindows(opts.Spend)
	}
	return r
}

type recorderKey struct{}

// WithRecorder installs a recorder for the request. Carried in the context
// rather than threaded through every middleware constructor because the
// emission points are spread across four packages, and the alternative is a
// new parameter on Auth, RateLimit, Router, Budget and the proxy, plus every
// call site and test that builds them.
func WithRecorder(ctx context.Context, r *Recorder) context.Context {
	return context.WithValue(ctx, recorderKey{}, r)
}

// From returns the request's recorder, or nil when none is installed. The
// nil is usable: every Recorder method tolerates it.
func From(ctx context.Context) *Recorder {
	r, _ := ctx.Value(recorderKey{}).(*Recorder)
	return r
}

// Observe is the middleware that installs a recorder. It belongs outside
// everything that decides anything, which in the gateway's chain means
// directly inside Recover.
func Observe(r *Recorder) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(WithRecorder(req.Context(), r)))
		})
	}
}

// Emit records one event and returns it as recorded.
//
// The caller supplies what only it knows: the type, the control, the outcome
// and the evidence. Everything that identifies the request is filled in from
// the context here, in one place, so no call site can forget the trace id and
// no two call sites can disagree about what the tenant label is.
func (r *Recorder) Emit(ctx context.Context, e Event) Event {
	if r == nil {
		return e
	}
	e.ID = r.counter.Add(1)
	if e.At.IsZero() {
		e.At = r.now()
	}

	info := reqctx.InfoFrom(ctx)
	if e.RequestID == "" {
		e.RequestID = info.RequestID
	}
	if e.TenantID == "" {
		e.TenantID = info.TenantLabel()
	}
	if e.KeyID == "" {
		e.KeyID = info.KeyID
	}
	if e.Route == "" {
		e.Route = info.RouteLabel()
	}
	if e.Attempt == 0 {
		e.Attempt = info.Attempts
	}
	if !e.Hedged {
		e.Hedged = info.Hedged
	}

	// The span is the authority on trace and span id: reqctx.Info carries the
	// trace id for the access log, but only the live span knows which span
	// this event is attached to, and an event whose span id came from
	// somewhere else would link a trace viewer to the wrong node.
	span := oteltrace.SpanFromContext(ctx)
	if sc := span.SpanContext(); sc.IsValid() {
		e.TraceID = sc.TraceID().String()
		e.SpanID = sc.SpanID().String()
	} else if e.TraceID == "" {
		e.TraceID = info.TraceID
	}

	plantedFault(&e)

	// The same event on the span, so request, tenant, provider attempt,
	// fallback and outcome are one trace rather than a log line beside one.
	if span.IsRecording() {
		span.AddEvent(string(e.Type), oteltrace.WithAttributes(e.attributes()...))
	}
	for _, s := range r.sinks {
		s.Record(e)
	}
	return e
}

func (e Event) attributes() []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Int64("tollgate.secops.event_id", e.ID),
		attribute.String("tollgate.secops.event_type", string(e.Type)),
		attribute.String("tollgate.secops.control", e.Control),
		attribute.String("tollgate.secops.outcome", string(e.Outcome)),
		attribute.String("tollgate.tenant", e.TenantID),
		attribute.String("tollgate.request_id", e.RequestID),
		attribute.String("tollgate.route", e.Route),
		attribute.Int("tollgate.attempt", e.Attempt),
		attribute.Bool("tollgate.hedged", e.Hedged),
		attribute.Bool("tollgate.fallback", e.Fallback),
	}
	if e.KeyID != "" {
		attrs = append(attrs, attribute.String("tollgate.key_id", e.KeyID))
	}
	for k, v := range e.Evidence {
		attrs = append(attrs, attribute.String("tollgate.secops.evidence."+k, v))
	}
	return attrs
}

// LogSink writes each event as one structured line. This is what the gateway
// installs when nothing is collecting a timeline: the events are worth having
// in the log even when nobody is correlating them.
func LogSink(logger *slog.Logger) Sink {
	return SinkFunc(func(e Event) {
		if logger == nil {
			return
		}
		attrs := []any{
			"event_id", e.ID,
			"event_type", string(e.Type),
			"control", e.Control,
			"outcome", string(e.Outcome),
			"request_id", e.RequestID,
			"trace_id", e.TraceID,
			"span_id", e.SpanID,
			"tenant", e.TenantID,
			"route", e.Route,
			"provider_attempt", e.Attempt,
			"hedged", e.Hedged,
			"fallback", e.Fallback,
		}
		if e.KeyID != "" {
			attrs = append(attrs, "key_id", e.KeyID)
		}
		for k, v := range e.Evidence {
			attrs = append(attrs, "evidence_"+k, v)
		}
		logger.Warn("security event", attrs...)
	})
}

// reqctxInfo is the small slice of per-request state the detectors need,
// pulled out so they do not each repeat the label rules.
type requestIdentity struct {
	tenant string
	key    string
}

func reqctxInfo(ctx context.Context) requestIdentity {
	info := reqctx.InfoFrom(ctx)
	return requestIdentity{tenant: info.TenantLabel(), key: info.KeyID}
}

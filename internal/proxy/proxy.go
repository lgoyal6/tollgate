// Package proxy forwards authenticated, admitted requests to the tenant's
// upstream. It is hand-rolled rather than httputil.ReverseProxy because
// retries and hedging need to re-send a request, and ReverseProxy's
// one-shot, streaming design fights that.
package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/lgoyal6/tollgate/internal/limits"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/secops"
	"github.com/lgoyal6/tollgate/internal/store"
)

// Proxy is the terminal handler of the middleware chain.
type Proxy struct {
	transport      http.RoundTripper
	breakers       *resilience.BreakerGroup
	retry          resilience.RetryPolicy
	hedgingEnabled bool
	maxBodyBuffer  int64
	limits         limits.Config
	logger         *slog.Logger
	metrics        *observability.Metrics
	tracer         oteltrace.Tracer
	propagator     propagation.TextMapPropagator
}

type Options struct {
	Breakers       *resilience.BreakerGroup
	HedgingEnabled bool
	MaxBodyBuffer  int64
	MaxIdlePerHost int
	// Limits carries the response size cap, the total request deadline and
	// the retry ceiling. A zero value means each of those is not enforced.
	Limits  limits.Config
	Logger  *slog.Logger
	Metrics *observability.Metrics
}

func New(opts Options) *Proxy {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          4 * opts.MaxIdlePerHost,
		MaxIdleConnsPerHost:   opts.MaxIdlePerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Proxy{
		transport:      transport,
		breakers:       opts.Breakers,
		retry:          resilience.DefaultRetryPolicy(),
		hedgingEnabled: opts.HedgingEnabled,
		maxBodyBuffer:  opts.MaxBodyBuffer,
		limits:         opts.Limits,
		logger:         opts.Logger,
		metrics:        opts.Metrics,
		tracer:         otel.Tracer("tollgate/proxy"),
		propagator:     otel.GetTextMapPropagator(),
	}
}

// errBreakerOpen distinguishes "we refused to try" from transport failures.
var errBreakerOpen = errors.New("proxy: circuit breaker open")

// errCredentialMissing means a route is configured to inject the gateway's own
// credential and the environment does not have it. Retrying cannot fix that,
// and it is counted once rather than once per attempt.
var errCredentialMissing = errors.New("proxy: upstream credential is not set")

// credentialFailure records that the credential the gateway holds on
// everyone's behalf did not work. reason is "missing" or "rejected".
//
// This exists because the alternative is silence: an upstream that refuses the
// shared key answers 401, the gateway relays it, and the only trace is a 4xx
// in the same counter every tenant's own bad request lands in. The value is
// never logged, only the fact and the route.
func (p *Proxy) credentialFailure(route *store.Route, candidate store.Candidate, info *reqctx.Info, reason string, status int) {
	p.metrics.UpstreamCredentialFailures.WithLabelValues(candidate.Upstream.Host, reason).Inc()
	p.logger.Warn("the gateway's own upstream credential did not work",
		"request_id", info.RequestID, "upstream", candidate.Upstream.Host,
		"route", route.ID, "candidate", candidate.Role(), "reason", reason,
		"upstream_status", status, "credential_env", candidate.AuthEnv)
}

// maxAttemptsHardCap bounds attempts regardless of what the route says.
//
// RetryMax is a column in Postgres, so it is whatever an operator (or a bad
// migration, or a direct UPDATE) put there. Measured on this repo's harness, a
// route with retry_max=20 produced 20 upstream attempts and tripped the
// per-host circuit breaker, whose default MinRequests is 20. That breaker is
// shared by every tenant routed to that host, so one row turns a single
// tenant's misconfiguration into everybody's outage. Five attempts is enough
// for the transient-failure case retries exist for; more is amplification.
const maxAttemptsHardCap = 5

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := reqctx.InfoFrom(r.Context())
	plan := p.planFor(r)
	if plan == nil {
		p.fail(w, info, http.StatusInternalServerError, "proxy reached without a route", nil)
		return
	}
	route := plan.Route

	// One deadline for the whole exchange, covering every attempt and every
	// backoff between them. The route timeout alone bounds a single attempt,
	// so without this the real ceiling is route.Timeout multiplied by whatever
	// retry count is in the database, and a request can hold a connection, a
	// concurrency slot and a spend hold for all of it.
	if p.limits.MaxRequestDuration > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), p.limits.MaxRequestDuration)
		defer cancel()
		r = r.WithContext(ctx)
	}

	body, replayable, err := p.bufferBody(r)
	if err != nil {
		p.fail(w, info, http.StatusRequestEntityTooLarge, "request body too large to buffer", err)
		return
	}
	canRepeat := replayable && resilience.IdempotentMethod(r.Method)

	var resp *http.Response
	var release context.CancelFunc
	var chosen store.Candidate
	if p.hedgingEnabled && route.HedgeEnabled && canRepeat {
		// Hedging races two attempts at the primary and is left exactly as it
		// was. Combining it with failover would mean two upstreams and two
		// in-flight attempts sharing one ceiling, and the accounting for that
		// is a bigger change than the one fallback this is.
		chosen = plan.Primary()
		resp, release, err = p.doHedged(r, plan, body)
	} else {
		resp, chosen, release, err = p.doOrderedPlan(r, plan, body, canRepeat)
	}
	if err != nil {
		status, msg := classifyError(err)
		if errors.Is(err, errCredentialMissing) {
			p.credentialFailure(route, chosen, info, "missing", status)
		}
		p.fail(w, info, status, msg, err)
		return
	}
	defer release()
	defer resp.Body.Close()

	// A declared length over the cap is refusable, because nothing has been
	// written yet. This is the only path on which an oversize response can be
	// turned into a clean status rather than a truncated stream.
	if p.limits.MaxResponseBytes > 0 && resp.ContentLength > p.limits.MaxResponseBytes {
		p.metrics.ResponseTruncations.WithLabelValues(chosen.Upstream.Host).Inc()
		p.fail(w, info, http.StatusBadGateway, "upstream response too large", limits.ErrResponseTooLarge)
		return
	}

	// An upstream that refuses a request carrying the gateway's own credential
	// is the observable symptom of that credential having been revoked or
	// expired. The response is still relayed unchanged - the gateway is a
	// proxy, and the upstream may equally be refusing the caller - but it stops
	// being invisible.
	if chosen.InjectsCredential() &&
		(resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		p.credentialFailure(route, chosen, info, "rejected", resp.StatusCode)
	}

	// A request that only succeeded because a backup attempt overtook a slow
	// primary is the recovery half of a cascade, and it is the half that is
	// invisible in a status code: the client saw 200 either way.
	if info.Hedged && resp.StatusCode < 500 {
		secops.From(r.Context()).Emit(r.Context(), secops.Event{
			Type:     secops.EventUpstreamTimeoutCascade,
			Control:  secops.ControlRequestHedge,
			Outcome:  secops.OutcomeFellBack,
			Attempt:  info.Attempts,
			Hedged:   true,
			Fallback: true,
			Evidence: map[string]string{
				"upstream_host":      chosen.Upstream.Host,
				"fallback_mechanism": "hedge",
				"upstream_status":    strconv.Itoa(resp.StatusCode),
			},
		})
	}

	info.Status = resp.StatusCode
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, copyErr := p.copyBody(w, resp)
	info.BytesOut = n
	if errors.Is(copyErr, limits.ErrResponseTooLarge) {
		// The status line is already on the wire, so the client gets a short
		// body and no way to be told why. Stopping is still right: the
		// alternative is relaying an unbounded stream the gateway pays egress
		// on. The counter is what makes this visible.
		p.metrics.ResponseTruncations.WithLabelValues(chosen.Upstream.Host).Inc()
		info.Error = copyErr.Error()
		p.logger.Warn("upstream response truncated at the size limit",
			"request_id", info.RequestID, "upstream", chosen.Upstream.Host,
			"limit", p.limits.MaxResponseBytes, "bytes", n)
		return
	}
	if copyErr != nil && !errors.Is(copyErr, context.Canceled) {
		// Headers are gone; nothing to send the client. Log and move on.
		p.logger.Warn("response body copy interrupted",
			"request_id", info.RequestID, "upstream", chosen.Upstream.Host,
			"bytes", n, "error", copyErr)
	}
}

// planFor returns the ordered plan for this request.
//
// The router installs one. A caller that installed only a route gets the plan
// that route implies, which for a route with no fallback is a single candidate
// -- the same decision the gateway made before plans existed. Deriving it here
// cannot invent an upstream, and it means the proxy has exactly one shape of
// input to reason about.
func (p *Proxy) planFor(r *http.Request) *store.RoutePlan {
	if plan := reqctx.PlanFrom(r.Context()); plan != nil {
		return plan
	}
	if route := reqctx.RouteFrom(r.Context()); route != nil {
		return store.PlanFor(route)
	}
	return nil
}

// attemptCeiling is the total number of upstream attempts this request may
// make, across every candidate in its plan.
//
// One ceiling for the whole request, not one per upstream. A fallback is an
// attempt spent inside the existing budget; giving it a fresh one would double
// what a single request can do to the upstreams it touches, which is the
// amplification maxAttemptsHardCap exists to prevent.
func attemptCeiling(route *store.Route, canRepeat bool) int {
	attempts := 1
	if canRepeat && route.RetryMax > 0 {
		attempts = 1 + route.RetryMax
	}
	if attempts > maxAttemptsHardCap {
		attempts = maxAttemptsHardCap
	}
	return attempts
}

// candidateResult is what one upstream produced.
//
// transient distinguishes "here is the answer" from "here is a 502/503/504 I
// have run out of retries for". The second is still relayable - it is what the
// client would have received before failover existed - but it is also the one
// shape of response that may be abandoned in favour of the next candidate.
type candidateResult struct {
	resp      *http.Response
	cancel    context.CancelFunc
	transient bool
	err       error
}

// doOrderedPlan walks the plan's candidates in order, spending one shared
// attempt budget across all of them.
func (p *Proxy) doOrderedPlan(r *http.Request, plan *store.RoutePlan, body []byte, canRepeat bool) (*http.Response, store.Candidate, context.CancelFunc, error) {
	info := reqctx.InfoFrom(r.Context())
	ceiling := attemptCeiling(plan.Route, canRepeat)

	// The primary's refusal, kept rather than discarded. Throwing it away
	// before trying the fallback would be tidier, but it is the exact response
	// the client received before this change, and a fallback that also fails
	// would then turn a relayed 503 into a manufactured 502.
	var held candidateResult
	var heldBy store.Candidate
	var lastErr error

	for i, candidate := range plan.Candidates {
		if i > 0 {
			reason, ok := failoverReason(r, canRepeat, ceiling-info.Attempts, held, lastErr)
			if !ok {
				break
			}
			p.noteFailover(r, plan, candidate, reason)
		}

		allowed := ceiling - info.Attempts
		if i == 0 && plan.HasFallback() && canRepeat && allowed > 1 {
			// Hold one attempt of the shared ceiling back for the fallback.
			//
			// Without this the primary spends the whole budget retrying itself
			// and the fallback is configuration that can never fire - which is
			// worse than not having the feature, because the console says the
			// route has a standby and it does not. The ceiling itself is
			// untouched: this decides how the existing attempts are divided,
			// not how many there are.
			//
			// Only when there is more than one to divide. A route whose
			// ceiling is a single attempt gives it to the primary; reserving
			// out of one would leave the primary with none and turn a
			// misconfigured fallback into a route that contacts nothing.
			allowed--
		}

		res := p.sendTo(r, plan, candidate, body, canRepeat, allowed)
		switch {
		case res.resp != nil && !res.transient:
			drainClose(held)
			info.Upstream = candidate.Upstream.Host
			info.Fallback = candidate.Fallback
			return res.resp, candidate, res.cancel, nil
		case res.resp != nil && held.resp == nil:
			held, heldBy = res, candidate
		case res.resp != nil:
			drainClose(res)
		}
		if res.err != nil {
			lastErr = res.err
		}
	}

	if held.resp != nil {
		info.Upstream = heldBy.Upstream.Host
		info.Fallback = heldBy.Fallback
		return held.resp, heldBy, held.cancel, nil
	}
	return nil, plan.Primary(), nil, lastErr
}

// sendTo spends up to `allowed` attempts on one candidate.
func (p *Proxy) sendTo(r *http.Request, plan *store.RoutePlan, candidate store.Candidate, body []byte, canRepeat bool, allowed int) candidateResult {
	info := reqctx.InfoFrom(r.Context())
	if allowed < 1 {
		return candidateResult{err: fmt.Errorf("no attempts left for %s", candidate.Upstream.Host)}
	}

	var lastErr error
	for attempt := 0; attempt < allowed; attempt++ {
		if attempt > 0 {
			p.metrics.Retries.Inc()
			backoff := p.retry.Backoff(attempt)
			select {
			case <-r.Context().Done():
				return candidateResult{err: r.Context().Err()}
			case <-time.After(backoff):
			}
		}

		actx, cancel := context.WithTimeout(r.Context(), candidate.Timeout)
		resp, err := p.attempt(actx, r, plan, candidate, body, attempt)
		info.Attempts++

		if err != nil {
			cancel()
			lastErr = err
			p.recordAttemptFailure(r, plan.Route, candidate, info.Attempts, allowed, err)
			if errors.Is(err, errBreakerOpen) || errors.Is(err, errCredentialMissing) || !canRepeat {
				// Breaker open, or a credential that is not in the
				// environment: more attempts at this upstream would hit the
				// same wall.
				return candidateResult{err: err}
			}
			continue
		}
		if canRepeat && attempt < allowed-1 && resilience.RetryableStatus(resp.StatusCode) {
			// Transient upstream failure with budget left: drain a little so
			// the connection can be reused, then retry.
			io.CopyN(io.Discard, resp.Body, 4096) //nolint:errcheck
			resp.Body.Close()
			cancel()
			lastErr = fmt.Errorf("upstream returned %d", resp.StatusCode)
			continue
		}
		return candidateResult{
			resp:      resp,
			cancel:    cancel,
			transient: resilience.RetryableStatus(resp.StatusCode),
		}
	}
	return candidateResult{err: fmt.Errorf("all %d attempts failed: %w", allowed, lastErr)}
}

// failoverReason decides whether the next candidate may be tried, and says why
// in a phrase fit for a log line.
//
// The list of things that do *not* qualify is the interesting half:
//
//   - a non-idempotent method, or a body that was never buffered. Both arrive
//     here as canRepeat=false. An LLM completion is a POST that may already
//     have been generated and billed upstream, and a stream the gateway did not
//     keep cannot be sent a second time regardless of method.
//   - a cancelled client context, or a request past its total deadline. Both
//     show up as r.Context().Err(). Spending somebody else's upstream on a
//     request nobody is waiting for is the cascade this gateway exists to
//     avoid.
//   - anything the upstream actually answered that is not 502, 503 or 504. A
//     401 means the credential is wrong, a 403 means the caller may not, a 429
//     means slow down, and a 400 means the request is bad. Asking a second
//     provider the same question gets the same answer, one more time, from
//     somebody else's quota.
//   - a credential the gateway does not have. That is this gateway's own
//     misconfiguration, and a second upstream is not the fix for it.
//   - no attempts left inside the shared ceiling.
func failoverReason(r *http.Request, canRepeat bool, remaining int, held candidateResult, lastErr error) (string, bool) {
	if !canRepeat || remaining < 1 || r.Context().Err() != nil {
		return "", false
	}
	switch {
	case held.resp != nil && held.transient:
		return "primary answered " + strconv.Itoa(held.resp.StatusCode), true
	case errors.Is(lastErr, errBreakerOpen):
		return "primary circuit breaker open", true
	case errors.Is(lastErr, errCredentialMissing):
		return "", false
	case lastErr != nil:
		return "primary transport failure", true
	}
	return "", false
}

// noteFailover records the switch. Hosts and a reason, never a credential, a
// URL query or a byte of the request.
func (p *Proxy) noteFailover(r *http.Request, plan *store.RoutePlan, to store.Candidate, reason string) {
	info := reqctx.InfoFrom(r.Context())
	p.logger.Info("failing over to the route's fallback upstream",
		"request_id", info.RequestID, "route", plan.Route.ID,
		"candidate_order", plan.Order(), "from", plan.Primary().Upstream.Host,
		"to", to.Upstream.Host, "reason", reason, "attempts_used", info.Attempts)
}

// drainClose gives a response the gateway has decided not to relay back to the
// connection pool, reading a little so the connection can be reused.
func drainClose(res candidateResult) {
	if res.resp == nil {
		return
	}
	io.CopyN(io.Discard, res.resp.Body, 4096) //nolint:errcheck
	res.resp.Body.Close()
	if res.cancel != nil {
		res.cancel()
	}
}

// recordAttemptFailure records the two upstream failures that make up a
// cascade: an attempt that ran out of time, and an attempt the breaker
// refused to make.
//
// Everything else is left alone on purpose. A 502 from an upstream that
// answered is that upstream's business and already in the RED metrics; the
// two below are the ones that compound, because a timeout holds a
// connection, a concurrency slot and a spend hold for its whole duration,
// and a breaker refusal is the gateway declaring an upstream unusable for
// every tenant sharing it.
func (p *Proxy) recordAttemptFailure(r *http.Request, route *store.Route, candidate store.Candidate, attempt, allowed int, err error) {
	var control string
	var outcome secops.Outcome
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		control, outcome = secops.ControlRetryBudget, secops.OutcomeTimedOut
	case errors.Is(err, errBreakerOpen):
		control, outcome = secops.ControlCircuitBreaker, secops.OutcomeRejected
	default:
		return
	}
	secops.From(r.Context()).Emit(r.Context(), secops.Event{
		Type:    secops.EventUpstreamTimeoutCascade,
		Control: control,
		Outcome: outcome,
		Attempt: attempt,
		Evidence: map[string]string{
			"upstream_host":    candidate.Upstream.Host,
			"attempts_allowed": strconv.Itoa(allowed),
			"route_timeout_ms": strconv.FormatInt(candidate.Timeout.Milliseconds(), 10),
		},
	})
}

// doHedged races two attempts at the plan's primary, one of them delayed.
//
// The fallback is not involved. Hedging is already two in-flight attempts at
// one upstream; adding a second upstream to that would need both to share the
// one attempt ceiling while racing, and the plan exists to make failover
// legible rather than to make hedging cleverer.
func (p *Proxy) doHedged(r *http.Request, plan *store.RoutePlan, body []byte) (*http.Response, context.CancelFunc, error) {
	info := reqctx.InfoFrom(r.Context())
	route := plan.Route
	primary := plan.Primary()
	hctx, hcancel := context.WithTimeout(r.Context(), primary.Timeout)

	result, release := resilience.Hedge(hctx, route.HedgeDelay, func(actx context.Context, attempt int) (*http.Response, error) {
		if attempt > 0 {
			p.metrics.Hedges.Inc()
		}
		return p.attempt(actx, r, plan, primary, body, attempt)
	})

	info.Hedged = result.Hedged
	info.Attempts = 1
	if result.Hedged {
		info.Attempts = 2
	}
	if result.Err != nil {
		release()
		hcancel()
		return nil, nil, result.Err
	}
	if result.Attempt == 1 {
		p.metrics.HedgeWins.Inc()
	}
	return result.Resp, func() { release(); hcancel() }, nil
}

// attempt performs one upstream exchange with one candidate, under that
// candidate's own breaker.
//
// The breaker is keyed on the host, so a fallback gets its own: a primary the
// gateway has given up on must not drag its standby down with it, which is the
// whole reason the standby is there.
func (p *Proxy) attempt(ctx context.Context, r *http.Request, plan *store.RoutePlan, candidate store.Candidate, body []byte, attempt int) (*http.Response, error) {
	breaker := p.breakers.For(candidate.Upstream.Host)
	done, err := breaker.Allow()
	if err != nil {
		return nil, errBreakerOpen
	}

	out, err := p.outboundRequest(ctx, r, plan.Route, candidate, body)
	if err != nil {
		done(true) // request construction failure says nothing about upstream health
		return nil, fmt.Errorf("building upstream request: %w", err)
	}

	ctx, span := p.tracer.Start(ctx, "proxy "+candidate.Upstream.Host,
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("http.method", out.Method),
			attribute.String("http.url", redactedURL(out.URL)),
			attribute.String("tollgate.upstream", candidate.Upstream.Host),
			attribute.Int("tollgate.attempt", attempt),
			// The order that was decided, and which element of it this is.
			// Hosts only: redactedURL exists because several providers take
			// their key in a query parameter, and a span attribute is the one
			// place a secret escapes without anybody noticing.
			attribute.String("tollgate.candidate_order", plan.Order()),
			attribute.String("tollgate.candidate", candidate.Role()),
		),
	)
	defer span.End()
	out = out.WithContext(ctx)
	// Traces must continue in the upstream service.
	p.propagator.Inject(ctx, propagation.HeaderCarrier(out.Header))

	start := time.Now()
	resp, err := p.transport.RoundTrip(out)
	elapsed := time.Since(start)

	if err != nil {
		done(false)
		span.SetStatus(codes.Error, err.Error())
		p.metrics.UpstreamDuration.WithLabelValues(candidate.Upstream.Host, "error").Observe(elapsed.Seconds())
		return nil, fmt.Errorf("upstream %s: %w", candidate.Upstream.Host, err)
	}

	done(resp.StatusCode < 500)
	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
	if resp.StatusCode >= 500 {
		span.SetStatus(codes.Error, http.StatusText(resp.StatusCode))
	}
	p.metrics.UpstreamDuration.WithLabelValues(candidate.Upstream.Host, observability.CodeClass(resp.StatusCode)).Observe(elapsed.Seconds())
	return resp, nil
}

// outboundRequest clones the inbound request toward one candidate upstream.
//
// This is the boundary the route plan does not cross. The plan says which
// upstream and in what order; everything below - the body, the credential, the
// connection - stays here, where it always was.
func (p *Proxy) outboundRequest(ctx context.Context, r *http.Request, route *store.Route, candidate store.Candidate, body []byte) (*http.Request, error) {
	target := targetURL(candidate.Upstream, route, r.URL)

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else if r.Body != nil && r.ContentLength != 0 {
		bodyReader = r.Body
	}

	out, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		out.ContentLength = int64(len(body))
	} else {
		out.ContentLength = r.ContentLength
	}

	copyHeaders(out.Header, r.Header)

	// Shared-upstream credential injection (e.g. the team's real Anthropic
	// key): the caller authenticated with their own gateway key, which the
	// auth middleware already stripped; here the route's provider credential
	// is attached from the gateway's environment. Missing configuration
	// fails loud rather than forwarding unauthenticated.
	//
	// Per candidate, never shared. A fallback is usually a different provider
	// with a different key, so reusing the primary's environment variable would
	// send one provider's credential to another one.
	if candidate.InjectsCredential() {
		secret := os.Getenv(candidate.AuthEnv)
		if secret == "" {
			return nil, fmt.Errorf("route %d %s: %w", route.ID, candidate.Role(), errCredentialMissing)
		}
		out.Header.Set(candidate.AuthHeader, candidate.AuthPrefix+secret)
	}

	out.Header.Set("X-Forwarded-Host", r.Host)
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	out.Header.Set("X-Forwarded-Proto", proto)
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		prior := r.Header.Get("X-Forwarded-For")
		if prior != "" {
			clientIP = prior + ", " + clientIP
		}
		out.Header.Set("X-Forwarded-For", clientIP)
	}
	info := reqctx.InfoFrom(r.Context())
	out.Header.Set("X-Request-Id", info.RequestID)
	out.Header.Set("X-Tollgate-Tenant", info.TenantID)
	return out, nil
}

// redactedURL renders an upstream URL for a span attribute with the two
// credential-bearing parts of a URL removed: userinfo, which is how an
// operator points a route at a basic-auth upstream, and query parameter
// values, which is how several providers take their API key.
//
// A trace backend is a different trust domain from the gateway's environment,
// and a span attribute is the one place a secret escapes without anyone
// noticing, because nothing about a trace looks like a credential store.
// Parameter names survive: knowing which were sent is most of what makes the
// attribute worth exporting, and the name is not the secret.
func redactedURL(u *url.URL) string {
	safe := *u
	safe.User = nil
	if safe.RawQuery != "" {
		q := safe.Query()
		for k := range q {
			q[k] = []string{"REDACTED"}
		}
		safe.RawQuery = q.Encode()
	}
	return safe.String()
}

// targetURL joins one candidate's base with the (optionally stripped) path.
// Path handling is the route's, so both candidates see the same path.
func targetURL(upstream *url.URL, route *store.Route, in *url.URL) *url.URL {
	target := *upstream
	path := in.EscapedPath()
	if route.StripPrefix {
		path = strings.TrimPrefix(path, strings.TrimSuffix(route.PathPrefix, "/"))
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}
	target.Path = strings.TrimSuffix(target.Path, "/") + path
	target.RawQuery = in.RawQuery
	return &target
}

// bufferBody reads small bodies into memory so attempts can replay them.
// Returns (nil, true) for bodiless requests, (nil, false) for streams too
// large or of unknown length, and an error only when a declared length lied.
func (p *Proxy) bufferBody(r *http.Request) ([]byte, bool, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return nil, true, nil
	}
	if r.ContentLength < 0 || r.ContentLength > p.maxBodyBuffer {
		return nil, false, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, p.maxBodyBuffer+1))
	if err != nil {
		return nil, false, fmt.Errorf("reading request body: %w", err)
	}
	if int64(len(body)) > p.maxBodyBuffer {
		return nil, false, fmt.Errorf("body exceeds %d byte buffer limit", p.maxBodyBuffer)
	}
	return body, true, nil
}

// copyBody streams the upstream response to the client, flushing eagerly
// when the length is unknown (SSE and friends).
func (p *Proxy) copyBody(w http.ResponseWriter, resp *http.Response) (int64, error) {
	src := io.Reader(resp.Body)
	capped := p.limits.MaxResponseBytes > 0
	if capped {
		// One byte past the cap, so a response of exactly the cap still ends
		// on EOF and only cap+1 counts as over.
		src = io.LimitReader(resp.Body, p.limits.MaxResponseBytes+1)
	}
	if resp.ContentLength >= 0 {
		// A declared length over the cap was already refused before the
		// header went out, so this only catches an upstream that sent more
		// than it declared.
		n, err := io.Copy(w, src)
		if capped && n > p.limits.MaxResponseBytes {
			return n, limits.ErrResponseTooLarge
		}
		return n, err
	}
	rc := http.NewResponseController(w)
	var total int64
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if capped && total+int64(n) > p.limits.MaxResponseBytes {
				// Write only the part that fits, then stop: a streamed
				// response has no declared length, so this is the first point
				// at which the gateway can know it is over.
				keep := p.limits.MaxResponseBytes - total
				w.Write(buf[:keep]) //nolint:errcheck // the connection is being abandoned anyway
				return p.limits.MaxResponseBytes, limits.ErrResponseTooLarge
			}
			wn, werr := w.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
			rc.Flush() //nolint:errcheck // best-effort streaming
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

func (p *Proxy) fail(w http.ResponseWriter, info *reqctx.Info, status int, msg string, err error) {
	if err != nil {
		info.Error = err.Error()
	} else {
		info.Error = msg
	}
	info.Status = status
	p.logger.Warn("proxy error",
		"request_id", info.RequestID, "status", status, "msg", msg, "error", info.Error)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q,"request_id":%q}`+"\n", msg, info.RequestID)
}

// classifyError maps transport failures to gateway status codes.
func classifyError(err error) (int, string) {
	switch {
	case errors.Is(err, limits.ErrRequestTooLarge):
		// A chunked upload declares no length, so the cap can only fire while
		// the body is being read - which here means while it is being sent
		// upstream. 413 is still the honest answer to the client.
		return http.StatusRequestEntityTooLarge, "request body too large"
	case errors.Is(err, errBreakerOpen):
		return http.StatusServiceUnavailable, "upstream unavailable (circuit open)"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "upstream timeout"
	case errors.Is(err, context.Canceled):
		return 499, "client closed request"
	default:
		return http.StatusBadGateway, "upstream error"
	}
}

// hopByHop are connection-scoped headers that must not be forwarded.
var hopByHop = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func copyHeaders(dst, src http.Header) {
	// Headers named by Connection are hop-by-hop too (RFC 7230 §6.1).
	dynamic := map[string]struct{}{}
	for _, v := range src.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			dynamic[http.CanonicalHeaderKey(strings.TrimSpace(name))] = struct{}{}
		}
	}
	for k, vv := range src {
		if _, drop := hopByHop[k]; drop {
			continue
		}
		if _, drop := dynamic[k]; drop {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

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
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

// Proxy is the terminal handler of the middleware chain.
type Proxy struct {
	transport      http.RoundTripper
	breakers       *resilience.BreakerGroup
	retry          resilience.RetryPolicy
	hedgingEnabled bool
	maxBodyBuffer  int64
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
	Logger         *slog.Logger
	Metrics        *observability.Metrics
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
		logger:         opts.Logger,
		metrics:        opts.Metrics,
		tracer:         otel.Tracer("tollgate/proxy"),
		propagator:     otel.GetTextMapPropagator(),
	}
}

// errBreakerOpen distinguishes "we refused to try" from transport failures.
var errBreakerOpen = errors.New("proxy: circuit breaker open")

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := reqctx.InfoFrom(r.Context())
	route := reqctx.RouteFrom(r.Context())
	if route == nil {
		p.fail(w, info, http.StatusInternalServerError, "proxy reached without a route", nil)
		return
	}

	body, replayable, err := p.bufferBody(r)
	if err != nil {
		p.fail(w, info, http.StatusRequestEntityTooLarge, "request body too large to buffer", err)
		return
	}
	canRepeat := replayable && resilience.IdempotentMethod(r.Method)

	var resp *http.Response
	var release context.CancelFunc
	if p.hedgingEnabled && route.HedgeEnabled && canRepeat {
		resp, release, err = p.doHedged(r, route, body)
	} else {
		resp, release, err = p.doWithRetries(r, route, body, canRepeat)
	}
	if err != nil {
		status, msg := classifyError(err)
		p.fail(w, info, status, msg, err)
		return
	}
	defer release()
	defer resp.Body.Close()

	info.Status = resp.StatusCode
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, copyErr := p.copyBody(w, resp)
	info.BytesOut = n
	if copyErr != nil && !errors.Is(copyErr, context.Canceled) {
		// Headers are gone; nothing to send the client. Log and move on.
		p.logger.Warn("response body copy interrupted",
			"request_id", info.RequestID, "upstream", route.Upstream.Host,
			"bytes", n, "error", copyErr)
	}
}

// doWithRetries sends the request up to 1+RetryMax times. Non-idempotent or
// unbuffered requests get exactly one attempt.
func (p *Proxy) doWithRetries(r *http.Request, route *store.Route, body []byte, canRepeat bool) (*http.Response, context.CancelFunc, error) {
	info := reqctx.InfoFrom(r.Context())
	attempts := 1
	if canRepeat && route.RetryMax > 0 {
		attempts = 1 + route.RetryMax
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			p.metrics.Retries.Inc()
			backoff := p.retry.Backoff(attempt)
			select {
			case <-r.Context().Done():
				return nil, nil, r.Context().Err()
			case <-time.After(backoff):
			}
		}

		actx, cancel := context.WithTimeout(r.Context(), route.Timeout)
		resp, err := p.attempt(actx, r, route, body, attempt)
		info.Attempts = attempt + 1

		if err != nil {
			cancel()
			lastErr = err
			if errors.Is(err, errBreakerOpen) || !canRepeat {
				// Breaker open: more attempts would hit the same wall.
				return nil, nil, err
			}
			continue
		}
		if canRepeat && attempt < attempts-1 && resilience.RetryableStatus(resp.StatusCode) {
			// Transient upstream failure with budget left: drain a little so
			// the connection can be reused, then retry.
			io.CopyN(io.Discard, resp.Body, 4096) //nolint:errcheck
			resp.Body.Close()
			cancel()
			lastErr = fmt.Errorf("upstream returned %d", resp.StatusCode)
			continue
		}
		return resp, cancel, nil
	}
	return nil, nil, fmt.Errorf("all %d attempts failed: %w", attempts, lastErr)
}

// doHedged races a primary against one delayed backup attempt.
func (p *Proxy) doHedged(r *http.Request, route *store.Route, body []byte) (*http.Response, context.CancelFunc, error) {
	info := reqctx.InfoFrom(r.Context())
	hctx, hcancel := context.WithTimeout(r.Context(), route.Timeout)

	result, release := resilience.Hedge(hctx, route.HedgeDelay, func(actx context.Context, attempt int) (*http.Response, error) {
		if attempt > 0 {
			p.metrics.Hedges.Inc()
		}
		return p.attempt(actx, r, route, body, attempt)
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

// attempt performs one upstream exchange under the breaker.
func (p *Proxy) attempt(ctx context.Context, r *http.Request, route *store.Route, body []byte, attempt int) (*http.Response, error) {
	breaker := p.breakers.For(route.Upstream.Host)
	done, err := breaker.Allow()
	if err != nil {
		return nil, errBreakerOpen
	}

	out, err := p.outboundRequest(ctx, r, route, body)
	if err != nil {
		done(true) // request construction failure says nothing about upstream health
		return nil, fmt.Errorf("building upstream request: %w", err)
	}

	ctx, span := p.tracer.Start(ctx, "proxy "+route.Upstream.Host,
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("http.method", out.Method),
			attribute.String("http.url", out.URL.String()),
			attribute.String("tollgate.upstream", route.Upstream.Host),
			attribute.Int("tollgate.attempt", attempt),
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
		p.metrics.UpstreamDuration.WithLabelValues(route.Upstream.Host, "error").Observe(elapsed.Seconds())
		return nil, fmt.Errorf("upstream %s: %w", route.Upstream.Host, err)
	}

	done(resp.StatusCode < 500)
	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
	if resp.StatusCode >= 500 {
		span.SetStatus(codes.Error, http.StatusText(resp.StatusCode))
	}
	p.metrics.UpstreamDuration.WithLabelValues(route.Upstream.Host, observability.CodeClass(resp.StatusCode)).Observe(elapsed.Seconds())
	return resp, nil
}

// outboundRequest clones the inbound request toward the upstream.
func (p *Proxy) outboundRequest(ctx context.Context, r *http.Request, route *store.Route, body []byte) (*http.Request, error) {
	target := targetURL(route, r.URL)

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
	if route.InjectsCredential() {
		secret := os.Getenv(route.UpstreamAuthEnv)
		if secret == "" {
			return nil, fmt.Errorf("route %d: upstream credential env %s is not set", route.ID, route.UpstreamAuthEnv)
		}
		out.Header.Set(route.UpstreamAuthHeader, route.UpstreamAuthPrefix+secret)
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

// targetURL joins the upstream base with the (optionally stripped) path.
func targetURL(route *store.Route, in *url.URL) *url.URL {
	target := *route.Upstream
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
	if resp.ContentLength >= 0 {
		return io.Copy(w, resp.Body)
	}
	rc := http.NewResponseController(w)
	var total int64
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
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

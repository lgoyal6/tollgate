// Package middleware is the gateway's request pipeline. Order matters:
//
//	Recover -> RequestID -> AccessLog -> Metrics -> Tracing
//	        -> Auth -> Router -> RateLimit -> proxy
//
// Auth runs before RateLimit because limits are per tenant, and the tenant
// comes from the key. RateLimit runs before the proxy so rejected requests
// never consume upstream capacity.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/jwt"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/ratelimit"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/store"
)

// Middleware is the standard wrapping shape.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares so the first listed is outermost.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// statusWriter records what was written for logging and metrics.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Unwrap lets http.NewResponseController reach Flush on the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// writeJSONError is the single error-response shape for everything the
// gateway itself rejects.
func writeJSONError(w http.ResponseWriter, info *reqctx.Info, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":      msg,
		"request_id": info.RequestID,
	})
}

// Recover is the outermost layer: request-path code must not panic, and if
// something does anyway the client gets a 500 instead of a dropped
// connection, and we get a stack trace.
func Recover(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel by identity
						panic(rec)
					}
					info := reqctx.InfoFrom(r.Context())
					logger.Error("panic in request path",
						"panic", fmt.Sprint(rec),
						"request_id", info.RequestID,
						"path", r.URL.Path,
					)
					writeJSONError(w, info, http.StatusInternalServerError, "internal error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID installs reqctx.Info, honouring an inbound X-Request-Id so IDs
// correlate across hops, and echoes the ID on the response.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-Id")
			if id == "" || len(id) > 128 {
				id = newRequestID()
			}
			info := &reqctx.Info{RequestID: id}
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r.WithContext(reqctx.WithInfo(r.Context(), info)))
		})
	}
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the process is in serious trouble; a
		// degraded ID is still better than refusing traffic.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// AccessLog emits one structured line per request (sampled 1-in-n).
func AccessLog(logger *slog.Logger, enabled bool, sample int) Middleware {
	var counter atomic.Int64
	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)

			if sample > 1 && counter.Add(1)%int64(sample) != 0 {
				return
			}
			info := reqctx.InfoFrom(r.Context())
			logger.LogAttrs(r.Context(), slog.LevelInfo, "request",
				slog.String("request_id", info.RequestID),
				slog.String("trace_id", info.TraceID),
				slog.String("tenant", info.TenantLabel()),
				slog.String("route", info.RouteLabel()),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sw.status),
				slog.Int64("bytes", sw.bytes),
				slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000),
				slog.String("upstream", info.Upstream),
				slog.Int("attempts", info.Attempts),
				slog.Bool("hedged", info.Hedged),
				slog.Bool("rate_limited", info.RateLimited),
				slog.String("error", info.Error),
			)
		})
	}
}

// Metrics records the RED signals per tenant and route.
func Metrics(m *observability.Metrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			m.InFlight.Inc()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			m.InFlight.Dec()

			info := reqctx.InfoFrom(r.Context())
			code := observability.CodeClass(sw.status)
			tenant, route := info.TenantLabel(), info.RouteLabel()
			m.RequestsTotal.WithLabelValues(tenant, route, r.Method, code).Inc()
			m.RequestDuration.WithLabelValues(tenant, route, r.Method, code).
				Observe(time.Since(start).Seconds())
		})
	}
}

// Tracing continues an inbound W3C trace (or starts a new one) and records
// the request as a server span.
func Tracing(serviceName string) Middleware {
	tracer := otel.Tracer(serviceName)
	propagator := otel.GetTextMapPropagator()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			ctx, span := tracer.Start(ctx, r.Method+" "+r.URL.Path,
				oteltrace.WithSpanKind(oteltrace.SpanKindServer),
				oteltrace.WithAttributes(
					attribute.String("http.method", r.Method),
					attribute.String("http.target", r.URL.Path),
					attribute.String("http.host", r.Host),
				),
			)
			defer span.End()

			info := reqctx.InfoFrom(ctx)
			if sc := span.SpanContext(); sc.HasTraceID() {
				info.TraceID = sc.TraceID().String()
			}
			span.SetAttributes(attribute.String("tollgate.request_id", info.RequestID))

			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r.WithContext(ctx))

			span.SetAttributes(
				attribute.Int("http.status_code", sw.status),
				attribute.String("tollgate.tenant", info.TenantLabel()),
			)
			if sw.status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(sw.status))
			}
		})
	}
}

// Auth authenticates the caller, resolves the tenant, and enforces scopes
// later at routing time (the scope lives on the route).
//
// Two credential types, told apart by shape rather than by trying both: a
// tollgate key is tg_<id>_<secret> and a JWS is three dot-separated segments,
// so the discriminator is unambiguous and neither path can be used as an
// oracle for the other. A nil tokens argument turns the OIDC path off
// entirely.
func Auth(snapshots func() *store.Snapshot, m *observability.Metrics, tokens *TokenAuth) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := reqctx.InfoFrom(r.Context())
			raw := credentialFrom(r)
			if raw == "" {
				m.AuthFailures.WithLabelValues("missing").Inc()
				writeJSONError(w, info, http.StatusUnauthorized, "missing API key")
				return
			}
			snap := snapshots()
			if snap == nil {
				// No config loaded yet; readiness should have kept traffic
				// away, but never authenticate against nothing.
				writeJSONError(w, info, http.StatusServiceUnavailable, "gateway warming up")
				return
			}

			var (
				tenant     *store.Tenant
				key        *store.APIKey
				deprecated bool
				graceUntil *time.Time
			)
			if tokens != nil && jwt.LooksLikeJWT(raw) {
				verified, err := tokens.verify(r.Context(), raw, bindingFor(r))
				if err == nil {
					tenant, key, err = tokenVerdict(snap, verified)
				}
				if err != nil {
					m.AuthFailures.WithLabelValues(tokenFailureReason(err)).Inc()
					writeJSONError(w, info, http.StatusUnauthorized, "invalid credential")
					return
				}
			} else {
				verdict, err := auth.Verify(snap, raw, time.Now())
				if err != nil {
					m.AuthFailures.WithLabelValues(authFailureReason(err)).Inc()
					// One opaque message for every failure mode: never confirm
					// whether a key id exists or is merely revoked.
					writeJSONError(w, info, http.StatusUnauthorized, "invalid API key")
					return
				}
				tenant, key = verdict.Tenant, verdict.Key
				deprecated, graceUntil = verdict.Deprecated, verdict.Key.GraceUntil
			}

			info.TenantID = tenant.ID
			info.KeyID = key.ID
			if deprecated {
				info.KeyDeprecated = true
				w.Header().Set("X-Api-Key-Deprecated", "true")
				if graceUntil != nil {
					w.Header().Set("X-Api-Key-Grace-Until", graceUntil.UTC().Format(time.RFC3339))
				}
			}

			// The gateway credential must not leak to upstreams.
			r.Header.Del("Authorization")
			r.Header.Del("X-API-Key")

			ctx := reqctx.WithTenant(r.Context(), tenant)
			ctx = reqctx.WithKey(ctx, key)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func credentialFrom(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		const prefix = "Bearer "
		if len(h) > len(prefix) && h[:len(prefix)] == prefix {
			return h[len(prefix):]
		}
		return ""
	}
	return r.Header.Get("X-API-Key")
}

func authFailureReason(err error) string {
	switch {
	case errors.Is(err, auth.ErrMalformed):
		return "malformed"
	case errors.Is(err, auth.ErrUnknownKey):
		return "unknown_key"
	case errors.Is(err, auth.ErrBadSecret):
		return "bad_secret"
	case errors.Is(err, auth.ErrRevoked):
		return "revoked"
	case errors.Is(err, auth.ErrGraceExpired):
		return "grace_expired"
	case errors.Is(err, auth.ErrTenantDisabled):
		return "tenant_disabled"
	default:
		return "other"
	}
}

// Router resolves the tenant's route for the path and enforces the route's
// required scope.
func Router(snapshots func() *store.Snapshot) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := reqctx.InfoFrom(r.Context())
			tenant := reqctx.TenantFrom(r.Context())
			key := reqctx.KeyFrom(r.Context())
			if tenant == nil || key == nil {
				writeJSONError(w, info, http.StatusInternalServerError, "routing before auth")
				return
			}
			snap := snapshots()
			if snap == nil {
				writeJSONError(w, info, http.StatusServiceUnavailable, "gateway warming up")
				return
			}
			route, ok := snap.MatchRoute(tenant.ID, r.URL.Path)
			if !ok {
				writeJSONError(w, info, http.StatusNotFound, "no route for path")
				return
			}
			if !auth.HasScope(key, route.RequiredScope) {
				writeJSONError(w, info, http.StatusForbidden, "key lacks required scope")
				return
			}
			info.RoutePrefix = route.PathPrefix
			info.Upstream = route.Upstream.Host
			next.ServeHTTP(w, r.WithContext(reqctx.WithRoute(r.Context(), route)))
		})
	}
}

// RateLimit admits or rejects the request under the tenant's policy.
func RateLimit(limiter ratelimit.Limiter, failOpen bool, m *observability.Metrics, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := reqctx.InfoFrom(r.Context())
			tenant := reqctx.TenantFrom(r.Context())
			if tenant == nil {
				writeJSONError(w, info, http.StatusInternalServerError, "rate limit before auth")
				return
			}
			policy := ratelimit.PolicyForTenant(tenant)

			start := time.Now()
			decision, err := limiter.Allow(r.Context(), tenant.ID, policy, info.RequestID)
			m.RateLimiterDuration.Observe(time.Since(start).Seconds())

			if err != nil {
				m.RateLimiterErrors.Inc()
				logger.Error("rate limiter check failed",
					"tenant", tenant.ID, "fail_open", failOpen, "error", err)
				if failOpen {
					// Availability over strictness: a Redis blip should not
					// take every tenant to zero. The error metric feeds an
					// alert instead.
					next.ServeHTTP(w, r)
					return
				}
				writeJSONError(w, info, http.StatusServiceUnavailable, "rate limiter unavailable")
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(decision.Limit, 10))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(decision.Remaining, 10))
			outcome := "allowed"
			if !decision.Allowed {
				outcome = "limited"
			}
			m.RateLimitDecisions.WithLabelValues(tenant.ID, string(policy.Algorithm), outcome).Inc()

			if !decision.Allowed {
				info.RateLimited = true
				retryAfterSec := int64(decision.RetryAfter.Seconds() + 0.999)
				if retryAfterSec < 1 {
					retryAfterSec = 1
				}
				w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSec, 10))
				writeJSONError(w, info, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORS answers browser preflight and tags responses with the allowed origin.
//
// It sits directly inside Recover and outside Auth, because a preflight OPTIONS
// carries no Authorization header: run it after Auth and every browser client
// is rejected before it ever gets to send the real request.
//
// Origins are an explicit allow-list, never "*". A gateway holding a shared
// provider key should not let any page on the internet spend it, and the
// rate-limit headers below are exposed deliberately so a browser client can
// read its own remaining budget.
func CORS(allowed []string) Middleware {
	allow := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		if o != "" {
			allow[o] = true
		}
	}
	const exposed = "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After, X-Request-Id"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allow[origin] {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Vary", "Origin")
				h.Set("Access-Control-Expose-Headers", exposed)
				if r.Method == http.MethodOptions {
					h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
					h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
					h.Set("Access-Control-Max-Age", "600")
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

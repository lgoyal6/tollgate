package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lgoyal6/tollgate/internal/limits"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/reqctx"
)

// RequestSize bounds what one caller may hand the gateway.
//
// It runs outside RateLimit and outside Budget on purpose. Outside RateLimit
// because a declared Content-Length is free to check and a Redis round trip is
// not, so the cheapest rejection goes first. Outside Budget because a request
// refused for size must not leave a spend hold behind: the ledger only ever
// sees requests that were going to be forwarded.
//
// Three separate things are bounded here, because they fail differently:
//
//   - A declared length over the cap is refused before a body byte is read.
//   - An undeclared length (chunked) can only be bounded while reading, so the
//     body is wrapped and the failure surfaces at the reader.
//   - A compressed body is bounded by what it EXPANDS to, not by what it cost
//     to send. Measured on this repo's own harness, padded JSON gzips at about
//     510:1, so a wire cap on its own is not a size limit at all.
func RequestSize(cfg limits.Config, m *observability.Metrics) Middleware {
	return func(next http.Handler) http.Handler {
		if cfg.MaxRequestBytes <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := reqctx.InfoFrom(r.Context())
			if r.ContentLength > cfg.MaxRequestBytes {
				rejectTooLarge(w, info, m, "declared_length", cfg.MaxRequestBytes)
				return
			}
			if r.Body == nil {
				next.ServeHTTP(w, r)
				return
			}

			switch encodingOf(r) {
			case encodingIdentity:
				r.Body = limits.NewCappedBody(r.Body, cfg.MaxRequestBytes)
				next.ServeHTTP(w, r)
			case encodingGzip:
				serveGzip(w, r, next, cfg, m, info)
			default:
				// A body the gateway cannot inflate is a body whose real size
				// it cannot bound, and relaying it unexamined is exactly the
				// bypass this limit exists to close. Providers in front of
				// which this gateway sits accept gzip, so refusing the rest
				// costs a compression ratio, not a capability.
				m.LimitRejections.WithLabelValues(info.TenantLabel(), "unsupported_encoding").Inc()
				writeJSONError(w, info, http.StatusUnsupportedMediaType,
					"unsupported Content-Encoding: the gateway only accepts identity or gzip request bodies")
			}
		})
	}
}

// serveGzip buffers the compressed body, proves it does not expand past the
// cap, and only then lets the request continue.
//
// It is buffered rather than streamed so the decision happens BEFORE anything
// reaches the upstream. A streaming check would necessarily discover the bomb
// halfway through relaying it, which on a metered upstream means the caller
// has already been billed for the part that got through.
func serveGzip(w http.ResponseWriter, r *http.Request, next http.Handler,
	cfg limits.Config, m *observability.Metrics, info *reqctx.Info) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, cfg.MaxRequestBytes+1))
	if err != nil {
		writeJSONError(w, info, http.StatusBadRequest, "unreadable request body")
		return
	}
	if int64(len(raw)) > cfg.MaxRequestBytes {
		rejectTooLarge(w, info, m, "wire_bytes", cfg.MaxRequestBytes)
		return
	}

	decoded, err := limits.Inflate(raw, cfg.MaxDecompressedBytes, maxBudgetInspectBody)
	switch {
	case errors.Is(err, limits.ErrDecompressedTooLarge):
		m.LimitRejections.WithLabelValues(info.TenantLabel(), "decompressed_bytes").Inc()
		w.Header().Set("X-Decompressed-Limit", strconv.FormatInt(cfg.MaxDecompressedBytes, 10))
		writeJSONError(w, info, http.StatusRequestEntityTooLarge,
			"request body expands past the decompressed size limit")
		return
	case err != nil:
		writeJSONError(w, info, http.StatusBadRequest, "malformed gzip request body")
		return
	}

	// The compressed bytes go upstream untouched: normalising them would
	// multiply the gateway-to-provider hop and throw away the caller's own
	// bandwidth decision. Only the pricing view is decompressed.
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	next.ServeHTTP(w, r.WithContext(reqctx.WithDecodedBody(r.Context(), decoded)))
}

type contentEncoding int

const (
	encodingIdentity contentEncoding = iota
	encodingGzip
	encodingOther
)

func encodingOf(r *http.Request) contentEncoding {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
		return encodingIdentity
	case "gzip", "x-gzip":
		return encodingGzip
	default:
		return encodingOther
	}
}

func rejectTooLarge(w http.ResponseWriter, info *reqctx.Info, m *observability.Metrics, reason string, limit int64) {
	m.LimitRejections.WithLabelValues(info.TenantLabel(), reason).Inc()
	w.Header().Set("X-Request-Limit", strconv.FormatInt(limit, 10))
	writeJSONError(w, info, http.StatusRequestEntityTooLarge, "request body too large")
}

// Concurrency bounds how many of a tenant's requests occupy the gateway at
// once, and how many more may wait.
//
// This is the limit the rate limiter cannot express. A token bucket bounds
// arrivals per second; it says nothing about how many of those are still
// in flight, and against a slow upstream a tenant well inside its rate can
// accumulate thousands of open requests. Measured on this repo's harness, a
// request with a 1 MiB body holds about 1.06 MiB of heap and three gateway
// goroutines for as long as it is open, and 512 of them cost 542 MiB with
// nothing refusing any of them.
//
// It sits INSIDE RateLimit so a slot is never held across the limiter's Redis
// round trip, and OUTSIDE Budget so a queued or refused request never takes a
// spend hold.
//
// The gate is per tenant, which is the whole point: a global cap would let one
// caller's fan-out refuse everybody else's traffic, and the property worth
// having is that a hostile tenant is refused while a well-behaved one is not.
func Concurrency(cfg limits.Config, m *observability.Metrics) Middleware {
	if cfg.MaxInFlightPerTenant <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	gates := &gateGroup{cfg: cfg}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := reqctx.InfoFrom(r.Context())
			tenant := reqctx.TenantFrom(r.Context())
			if tenant == nil {
				writeJSONError(w, info, http.StatusInternalServerError, "concurrency limit before auth")
				return
			}
			g := gates.gateFor(tenant.ID)
			reason, ok := g.acquire(r.Context(), cfg)
			if !ok {
				m.LimitRejections.WithLabelValues(tenant.ID, reason).Inc()
				if reason == "client_gone" {
					// The caller has already hung up; there is nobody to tell.
					return
				}
				// Retry-After is what makes the rejection actionable rather
				// than just a failure: the queue drains on the order of one
				// upstream call, so a second is an honest hint.
				w.Header().Set("Retry-After", "1")
				writeJSONError(w, info, http.StatusTooManyRequests,
					"too many concurrent requests for this tenant")
				return
			}
			defer g.release()
			next.ServeHTTP(w, r)
		})
	}
}

// gateGroup holds one gate per tenant. Entries are never evicted: tenant ids
// come from Postgres, so the key space is the operator's tenant list rather
// than anything a caller can invent.
type gateGroup struct {
	cfg   limits.Config
	mu    sync.RWMutex
	gates map[string]*gate
}

func (gg *gateGroup) gateFor(tenantID string) *gate {
	gg.mu.RLock()
	g, ok := gg.gates[tenantID]
	gg.mu.RUnlock()
	if ok {
		return g
	}
	gg.mu.Lock()
	defer gg.mu.Unlock()
	if g, ok := gg.gates[tenantID]; ok {
		return g
	}
	if gg.gates == nil {
		gg.gates = make(map[string]*gate)
	}
	g = &gate{slots: make(chan struct{}, gg.cfg.MaxInFlightPerTenant)}
	gg.gates[tenantID] = g
	return g
}

type gate struct {
	slots  chan struct{}
	queued atomic.Int64
}

// acquire takes a slot, waits for one, or reports why it will not.
//
// The three refusal reasons are kept apart because they mean different things
// to an operator: queue_full is a tenant sending faster than the upstream can
// absorb, queue_timeout is an upstream that has become slow, and client_gone
// is neither.
func (g *gate) acquire(ctx context.Context, cfg limits.Config) (string, bool) {
	select {
	case g.slots <- struct{}{}:
		return "", true
	default:
	}
	if cfg.MaxQueuePerTenant <= 0 {
		return "queue_full", false
	}
	if g.queued.Add(1) > int64(cfg.MaxQueuePerTenant) {
		g.queued.Add(-1)
		return "queue_full", false
	}
	defer g.queued.Add(-1)

	timer := time.NewTimer(cfg.QueueWait)
	defer timer.Stop()
	select {
	case g.slots <- struct{}{}:
		return "", true
	case <-timer.C:
		return "queue_timeout", false
	case <-ctx.Done():
		return "client_gone", false
	}
}

func (g *gate) release() { <-g.slots }

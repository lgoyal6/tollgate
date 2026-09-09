package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/lgoyal6/tollgate/internal/budget"
	"github.com/lgoyal6/tollgate/internal/limits"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/secops"
)

// maxBudgetInspectBody caps how much of a request body the estimator will buffer.
// Bodies larger than this are forwarded but not enforced: buffering an unbounded
// upload to price it would itself be the resource-exhaustion bug.
const maxBudgetInspectBody = 1 << 20 // 1 MiB

// budgetLedger is the slice of *budget.Ledger this middleware needs, so tests can
// substitute a fake without a database.
type budgetLedger interface {
	Reserve(ctx context.Context, tenantID, requestID string, upperBoundMicros int64, model string) (budget.Status, error)
	Settle(ctx context.Context, tenantID, requestID string, actualMicros int64) (budget.Status, error)
	Release(ctx context.Context, tenantID, requestID, reason string) error
	MarkUncertain(ctx context.Context, tenantID, requestID, reason string) error
}

// Budget enforces per-tenant spend limits, which the rate limiter cannot: one
// request inside the rate limit can cost more than a thousand cheap ones.
//
// It sits INSIDE RateLimit and outside the proxy - a request refused on rate should
// never take a budget hold, and a request refused on budget must never reach the
// upstream.
//
// Enforcement is deliberately conditional. A hard refusal needs a known model price
// AND a caller-declared output ceiling; without both there is no upper bound to hold,
// so the request is forwarded and merely settled after the fact. Refusing on a guessed
// price would be worse than not enforcing, and silently "enforcing" an unbounded
// request would be a lie.
func Budget(ledger budgetLedger, failOpen bool, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := reqctx.InfoFrom(r.Context())
			tenant := reqctx.TenantFrom(r.Context())
			if tenant == nil || ledger == nil {
				next.ServeHTTP(w, r)
				return
			}

			body, rest, err := peekBody(r, maxBudgetInspectBody)
			if err != nil {
				if errors.Is(err, limits.ErrRequestTooLarge) {
					writeJSONError(w, info, http.StatusRequestEntityTooLarge, "request body too large")
					return
				}
				writeJSONError(w, info, http.StatusBadRequest, "unreadable request body")
				return
			}
			r.Body = rest

			// A compressed body is unparseable JSON, so without the decoded
			// view RequestSize leaves behind, every gzipped request would
			// price as an unknown model with no ceiling: forwarded, no hold,
			// no enforcement. That is a budget bypass a caller can trigger
			// with one header, and it is measured in RECORD_tollgate_limits.
			if decoded := reqctx.DecodedBodyFrom(r.Context()); decoded != nil {
				body = decoded
			}
			// Price the DECOMPRESSED body. Reading it raw meant a gzipped
			// request never parsed as JSON, so it was classed unpriceable and
			// forwarded with no hold at all: a client could skip the budget
			// entirely with one Content-Encoding header. The size cap here is
			// the same 1 MiB peek, so a decompression bomb cannot be used to
			// turn pricing into a memory attack; a body that will not inflate
			// within it stays unpriceable, which is the safe direction.
			shape := budget.ShapeFromBody(priceableBody(r, body))
			upper, enforceable := budget.EstimateUpperBound(shape)

			if !enforceable {
				// Track-only: no hold, but settle afterwards so spend is still visible.
				sw := &budgetCapture{ResponseWriter: w}
				next.ServeHTTP(sw, r)
				settleObserved(r.Context(), ledger, tenant.ID, info.RequestID, shape.Model, sw, info, logger, false)
				return
			}

			st, err := ledger.Reserve(r.Context(), tenant.ID, info.RequestID, upper, shape.Model)
			switch {
			case err == nil:
				if st.Remaining != nil {
					w.Header().Set("X-Budget-Remaining-Micros", strconv.FormatInt(*st.Remaining, 10))
				}
			case errors.Is(err, budget.ErrNoBudget):
				// No budget configured for this tenant: unlimited, by design, so that
				// enabling this feature cannot brick an existing deployment.
				next.ServeHTTP(w, r)
				return
			case errors.Is(err, budget.ErrOverBudget):
				w.Header().Set("X-Budget-Exceeded", "1")
				writeJSONError(w, info, http.StatusPaymentRequired,
					"tenant budget exhausted: this request's maximum cost exceeds the remaining budget")
				return
			default:
				logger.Error("budget reserve failed",
					"tenant", tenant.ID, "fail_open", failOpen, "error", err)
				if failOpen {
					next.ServeHTTP(w, r)
					return
				}
				writeJSONError(w, info, http.StatusServiceUnavailable, "budget ledger unavailable")
				return
			}

			sw := &budgetCapture{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			settleObserved(r.Context(), ledger, tenant.ID, info.RequestID, shape.Model, sw, info, logger, true)
		})
	}
}

// settleObserved closes out the hold from what the response actually reported.
//
// The three outcomes are distinct on purpose:
//   - usage present     -> settle at the real cost.
//   - upstream never ran -> release; nothing was consumed.
//   - anything else      -> UNCERTAIN, keeping the hold. A stream that broke after
//     bytes went upstream may still be billed in full, so releasing here would let a
//     client disconnect mid-stream to get its usage for free.
func settleObserved(ctx context.Context, ledger budgetLedger, tenantID, requestID, model string,
	sw *budgetCapture, info *reqctx.Info, logger *slog.Logger, held bool) {
	// The client's context is already cancelled when it disconnects; settlement must
	// still run, so it gets a context detached from the request's lifetime.
	ctx = context.WithoutCancel(ctx)

	if in, out, ok := budget.UsageFromResponse(sw.body.Bytes()); ok {
		if cost, priced := budget.Cost(model, in, out); priced {
			// Settlement is the only point in the gateway that knows what a
			// request actually cost: the hold taken before forwarding is an
			// upper bound computed from the caller's own declared ceiling,
			// and a detector reading that would report an anomaly for
			// anybody who declared a large max_tokens and then sent a short
			// prompt. The detector cannot refuse anything; the ledger below
			// is still the only thing that can.
			secops.From(ctx).NoteSpend(ctx, cost, info != nil && info.KeyDeprecated)
			if _, err := ledger.Settle(ctx, tenantID, requestID, cost); err != nil {
				logger.Error("budget settle failed", "tenant", tenantID, "error", err)
			}
			return
		}
	}
	if !held {
		return // track-only request with no usable usage block: nothing to close out
	}
	if reason, ok := neverReachedUpstream(info, sw); ok {
		if err := ledger.Release(ctx, tenantID, requestID, reason); err != nil {
			logger.Error("budget release failed", "tenant", tenantID, "error", err)
		}
		return
	}
	if err := ledger.MarkUncertain(ctx, tenantID, requestID, "no usage reported by upstream"); err != nil {
		logger.Error("budget mark-uncertain failed", "tenant", tenantID, "error", err)
	}
}

// neverReachedUpstream reports whether the gateway itself refused or failed the
// request before the provider could have processed anything, which is the only
// case where a hold may be given back.
//
// An earlier version tested `sw.written == 0`, which never fired: the proxy's
// own failure path writes a JSON error body, so every dead upstream fell through
// to MarkUncertain and the hold leaked. A tenant whose provider was down would
// have watched its budget fill with holds that never released.
//
// The split is by what actually happened on the wire:
//
//   - 503 with a gateway error is the circuit breaker refusing locally. Nothing
//     was sent, so nothing can be billed.
//   - 502 with a gateway error is a transport failure: the connection was never
//     established, or died before a response line.
//   - 504 is deliberately NOT here. A timeout means the request WAS sent and the
//     provider may have completed and billed it while the gateway stopped
//     waiting. That is the definition of uncertain.
//
// info.Error is what distinguishes the gateway's own failure from an upstream
// response that merely carried a 5xx status: the proxy only sets it on its own
// error path, and a forwarded response leaves it empty.
func neverReachedUpstream(info *reqctx.Info, sw *budgetCapture) (string, bool) {
	if info == nil || info.Error == "" {
		return "", false
	}
	switch sw.status {
	case http.StatusServiceUnavailable:
		return "circuit open: request refused before reaching the upstream", true
	case http.StatusBadGateway:
		return "transport failure: no response line from the upstream", true
	default:
		return "", false
	}
}

// priceableBody returns the bytes the pricer should parse: the decompressed
// head when the request declares an encoding it can undo, and the raw bytes
// otherwise. An encoding it cannot undo (brotli, say) yields the raw bytes,
// which will not parse, which correctly leaves the request unpriceable rather
// than silently priced from garbage.
func priceableBody(r *http.Request, raw []byte) []byte {
	if !strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		return raw
	}
	prefix, err := limits.Inflate(raw, maxBudgetInspectBody, maxBudgetInspectBody)
	if err != nil {
		return raw
	}
	return prefix
}

// peekBody reads up to limit bytes so the request can be priced, and returns a
// ReadCloser that replays them to the proxy. Bodies past the limit stream through
// unbuffered and unenforced rather than being held in memory.
func peekBody(r *http.Request, limit int64) ([]byte, io.ReadCloser, error) {
	if r.Body == nil {
		return nil, http.NoBody, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		return nil, nil, err
	}
	return buf, struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}, nil
}

// budgetCapture keeps a bounded copy of the response so settlement can read the
// provider's usage block, while streaming every byte straight through.
type budgetCapture struct {
	http.ResponseWriter
	status  int
	written int64
	body    bytes.Buffer
}

func (c *budgetCapture) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *budgetCapture) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	// Usage blocks live at the end of a response, so keep the tail, bounded.
	if c.body.Len() < maxBudgetInspectBody {
		c.body.Write(p)
	}
	n, err := c.ResponseWriter.Write(p)
	c.written += int64(n)
	return n, err
}

// Flush keeps streaming responses streaming; without it the proxy's SSE path would
// buffer behind this wrapper.
func (c *budgetCapture) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

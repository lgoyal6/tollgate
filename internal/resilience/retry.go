package resilience

import (
	"math/rand/v2"
	"net/http"
	"time"
)

// RetryPolicy shapes the backoff between proxy attempts.
type RetryPolicy struct {
	BaseDelay time.Duration
	MaxDelay  time.Duration
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{BaseDelay: 25 * time.Millisecond, MaxDelay: 250 * time.Millisecond}
}

// Backoff returns the sleep before retry number `retry` (1-based) using
// exponential growth with full jitter: uniform in [0, min(max, base*2^(n-1))].
// Full jitter spreads synchronized retry storms across the whole interval
// instead of stacking them at the deadline.
func (p RetryPolicy) Backoff(retry int) time.Duration {
	if retry < 1 {
		retry = 1
	}
	ceil := p.BaseDelay << (retry - 1)
	if ceil > p.MaxDelay || ceil <= 0 {
		ceil = p.MaxDelay
	}
	return time.Duration(rand.Int64N(int64(ceil) + 1))
}

// IdempotentMethod reports whether a method is safe to send twice. Only
// safe methods are retried or hedged; PUT/DELETE are formally idempotent but
// re-sending them by default surprises people, so they are excluded.
func IdempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// RetryableStatus reports whether an upstream status is worth another
// attempt: transient gateway-class errors only. 500 is excluded - it usually
// means the upstream executed and broke, not that it never saw the request.
func RetryableStatus(status int) bool {
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

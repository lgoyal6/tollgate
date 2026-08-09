package ratelimit

import "time"

// NewMemoryLimiterWithClock is NewMemoryLimiter with an injectable clock, for
// deterministic simulations (the browser demo) and time-sensitive tests.
func NewMemoryLimiterWithClock(now func() time.Time) *MemoryLimiter {
	l := NewMemoryLimiter()
	l.now = now
	return l
}

package ratelimit

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/lgoyal6/tollgate/internal/store"
)

// MemoryLimiter applies the same algorithms as RedisLimiter but keeps state
// in process memory. With N replicas behind a load balancer each replica
// keeps its own counters, so a tenant limited to L req/s is actually allowed
// up to N*L. It exists to make that failure measurable (see the README's
// distributed-correctness proof) and doubles as the unit-test reference
// implementation for the algorithm math.
type MemoryLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucketState
	windows map[string][]int64 // arrival times, unix micros, oldest first
	now     func() time.Time   // injectable for tests
}

type bucketState struct {
	tokens float64
	ts     time.Time
}

func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{
		buckets: make(map[string]*bucketState),
		windows: make(map[string][]int64),
		now:     time.Now,
	}
}

func (l *MemoryLimiter) Name() string { return "memory" }

func (l *MemoryLimiter) Allow(_ context.Context, tenantID string, p Policy, _ string) (Decision, error) {
	if err := p.Validate(); err != nil {
		return Decision{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch p.Algorithm {
	case store.AlgoTokenBucket:
		return l.allowTokenBucket(tenantID, p), nil
	default:
		return l.allowSlidingWindow(tenantID, p), nil
	}
}

func (l *MemoryLimiter) allowTokenBucket(tenantID string, p Policy) Decision {
	now := l.now()
	b, ok := l.buckets[tenantID]
	if !ok {
		b = &bucketState{tokens: float64(p.Burst), ts: now}
		l.buckets[tenantID] = b
	}
	elapsed := now.Sub(b.ts).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(float64(p.Burst), b.tokens+elapsed*p.Rate)
		b.ts = now
	}
	d := Decision{Limit: p.Burst}
	if b.tokens >= 1 {
		b.tokens--
		d.Allowed = true
	} else {
		d.RetryAfter = time.Duration(math.Ceil((1-b.tokens)/p.Rate*1000)) * time.Millisecond
	}
	d.Remaining = int64(b.tokens)
	return d
}

func (l *MemoryLimiter) allowSlidingWindow(tenantID string, p Policy) Decision {
	nowUs := l.now().UnixMicro()
	cutoff := nowUs - p.Window.Microseconds()
	log := l.windows[tenantID]
	// Drop entries older than the window.
	i := 0
	for i < len(log) && log[i] <= cutoff {
		i++
	}
	log = log[i:]

	d := Decision{Limit: p.Limit}
	if int64(len(log)) < p.Limit {
		log = append(log, nowUs)
		d.Allowed = true
	} else {
		retryUs := log[0] + p.Window.Microseconds() - nowUs
		d.RetryAfter = time.Duration(retryUs) * time.Microsecond
	}
	d.Remaining = max(p.Limit-int64(len(log)), 0)
	l.windows[tenantID] = log
	return d
}

// Package ratelimit is the core of the gateway: per-tenant admission control
// with two selectable algorithms (token bucket, sliding window log) backed by
// Redis Lua scripts so check-and-decrement is atomic across every gateway
// replica. A deliberately naive in-memory backend exists solely to
// demonstrate why per-replica limiting is wrong.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/lgoyal6/tollgate/internal/store"
)

// Policy is the per-tenant limit configuration, derived from tenant columns.
type Policy struct {
	Algorithm store.Algorithm
	// Token bucket.
	Rate  float64 // tokens per second
	Burst int64   // bucket capacity
	// Sliding window log.
	Window time.Duration
	Limit  int64 // max requests per window
}

// Validate rejects policies that would divide by zero or admit nothing.
func (p Policy) Validate() error {
	switch p.Algorithm {
	case store.AlgoTokenBucket:
		if p.Rate <= 0 || p.Burst <= 0 {
			return fmt.Errorf("token bucket needs rate > 0 and burst > 0, got rate=%v burst=%d", p.Rate, p.Burst)
		}
	case store.AlgoSlidingWindow:
		if p.Limit <= 0 || p.Window <= 0 {
			return fmt.Errorf("sliding window needs limit > 0 and window > 0, got limit=%d window=%v", p.Limit, p.Window)
		}
	default:
		return fmt.Errorf("unknown algorithm %q", p.Algorithm)
	}
	return nil
}

// MaxAdmitted is the ceiling on requests the policy can admit over d,
// starting from a full bucket / empty window. Used by tests and the
// correctness demo to state the expected bound.
func (p Policy) MaxAdmitted(d time.Duration) int64 {
	switch p.Algorithm {
	case store.AlgoTokenBucket:
		return p.Burst + int64(p.Rate*d.Seconds())
	case store.AlgoSlidingWindow:
		windows := int64(d/p.Window) + 1
		return p.Limit * windows
	default:
		return 0
	}
}

// PolicyForTenant maps tenant config to a Policy.
func PolicyForTenant(t *store.Tenant) Policy {
	return Policy{
		Algorithm: t.RLAlgorithm,
		Rate:      t.RLRate,
		Burst:     t.RLBurst,
		Window:    t.RLWindow,
		Limit:     t.RLLimit,
	}
}

// Decision is the outcome of one admission check.
type Decision struct {
	Allowed bool
	// Limit is the advertised ceiling (burst for token bucket, window limit
	// for sliding window), for X-RateLimit-Limit.
	Limit      int64
	Remaining  int64
	RetryAfter time.Duration
}

// Limiter admits or rejects a request for a tenant under a policy.
// uniq must be unique per request (the request id); the sliding window uses
// it to disambiguate same-microsecond arrivals from different replicas.
type Limiter interface {
	Allow(ctx context.Context, tenantID string, p Policy, uniq string) (Decision, error)
	Name() string
}

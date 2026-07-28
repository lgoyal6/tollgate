package ratelimit

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/lgoyal6/tollgate/internal/store"
)

//go:embed tokenbucket.lua
var tokenBucketSrc string

//go:embed slidingwindow.lua
var slidingWindowSrc string

// RedisLimiter shares limit state across all gateway replicas. Each check is
// one round trip executing a Lua script, so read-modify-write is atomic; two
// replicas can never both spend the same token. redis.Script runs EVALSHA
// and falls back to EVAL once per script flush, so the steady state sends
// only the SHA.
type RedisLimiter struct {
	client        redis.UniversalClient
	tokenBucket   *redis.Script
	slidingWindow *redis.Script
	// keyTTL guards against dead tenants leaking keys forever. It only needs
	// to exceed the largest window/refill horizon.
	keyTTL time.Duration
}

func NewRedisLimiter(client redis.UniversalClient) *RedisLimiter {
	return &RedisLimiter{
		client:        client,
		tokenBucket:   redis.NewScript(tokenBucketSrc),
		slidingWindow: redis.NewScript(slidingWindowSrc),
		keyTTL:        time.Hour,
	}
}

func (l *RedisLimiter) Name() string { return "redis" }

func (l *RedisLimiter) Allow(ctx context.Context, tenantID string, p Policy, uniq string) (Decision, error) {
	if err := p.Validate(); err != nil {
		return Decision{}, fmt.Errorf("invalid policy for tenant %s: %w", tenantID, err)
	}
	switch p.Algorithm {
	case store.AlgoTokenBucket:
		return l.allowTokenBucket(ctx, tenantID, p)
	case store.AlgoSlidingWindow:
		return l.allowSlidingWindow(ctx, tenantID, p, uniq)
	default:
		return Decision{}, fmt.Errorf("unknown algorithm %q", p.Algorithm)
	}
}

func (l *RedisLimiter) allowTokenBucket(ctx context.Context, tenantID string, p Policy) (Decision, error) {
	// Hash-tagged key so all state for a tenant lands on one cluster slot.
	key := "rl:tb:{" + tenantID + "}"
	res, err := l.tokenBucket.Run(ctx, l.client, []string{key},
		p.Burst,
		strconv.FormatFloat(p.Rate, 'f', -1, 64),
		1, // cost
		l.keyTTL.Milliseconds(),
	).Result()
	if err != nil {
		return Decision{}, fmt.Errorf("token bucket script for tenant %s: %w", tenantID, err)
	}
	allowed, remaining, retryAfter, err := parseScriptReply(res)
	if err != nil {
		return Decision{}, fmt.Errorf("token bucket reply for tenant %s: %w", tenantID, err)
	}
	return Decision{
		Allowed:    allowed,
		Limit:      p.Burst,
		Remaining:  remaining,
		RetryAfter: retryAfter,
	}, nil
}

func (l *RedisLimiter) allowSlidingWindow(ctx context.Context, tenantID string, p Policy, uniq string) (Decision, error) {
	key := "rl:sw:{" + tenantID + "}"
	res, err := l.slidingWindow.Run(ctx, l.client, []string{key},
		p.Limit,
		p.Window.Milliseconds(),
		uniq,
	).Result()
	if err != nil {
		return Decision{}, fmt.Errorf("sliding window script for tenant %s: %w", tenantID, err)
	}
	allowed, remaining, retryAfter, err := parseScriptReply(res)
	if err != nil {
		return Decision{}, fmt.Errorf("sliding window reply for tenant %s: %w", tenantID, err)
	}
	return Decision{
		Allowed:    allowed,
		Limit:      p.Limit,
		Remaining:  remaining,
		RetryAfter: retryAfter,
	}, nil
}

// parseScriptReply decodes the {allowed, remaining, retry_after_ms} table
// both scripts return. Lua integers arrive as int64; the token bucket returns
// remaining as a string because Lua->Redis conversion truncates floats.
func parseScriptReply(res any) (allowed bool, remaining int64, retryAfter time.Duration, err error) {
	arr, ok := res.([]any)
	if !ok || len(arr) != 3 {
		return false, 0, 0, fmt.Errorf("unexpected reply shape %T", res)
	}
	a, ok := arr[0].(int64)
	if !ok {
		return false, 0, 0, fmt.Errorf("allowed field has type %T", arr[0])
	}
	switch v := arr[1].(type) {
	case int64:
		remaining = v
	case string:
		remaining, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			return false, 0, 0, fmt.Errorf("parsing remaining %q: %w", v, err)
		}
	default:
		return false, 0, 0, fmt.Errorf("remaining field has type %T", arr[1])
	}
	ra, ok := arr[2].(int64)
	if !ok {
		return false, 0, 0, fmt.Errorf("retry_after field has type %T", arr[2])
	}
	if remaining < 0 {
		remaining = 0
	}
	return a == 1, remaining, time.Duration(ra) * time.Millisecond, nil
}

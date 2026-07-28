package ratelimit

// Integration tests for the Lua scripts against a real Redis. They assert the
// property the whole project hinges on: N concurrent clients sharing one
// Redis can never over-admit, because the check-and-decrement runs atomically
// inside the script.
//
// Skipped unless TOLLGATE_TEST_REDIS is set (e.g. localhost:6379).

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/lgoyal6/tollgate/internal/store"
)

func newTestRedisLimiter(t *testing.T) *RedisLimiter {
	t.Helper()
	addr := os.Getenv("TOLLGATE_TEST_REDIS")
	if addr == "" {
		t.Skip("TOLLGATE_TEST_REDIS not set; skipping Redis integration tests")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("pinging redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { client.Close() })
	return NewRedisLimiter(client)
}

func uniqueTenant(t *testing.T) string {
	return fmt.Sprintf("test-%s-%d", t.Name(), time.Now().UnixNano())
}

func TestRedisTokenBucketBasics(t *testing.T) {
	l := newTestRedisLimiter(t)
	ctx := context.Background()
	tenant := uniqueTenant(t)
	policy := Policy{Algorithm: store.AlgoTokenBucket, Rate: 100, Burst: 10}

	allowed := 0
	for i := 0; i < 15; i++ {
		d, err := l.Allow(ctx, tenant, policy, fmt.Sprint(i))
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if d.Allowed {
			allowed++
		} else if d.RetryAfter <= 0 {
			t.Errorf("rejected decision has RetryAfter %v, want > 0", d.RetryAfter)
		}
	}
	// 15 back-to-back requests against burst 10: refill at 100/s may top up
	// a token or two during the loop, but never all 15.
	if allowed < 10 || allowed > 12 {
		t.Errorf("allowed %d of 15 burst requests, want 10..12", allowed)
	}
}

func TestRedisSlidingWindowBasics(t *testing.T) {
	l := newTestRedisLimiter(t)
	ctx := context.Background()
	tenant := uniqueTenant(t)
	policy := Policy{Algorithm: store.AlgoSlidingWindow, Limit: 5, Window: 500 * time.Millisecond}

	allowed := 0
	for i := 0; i < 8; i++ {
		d, err := l.Allow(ctx, tenant, policy, fmt.Sprint(i))
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if d.Allowed {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("allowed %d of 8, want exactly 5", allowed)
	}

	// After the window passes, capacity returns.
	time.Sleep(600 * time.Millisecond)
	d, err := l.Allow(ctx, tenant, policy, "after")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !d.Allowed {
		t.Error("request after window expiry should be admitted")
	}
}

// TestRedisAtomicityUnderConcurrency is the load-bearing test: many
// goroutines (standing in for gateway replicas) hammer one tenant, and the
// total admitted must not exceed the policy's ceiling.
func TestRedisAtomicityUnderConcurrency(t *testing.T) {
	l := newTestRedisLimiter(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		policy  Policy
		workers int
		perW    int
	}{
		{
			"token bucket",
			Policy{Algorithm: store.AlgoTokenBucket, Rate: 50, Burst: 100},
			20, 50,
		},
		{
			"sliding window",
			Policy{Algorithm: store.AlgoSlidingWindow, Limit: 100, Window: 2 * time.Second},
			20, 50,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := uniqueTenant(t)
			var admitted atomic.Int64
			var wg sync.WaitGroup
			start := time.Now()
			for w := 0; w < tt.workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < tt.perW; i++ {
						d, err := l.Allow(ctx, tenant, tt.policy, fmt.Sprintf("%d-%d", w, i))
						if err != nil {
							t.Errorf("Allow: %v", err)
							return
						}
						if d.Allowed {
							admitted.Add(1)
						}
					}
				}(w)
			}
			wg.Wait()
			elapsed := time.Since(start)

			// Ceiling with slack for elapsed-time refill/window rollover.
			ceiling := tt.policy.MaxAdmitted(elapsed + 100*time.Millisecond)
			got := admitted.Load()
			if got > ceiling {
				t.Errorf("admitted %d requests, atomicity ceiling is %d (elapsed %v)", got, ceiling, elapsed)
			}
			if got == 0 {
				t.Error("admitted nothing; test is broken")
			}
			t.Logf("admitted %d / %d requests in %v (ceiling %d)", got, tt.workers*tt.perW, elapsed, ceiling)
		})
	}
}

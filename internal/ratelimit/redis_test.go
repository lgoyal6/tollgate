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
	"net"
	"os"
	"strings"
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

func TestRedisLimiterReturnsErrorWhenRedisIsUnavailable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	client := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 50 * time.Millisecond, ReadTimeout: 50 * time.Millisecond, WriteTimeout: 50 * time.Millisecond, MaxRetries: 0})
	defer client.Close()

	decision, err := NewRedisLimiter(client).Allow(context.Background(), "unavailable", Policy{Algorithm: store.AlgoTokenBucket, Rate: 1, Burst: 1}, "request")
	if err == nil {
		t.Fatalf("Allow returned decision %+v without Redis", decision)
	}
	if decision.Allowed {
		t.Fatalf("unavailable Redis admitted a request: %+v", decision)
	}
}

func TestRedisLimiterScriptsUseRedisServerTime(t *testing.T) {
	for name, source := range map[string]string{"token bucket": tokenBucketSrc, "sliding window": slidingWindowSrc} {
		if !strings.Contains(source, "redis.call('TIME')") {
			t.Errorf("%s script does not use the Redis server clock", name)
		}
	}
}

func TestRedisLimiterRecoversAfterScriptCacheFlush(t *testing.T) {
	l := newTestRedisLimiter(t)
	ctx := context.Background()
	policy := Policy{Algorithm: store.AlgoTokenBucket, Rate: 1, Burst: 2}
	if _, err := l.Allow(ctx, uniqueTenant(t), policy, "before-flush"); err != nil {
		t.Fatalf("initial Allow: %v", err)
	}
	if err := l.client.ScriptFlush(ctx).Err(); err != nil {
		t.Fatalf("SCRIPT FLUSH: %v", err)
	}
	if _, err := l.Allow(ctx, uniqueTenant(t), policy, "after-flush"); err != nil {
		t.Fatalf("Allow after server script-cache loss: %v", err)
	}
}

func TestRedisLimiterRecoversAfterIdleConnectionsAreKilled(t *testing.T) {
	l := newTestRedisLimiter(t)
	ctx := context.Background()
	policy := Policy{Algorithm: store.AlgoTokenBucket, Rate: 1, Burst: 2}
	if _, err := l.Allow(ctx, uniqueTenant(t), policy, "before-kill"); err != nil {
		t.Fatalf("initial Allow: %v", err)
	}
	admin := redis.NewClient(&redis.Options{Addr: os.Getenv("TOLLGATE_TEST_REDIS")})
	defer admin.Close()
	connectionID, err := l.client.Do(ctx, "CLIENT", "ID").Int64()
	if err != nil {
		t.Fatalf("get pooled connection id: %v", err)
	}
	killed, err := admin.Do(ctx, "CLIENT", "KILL", "ID", connectionID).Int()
	if err != nil {
		t.Fatalf("kill pooled Redis connections: %v", err)
	}
	if killed == 0 {
		t.Fatal("Redis did not close any pooled client connections")
	}
	if _, err := l.Allow(ctx, uniqueTenant(t), policy, "after-kill"); err != nil {
		t.Fatalf("Allow after Redis closed pooled connections: %v", err)
	}
}

func TestRedisLimiterThreeReplicasPreserveTwoTenantBursts(t *testing.T) {
	first := newTestRedisLimiter(t)
	clients := []*RedisLimiter{first}
	for range 2 {
		client := redis.NewClient(&redis.Options{Addr: os.Getenv("TOLLGATE_TEST_REDIS")})
		t.Cleanup(func() { client.Close() })
		clients = append(clients, NewRedisLimiter(client))
	}
	tenants := []struct {
		id    string
		burst int64
	}{
		{id: uniqueTenant(t) + "-a", burst: 3},
		{id: uniqueTenant(t) + "-b", burst: 5},
	}
	var admitted [2]atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 60)
	for replica, limiter := range clients {
		for tenant := range tenants {
			for request := range 10 {
				wg.Add(1)
				go func(replica, tenant, request int, limiter *RedisLimiter) {
					defer wg.Done()
					<-start
					d, err := limiter.Allow(context.Background(), tenants[tenant].id,
						Policy{Algorithm: store.AlgoTokenBucket, Rate: 0.000000001, Burst: tenants[tenant].burst},
						fmt.Sprintf("%d-%d-%d", replica, tenant, request))
					if err != nil {
						errs <- err
						return
					}
					if d.Allowed {
						admitted[tenant].Add(1)
					}
				}(replica, tenant, request, limiter)
			}
		}
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("Redis Allow: %v", err)
	}
	for tenant, tc := range tenants {
		if got := admitted[tenant].Load(); got != tc.burst {
			t.Errorf("tenant %s admitted %d of 30 attempts, want exactly burst %d", tc.id, got, tc.burst)
		}
	}
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
	start := time.Now()
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
	elapsed := time.Since(start)

	// The bucket starts full, so the first Burst requests are owed.
	if allowed < int(policy.Burst) {
		t.Errorf("allowed %d of 15, want at least the full burst of %d", allowed, policy.Burst)
	}
	// Everything above the burst is refill that accrued while the loop ran. The
	// ceiling is derived from measured elapsed time rather than from an assumption
	// that 15 Redis round trips finish inside one refill period: on a loaded
	// machine they do not, refill at 100/s tops the bucket back up, and a fixed
	// "10..12" bound fails for a reason that has nothing to do with the limiter.
	refill := int(elapsed.Seconds() * policy.Rate)
	ceiling := int(policy.Burst) + refill + 1 // +1 for the sub-token boundary
	if allowed > ceiling {
		t.Errorf("allowed %d of 15 in %v; ceiling is burst %d + refill %d + 1 = %d",
			allowed, elapsed, policy.Burst, refill, ceiling)
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

package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/store"
)

// fakeClock lets tests move time deterministically.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestMemoryLimiter() (*MemoryLimiter, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)}
	l := NewMemoryLimiter()
	l.now = clock.now
	return l, clock
}

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{"valid token bucket", Policy{Algorithm: store.AlgoTokenBucket, Rate: 10, Burst: 20}, false},
		{"token bucket zero rate", Policy{Algorithm: store.AlgoTokenBucket, Rate: 0, Burst: 20}, true},
		{"token bucket zero burst", Policy{Algorithm: store.AlgoTokenBucket, Rate: 10, Burst: 0}, true},
		{"valid sliding window", Policy{Algorithm: store.AlgoSlidingWindow, Limit: 5, Window: time.Second}, false},
		{"sliding window zero limit", Policy{Algorithm: store.AlgoSlidingWindow, Limit: 0, Window: time.Second}, true},
		{"sliding window zero window", Policy{Algorithm: store.AlgoSlidingWindow, Limit: 5, Window: 0}, true},
		{"unknown algorithm", Policy{Algorithm: "leaky_bucket", Rate: 1, Burst: 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.policy.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMemoryTokenBucket(t *testing.T) {
	policy := Policy{Algorithm: store.AlgoTokenBucket, Rate: 10, Burst: 5}
	ctx := context.Background()

	t.Run("burst then exhaustion", func(t *testing.T) {
		l, _ := newTestMemoryLimiter()
		for i := 0; i < 5; i++ {
			d, err := l.Allow(ctx, "t1", policy, "r")
			if err != nil {
				t.Fatalf("Allow #%d: %v", i, err)
			}
			if !d.Allowed {
				t.Fatalf("request %d should be within burst", i)
			}
		}
		d, _ := l.Allow(ctx, "t1", policy, "r")
		if d.Allowed {
			t.Fatal("6th request should exceed burst")
		}
		if d.RetryAfter <= 0 {
			t.Errorf("RetryAfter = %v, want > 0", d.RetryAfter)
		}
	})

	t.Run("refill restores tokens at rate", func(t *testing.T) {
		l, clock := newTestMemoryLimiter()
		for i := 0; i < 5; i++ {
			l.Allow(ctx, "t1", policy, "r") //nolint:errcheck
		}
		// 300ms at 10 tokens/sec = 3 tokens.
		clock.advance(300 * time.Millisecond)
		allowed := 0
		for i := 0; i < 5; i++ {
			if d, _ := l.Allow(ctx, "t1", policy, "r"); d.Allowed {
				allowed++
			}
		}
		if allowed != 3 {
			t.Errorf("allowed %d after 300ms refill, want 3", allowed)
		}
	})

	t.Run("bucket never exceeds burst", func(t *testing.T) {
		l, clock := newTestMemoryLimiter()
		l.Allow(ctx, "t1", policy, "r") //nolint:errcheck
		clock.advance(time.Hour)
		allowed := 0
		for i := 0; i < 20; i++ {
			if d, _ := l.Allow(ctx, "t1", policy, "r"); d.Allowed {
				allowed++
			}
		}
		if allowed != 5 {
			t.Errorf("allowed %d after long idle, want burst=5", allowed)
		}
	})

	t.Run("tenants are isolated", func(t *testing.T) {
		l, _ := newTestMemoryLimiter()
		for i := 0; i < 5; i++ {
			l.Allow(ctx, "noisy", policy, "r") //nolint:errcheck
		}
		if d, _ := l.Allow(ctx, "quiet", policy, "r"); !d.Allowed {
			t.Error("tenant quiet should have a full bucket")
		}
	})
}

func TestMemorySlidingWindow(t *testing.T) {
	policy := Policy{Algorithm: store.AlgoSlidingWindow, Limit: 3, Window: time.Second}
	ctx := context.Background()

	t.Run("admits limit then rejects", func(t *testing.T) {
		l, _ := newTestMemoryLimiter()
		for i := 0; i < 3; i++ {
			if d, _ := l.Allow(ctx, "t1", policy, "r"); !d.Allowed {
				t.Fatalf("request %d should be admitted", i)
			}
		}
		if d, _ := l.Allow(ctx, "t1", policy, "r"); d.Allowed {
			t.Fatal("4th request in window should be rejected")
		}
	})

	t.Run("window actually slides", func(t *testing.T) {
		l, clock := newTestMemoryLimiter()
		l.Allow(ctx, "t1", policy, "r") //nolint:errcheck
		l.Allow(ctx, "t1", policy, "r") //nolint:errcheck
		clock.advance(600 * time.Millisecond)
		l.Allow(ctx, "t1", policy, "r") //nolint:errcheck
		// 3 in window: full.
		if d, _ := l.Allow(ctx, "t1", policy, "r"); d.Allowed {
			t.Fatal("window is full")
		}
		// 500ms later the first two (at t=0) have aged out; one slot... two slots free.
		clock.advance(500 * time.Millisecond)
		if d, _ := l.Allow(ctx, "t1", policy, "r"); !d.Allowed {
			t.Fatal("oldest entries should have aged out")
		}
	})

	t.Run("retry-after points at oldest entry expiry", func(t *testing.T) {
		l, clock := newTestMemoryLimiter()
		for i := 0; i < 3; i++ {
			l.Allow(ctx, "t1", policy, "r") //nolint:errcheck
		}
		clock.advance(400 * time.Millisecond)
		d, _ := l.Allow(ctx, "t1", policy, "r")
		if d.Allowed {
			t.Fatal("should be rejected")
		}
		if want := 600 * time.Millisecond; d.RetryAfter != want {
			t.Errorf("RetryAfter = %v, want %v", d.RetryAfter, want)
		}
	})
}

func TestPolicyMaxAdmitted(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		d      time.Duration
		want   int64
	}{
		{
			"token bucket: burst plus refill",
			Policy{Algorithm: store.AlgoTokenBucket, Rate: 100, Burst: 200},
			10 * time.Second, 200 + 1000,
		},
		{
			"sliding window: limit per window",
			Policy{Algorithm: store.AlgoSlidingWindow, Limit: 100, Window: time.Second},
			10 * time.Second, 100 * 11,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.MaxAdmitted(tt.d); got != tt.want {
				t.Errorf("MaxAdmitted(%v) = %d, want %d", tt.d, got, tt.want)
			}
		})
	}
}

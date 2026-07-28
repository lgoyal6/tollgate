package resilience

import (
	"errors"
	"testing"
	"time"
)

func newTestBreaker() (*Breaker, *time.Time) {
	now := time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)
	b := NewBreaker(BreakerConfig{
		Window:         10 * time.Second,
		Buckets:        10,
		MinRequests:    10,
		FailureRatio:   0.5,
		Cooldown:       5 * time.Second,
		HalfOpenProbes: 2,
	})
	b.now = func() time.Time { return now }
	b.bucketStart = now
	return b, &now
}

func record(t *testing.T, b *Breaker, success bool) {
	t.Helper()
	done, err := b.Allow()
	if err != nil {
		t.Fatalf("Allow unexpectedly rejected: %v", err)
	}
	done(success)
}

func TestBreakerStaysClosedBelowThreshold(t *testing.T) {
	tests := []struct {
		name      string
		successes int
		failures  int
	}{
		{"all successes", 50, 0},
		{"failures below min sample", 0, 9},
		{"ratio just under threshold", 11, 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := newTestBreaker()
			for i := 0; i < tt.successes; i++ {
				record(t, b, true)
			}
			for i := 0; i < tt.failures; i++ {
				record(t, b, false)
			}
			if got := b.State(); got != Closed {
				t.Errorf("state = %v, want Closed", got)
			}
		})
	}
}

func TestBreakerTripsAtThreshold(t *testing.T) {
	b, _ := newTestBreaker()
	for i := 0; i < 5; i++ {
		record(t, b, true)
	}
	for i := 0; i < 5; i++ {
		record(t, b, false)
	}
	// 10 samples, 50% failures: trips.
	if got := b.State(); got != Open {
		t.Fatalf("state = %v, want Open", got)
	}
	if _, err := b.Allow(); !errors.Is(err, ErrOpen) {
		t.Fatalf("Allow while open = %v, want ErrOpen", err)
	}
}

func trip(t *testing.T, b *Breaker) {
	t.Helper()
	for i := 0; i < 5; i++ {
		record(t, b, true)
	}
	for i := 0; i < 5; i++ {
		record(t, b, false)
	}
	if b.State() != Open {
		t.Fatal("setup: breaker should be open")
	}
}

func TestBreakerHalfOpenAfterCooldown(t *testing.T) {
	b, now := newTestBreaker()
	trip(t, b)

	*now = now.Add(5 * time.Second)
	done, err := b.Allow()
	if err != nil {
		t.Fatalf("Allow after cooldown: %v", err)
	}
	if got := b.State(); got != HalfOpen {
		t.Fatalf("state = %v, want HalfOpen", got)
	}
	done(true)

	// Second consecutive probe success closes it (HalfOpenProbes=2).
	record(t, b, true)
	if got := b.State(); got != Closed {
		t.Errorf("state after probe successes = %v, want Closed", got)
	}
}

func TestBreakerReopensOnProbeFailure(t *testing.T) {
	b, now := newTestBreaker()
	trip(t, b)

	*now = now.Add(5 * time.Second)
	done, err := b.Allow()
	if err != nil {
		t.Fatalf("Allow after cooldown: %v", err)
	}
	done(false)
	if got := b.State(); got != Open {
		t.Fatalf("state after failed probe = %v, want Open", got)
	}
	// And the cooldown restarts: still rejecting.
	if _, err := b.Allow(); !errors.Is(err, ErrOpen) {
		t.Errorf("Allow immediately after reopen = %v, want ErrOpen", err)
	}
}

func TestBreakerHalfOpenLimitsProbes(t *testing.T) {
	b, now := newTestBreaker()
	trip(t, b)
	*now = now.Add(5 * time.Second)

	if _, err := b.Allow(); err != nil {
		t.Fatalf("probe 1: %v", err)
	}
	if _, err := b.Allow(); err != nil {
		t.Fatalf("probe 2: %v", err)
	}
	// Probe budget (2) exhausted while both are in flight.
	if _, err := b.Allow(); !errors.Is(err, ErrOpen) {
		t.Errorf("third concurrent probe = %v, want ErrOpen", err)
	}
}

func TestBreakerOldFailuresAgeOut(t *testing.T) {
	b, now := newTestBreaker()
	// 9 failures now (below MinRequests, stays closed).
	for i := 0; i < 9; i++ {
		record(t, b, false)
	}
	// The whole window plus slack passes; those failures rotate out.
	*now = now.Add(11 * time.Second)
	for i := 0; i < 10; i++ {
		record(t, b, true)
	}
	record(t, b, false)
	if got := b.State(); got != Closed {
		t.Errorf("state = %v, want Closed (old failures should have aged out)", got)
	}
}

func TestBreakerStateChangeCallback(t *testing.T) {
	b, now := newTestBreaker()
	var transitions []string
	b.OnStateChange = func(from, to State) {
		transitions = append(transitions, from.String()+"->"+to.String())
	}
	trip(t, b)
	*now = now.Add(5 * time.Second)
	record(t, b, true)
	record(t, b, true)

	want := []string{"closed->open", "open->half_open", "half_open->closed"}
	if len(transitions) != len(want) {
		t.Fatalf("transitions = %v, want %v", transitions, want)
	}
	for i := range want {
		if transitions[i] != want[i] {
			t.Errorf("transition %d = %q, want %q", i, transitions[i], want[i])
		}
	}
}

func TestBreakerGroupIsPerHost(t *testing.T) {
	g := NewBreakerGroup(BreakerConfig{
		Window: 10 * time.Second, Buckets: 10, MinRequests: 2,
		FailureRatio: 0.5, Cooldown: time.Minute, HalfOpenProbes: 1,
	})
	a := g.For("upstream-a:9000")
	// MinRequests=2 at 100% failure: opens on the second failure.
	for i := 0; i < 2; i++ {
		done, err := a.Allow()
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		done(false)
	}
	if a.State() != Open {
		t.Fatal("upstream-a breaker should be open")
	}
	if _, err := a.Allow(); !errors.Is(err, ErrOpen) {
		t.Fatalf("Allow on open breaker = %v, want ErrOpen", err)
	}
	if g.For("upstream-b:9000").State() != Closed {
		t.Error("upstream-b breaker must be independent of upstream-a")
	}
	if g.For("upstream-a:9000") != a {
		t.Error("same host must return the same breaker")
	}
}

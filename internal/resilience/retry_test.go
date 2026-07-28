package resilience

import (
	"net/http"
	"testing"
	"time"
)

func TestBackoffJitterBounds(t *testing.T) {
	p := RetryPolicy{BaseDelay: 25 * time.Millisecond, MaxDelay: 250 * time.Millisecond}
	tests := []struct {
		retry int
		ceil  time.Duration
	}{
		{1, 25 * time.Millisecond},
		{2, 50 * time.Millisecond},
		{3, 100 * time.Millisecond},
		{4, 200 * time.Millisecond},
		{5, 250 * time.Millisecond},  // capped
		{10, 250 * time.Millisecond}, // shift overflow guarded
	}
	for _, tt := range tests {
		for i := 0; i < 200; i++ {
			got := p.Backoff(tt.retry)
			if got < 0 || got > tt.ceil {
				t.Fatalf("Backoff(%d) = %v, want in [0, %v]", tt.retry, got, tt.ceil)
			}
		}
	}
}

func TestBackoffActuallyJitters(t *testing.T) {
	p := DefaultRetryPolicy()
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		seen[p.Backoff(3)] = true
	}
	if len(seen) < 2 {
		t.Error("50 samples produced one value; jitter is not jittering")
	}
}

func TestIdempotentMethod(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{http.MethodGet, true},
		{http.MethodHead, true},
		{http.MethodOptions, true},
		{http.MethodPost, false},
		{http.MethodPut, false},    // formally idempotent, deliberately excluded
		{http.MethodDelete, false}, // same
		{http.MethodPatch, false},
	}
	for _, tt := range tests {
		if got := IdempotentMethod(tt.method); got != tt.want {
			t.Errorf("IdempotentMethod(%s) = %v, want %v", tt.method, got, tt.want)
		}
	}
}

func TestRetryableStatus(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
		{http.StatusInternalServerError, false}, // upstream ran and broke; do not re-run
		{http.StatusOK, false},
		{http.StatusTooManyRequests, false},
		{http.StatusNotFound, false},
	}
	for _, tt := range tests {
		if got := RetryableStatus(tt.status); got != tt.want {
			t.Errorf("RetryableStatus(%d) = %v, want %v", tt.status, got, tt.want)
		}
	}
}

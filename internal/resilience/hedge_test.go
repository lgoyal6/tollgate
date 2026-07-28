package resilience

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// hedgeServer answers slowly on the first request and fast afterwards,
// simulating the tail-latency situation hedging exists for.
func hedgeServer(t *testing.T, firstDelay, restDelay time.Duration) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		delay := restDelay
		if n == 1 {
			delay = firstDelay
		}
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "hello") //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func get(srv *httptest.Server) attemptFn {
	return func(ctx context.Context, _ int) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		if err != nil {
			return nil, err
		}
		return http.DefaultTransport.RoundTrip(req)
	}
}

func TestHedgeFastPrimaryNeverHedges(t *testing.T) {
	srv, calls := hedgeServer(t, 5*time.Millisecond, 5*time.Millisecond)
	res, release := Hedge(context.Background(), 200*time.Millisecond, get(srv))
	defer release()
	if res.Err != nil {
		t.Fatalf("Hedge: %v", res.Err)
	}
	defer res.Resp.Body.Close()
	if res.Hedged {
		t.Error("fast primary should not trigger a hedge")
	}
	if res.Attempt != 0 {
		t.Errorf("winner = attempt %d, want 0", res.Attempt)
	}
	time.Sleep(20 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream saw %d calls, want 1", got)
	}
}

func TestHedgeSlowPrimaryLosesToBackup(t *testing.T) {
	srv, calls := hedgeServer(t, 500*time.Millisecond, 5*time.Millisecond)
	start := time.Now()
	res, release := Hedge(context.Background(), 50*time.Millisecond, get(srv))
	defer release()
	if res.Err != nil {
		t.Fatalf("Hedge: %v", res.Err)
	}
	defer res.Resp.Body.Close()
	elapsed := time.Since(start)

	if !res.Hedged {
		t.Error("slow primary should have triggered the hedge")
	}
	if res.Attempt != 1 {
		t.Errorf("winner = attempt %d, want 1 (the backup)", res.Attempt)
	}
	if elapsed >= 400*time.Millisecond {
		t.Errorf("hedged request took %v; the backup should have finished around 55ms", elapsed)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("upstream saw %d calls, want 2", got)
	}
	body, err := io.ReadAll(res.Resp.Body)
	if err != nil {
		t.Fatalf("reading winner body: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}
}

func TestHedgePrimaryFailureBeforeDelayReturnsImmediately(t *testing.T) {
	boom := errors.New("connection refused")
	start := time.Now()
	res, release := Hedge(context.Background(), 300*time.Millisecond,
		func(ctx context.Context, _ int) (*http.Response, error) {
			return nil, boom
		})
	defer release()
	if !errors.Is(res.Err, boom) {
		t.Fatalf("err = %v, want the primary's error", res.Err)
	}
	if time.Since(start) >= 250*time.Millisecond {
		t.Error("a failed primary should return immediately, not wait out the hedge delay")
	}
	if res.Hedged {
		t.Error("no hedge should fire for a fast-failing primary")
	}
}

func TestHedgeBothFailPrefersHTTPResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	var attempts atomic.Int32
	res, release := Hedge(context.Background(), 10*time.Millisecond,
		func(ctx context.Context, attempt int) (*http.Response, error) {
			attempts.Add(1)
			if attempt == 1 {
				return nil, errors.New("dial error")
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
			return http.DefaultTransport.RoundTrip(req)
		})
	defer release()

	if res.Err != nil {
		t.Fatalf("want the 503 response surfaced, got err %v", res.Err)
	}
	defer res.Resp.Body.Close()
	if res.Resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", res.Resp.StatusCode)
	}
	if attempts.Load() != 2 {
		t.Errorf("attempts = %d, want 2", attempts.Load())
	}
}

func TestHedgeRespectsContextCancellation(t *testing.T) {
	srv, _ := hedgeServer(t, time.Second, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res, release := Hedge(ctx, 10*time.Millisecond, get(srv))
	defer release()
	if res.Err == nil {
		res.Resp.Body.Close()
		t.Fatal("expected an error from context expiry")
	}
	if !errors.Is(res.Err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", res.Err)
	}
}

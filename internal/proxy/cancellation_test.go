package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

func TestClientCancellationDuringRetryBackoffDoesNotStartAnotherAttempt(t *testing.T) {
	firstResponse := make(chan struct{})
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			defer close(firstResponse)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	p := testProxy(t, Options{})
	p.retry = resilience.RetryPolicy{BaseDelay: 250 * time.Millisecond, MaxDelay: 250 * time.Millisecond}
	route := routeTo(t, upstream.URL, func(r *store.Route) { r.RetryMax = 3 })
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/resource", strings.NewReader(""))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = send(p, route, req.WithContext(ctx))
	}()
	select {
	case <-firstResponse:
	case <-time.After(2 * time.Second):
		t.Fatal("first upstream attempt did not return")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not stop after cancellation")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream saw %d attempts after client cancellation, want one", got)
	}
}

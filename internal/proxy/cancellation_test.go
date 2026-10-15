package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

type retryWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *retryWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestRetryWaitStopsPromptlyWhenCancelledInsideBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := &retryWaitContext{Context: ctx, entered: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- waitForRetry(observed, time.Hour) }()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("retry wait never consulted cancellation")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wait error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled backoff did not stop promptly")
	}
}

type retryTransport func(*http.Request) (*http.Response, error)

func (f retryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type retryResponseBody struct {
	io.Reader
	cancel context.CancelFunc
}

func (b retryResponseBody) Close() error {
	if b.cancel != nil {
		b.cancel()
	}
	return nil
}

func TestClientCancellationDuringRetryBackoffDoesNotStartAnotherAttempt(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncancelled_retry_succeeds", true: "cancel_before_backoff"}[cancelled], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			p := testProxy(t, Options{})
			p.retry = resilience.RetryPolicy{BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}
			p.transport = retryTransport(func(_ *http.Request) (*http.Response, error) {
				code := http.StatusOK
				var onClose context.CancelFunc
				if calls.Add(1) == 1 {
					code = http.StatusServiceUnavailable
					if cancelled {
						onClose = cancel
					}
				}
				// Count every dispatch, including one a default transport might
				// suppress before reaching a socket with a cancelled context.
				return &http.Response{StatusCode: code, Header: make(http.Header), Body: retryResponseBody{Reader: strings.NewReader("body"), cancel: onClose}}, nil
			})
			route := routeTo(t, "http://upstream.example", func(r *store.Route) { r.RetryMax = 1 })
			req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/resource", nil).WithContext(ctx)
			rec, info := send(p, route, req)
			want := int32(2)
			if cancelled {
				want = 1
			}
			if calls.Load() != want || info.Attempts != int(want) {
				t.Fatalf("transport calls=%d proxy attempts=%d want=%d", calls.Load(), info.Attempts, want)
			}
			if !cancelled && rec.Code != http.StatusOK {
				t.Fatalf("uncancelled retry status=%d", rec.Code)
			}
		})
	}
}

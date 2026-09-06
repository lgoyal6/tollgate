package middleware

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lgoyal6/tollgate/internal/budget"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/store"
)

// fakeLedger records the calls the middleware makes, so these tests are about the
// middleware's decisions; the ledger's own semantics are tested against a real
// PostgreSQL in internal/budget.
type fakeLedger struct {
	mu         sync.Mutex
	reserveErr error
	remaining  int64
	calls      []string
	settled    int64
}

func (f *fakeLedger) Reserve(_ context.Context, _, _ string, upper int64, _ string) (budget.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "reserve")
	if f.reserveErr != nil {
		return budget.Status{}, f.reserveErr
	}
	rem := f.remaining - upper
	return budget.Status{Remaining: &rem}, nil
}
func (f *fakeLedger) Settle(_ context.Context, _, _ string, actual int64) (budget.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "settle")
	f.settled = actual
	return budget.Status{}, nil
}
func (f *fakeLedger) Release(_ context.Context, _, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "release")
	return nil
}
func (f *fakeLedger) MarkUncertain(_ context.Context, _, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "uncertain")
	return nil
}
func (f *fakeLedger) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func withTenant(r *http.Request) *http.Request {
	ctx := reqctx.WithInfo(r.Context(), &reqctx.Info{RequestID: "req-1"})
	ctx = reqctx.WithTenant(ctx, &store.Tenant{ID: "acme"})
	return r.WithContext(ctx)
}

func upstream(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // the proxy must still see the body
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func post(body string) *http.Request {
	return withTenant(httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body)))
}

const pricedReq = `{"model":"claude-sonnet-5","max_tokens":1000}`

func TestBudgetRefusesWhenOverBudget(t *testing.T) {
	f := &fakeLedger{reserveErr: budget.ErrOverBudget}
	var reached bool
	h := Budget(f, false, slog.Default())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, post(pricedReq))

	if reached {
		t.Error("an over-budget request reached the upstream")
	}
	if rec.Code != http.StatusPaymentRequired {
		t.Errorf("status %d, want 402", rec.Code)
	}
	if rec.Header().Get("X-Budget-Exceeded") != "1" {
		t.Error("missing X-Budget-Exceeded header")
	}
}

func TestBudgetSettlesFromReportedUsage(t *testing.T) {
	f := &fakeLedger{remaining: 100_000_000}
	body := `{"usage":{"input_tokens":1000,"output_tokens":2000}}`
	h := Budget(f, false, slog.Default())(upstream(200, body))
	h.ServeHTTP(httptest.NewRecorder(), post(pricedReq))

	// claude-sonnet-5: 1000 in @ $3/Mtok + 2000 out @ $15/Mtok = 3000 + 30000 micros
	want := int64(1000*3_000_000/1_000_000 + 2000*15_000_000/1_000_000)
	if f.settled != want {
		t.Errorf("settled %d micros, want %d", f.settled, want)
	}
	if got := f.seen(); len(got) != 2 || got[0] != "reserve" || got[1] != "settle" {
		t.Errorf("call sequence %v, want [reserve settle]", got)
	}
}

// The property that stops a client buying free tokens by hanging up mid-stream.
func TestBrokenStreamKeepsTheHoldAsUncertain(t *testing.T) {
	f := &fakeLedger{remaining: 100_000_000}
	// 200 with bytes written but no usage block: the classic interrupted stream.
	h := Budget(f, false, slog.Default())(upstream(200, `data: {"delta":"hi"}`))
	h.ServeHTTP(httptest.NewRecorder(), post(pricedReq))

	got := f.seen()
	if len(got) != 2 || got[1] != "uncertain" {
		t.Errorf("call sequence %v, want the hold kept as [reserve uncertain]", got)
	}
	for _, c := range got {
		if c == "release" {
			t.Error("an interrupted stream released the hold - that is free usage")
		}
	}
}

// The proxy's own failure path writes a JSON error body, so an earlier version of
// this middleware, which released only when nothing had been written, never
// released at all: every dead upstream leaked its hold as "uncertain" and a tenant
// whose provider was down watched its budget fill with holds that never came back.
// These drive the real shape: a status, an error recorded on the request, and a
// body already written.
func gatewayFailure(status int, msg string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqctx.InfoFrom(r.Context()).Error = msg
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"` + msg + `","request_id":"req-1"}`))
	})
}

func TestUpstreamThatNeverRanReleasesTheHold(t *testing.T) {
	for _, tc := range []struct {
		name, msg string
		status    int
	}{
		{"transport failure", "upstream error", http.StatusBadGateway},
		{"circuit open", "upstream unavailable (circuit open)", http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLedger{remaining: 100_000_000}
			h := Budget(f, false, slog.Default())(gatewayFailure(tc.status, tc.msg))
			h.ServeHTTP(httptest.NewRecorder(), post(pricedReq))

			got := f.seen()
			if len(got) != 2 || got[1] != "release" {
				t.Errorf("call sequence %v, want [reserve release]; the hold leaked", got)
			}
		})
	}
}

// A timeout is NOT a release: the request was sent, and the provider may have
// completed and billed it while the gateway stopped waiting.
func TestUpstreamTimeoutKeepsTheHold(t *testing.T) {
	f := &fakeLedger{remaining: 100_000_000}
	h := Budget(f, false, slog.Default())(gatewayFailure(http.StatusGatewayTimeout, "upstream timeout"))
	h.ServeHTTP(httptest.NewRecorder(), post(pricedReq))

	got := f.seen()
	if len(got) != 2 || got[1] != "uncertain" {
		t.Errorf("call sequence %v, want [reserve uncertain]: a timeout may still be billed", got)
	}
}

// A 5xx the upstream itself produced is not the gateway failing: it answered, so
// it may have billed. info.Error stays empty on a forwarded response.
func TestUpstreamOwn5xxKeepsTheHold(t *testing.T) {
	f := &fakeLedger{remaining: 100_000_000}
	h := Budget(f, false, slog.Default())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway) // forwarded from the provider, no info.Error
		_, _ = w.Write([]byte(`{"error":"provider exploded"}`))
	}))
	h.ServeHTTP(httptest.NewRecorder(), post(pricedReq))

	got := f.seen()
	if len(got) != 2 || got[1] != "uncertain" {
		t.Errorf("call sequence %v, want [reserve uncertain]", got)
	}
}

// Without a known price or a declared output ceiling there is no upper bound to
// hold, so the gateway must forward rather than refuse on a guess.
func TestUnpricedOrUnboundedRequestsAreTrackedNotRefused(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unknown model", `{"model":"some-new-model","max_tokens":100}`},
		{"no output ceiling", `{"model":"claude-sonnet-5"}`},
		{"unparseable body", `not json at all`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLedger{remaining: 100_000_000}
			var reached bool
			h := Budget(f, false, slog.Default())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(200)
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, post(tc.body))

			if !reached {
				t.Error("request was refused despite having no enforceable bound")
			}
			for _, c := range f.seen() {
				if c == "reserve" {
					t.Error("took a hold it could not compute an upper bound for")
				}
			}
		})
	}
}

// A tenant with no budget row is unlimited: enabling this must not brick anyone.
func TestTenantWithoutBudgetPassesThrough(t *testing.T) {
	f := &fakeLedger{reserveErr: budget.ErrNoBudget}
	var reached bool
	h := Budget(f, false, slog.Default())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(200)
	}))
	h.ServeHTTP(httptest.NewRecorder(), post(pricedReq))
	if !reached {
		t.Error("a tenant with no configured budget was refused")
	}
}

// The proxy behind this middleware must still receive the whole body, byte for byte,
// even though the middleware read it to price the request.
func TestRequestBodyIsForwardedIntact(t *testing.T) {
	f := &fakeLedger{remaining: 100_000_000}
	var got string
	h := Budget(f, false, slog.Default())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(200)
	}))
	h.ServeHTTP(httptest.NewRecorder(), post(pricedReq))
	if got != pricedReq {
		t.Errorf("upstream saw %q, want the original %q", got, pricedReq)
	}
}

func TestLedgerOutageRespectsFailOpen(t *testing.T) {
	for _, failOpen := range []bool{true, false} {
		f := &fakeLedger{reserveErr: context.DeadlineExceeded}
		var reached bool
		h := Budget(f, failOpen, slog.Default())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(200)
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, post(pricedReq))
		if failOpen && !reached {
			t.Error("fail-open should have forwarded despite the ledger error")
		}
		if !failOpen && rec.Code != http.StatusServiceUnavailable {
			t.Errorf("fail-closed status %d, want 503", rec.Code)
		}
	}
}

func TestPricingPrefixMatchAndUnknownModel(t *testing.T) {
	if _, ok := budget.PriceFor("claude-sonnet-5-20260101"); !ok {
		t.Error("a dated snapshot should inherit its base model's price")
	}
	if _, ok := budget.PriceFor("totally-unknown"); ok {
		t.Error("an unknown model must not resolve to a guessed price")
	}
	// Longest-prefix wins: haiku-4-5 must not match the shorter claude- entries.
	p, _ := budget.PriceFor("claude-haiku-4-5-20251001")
	if p.InputPerMTok != 1_000_000 {
		t.Errorf("longest-prefix match failed: got input price %d", p.InputPerMTok)
	}
}

func TestUsageParsingHandlesBothProviderSpellings(t *testing.T) {
	anthropic, _ := json.Marshal(map[string]any{"usage": map[string]int{"input_tokens": 5, "output_tokens": 7}})
	openai, _ := json.Marshal(map[string]any{"usage": map[string]int{"prompt_tokens": 5, "completion_tokens": 7}})
	for name, body := range map[string][]byte{"anthropic": anthropic, "openai": openai} {
		in, out, ok := budget.UsageFromResponse(body)
		if !ok || in != 5 || out != 7 {
			t.Errorf("%s: got (%d,%d,%v), want (5,7,true)", name, in, out, ok)
		}
	}
	if _, _, ok := budget.UsageFromResponse([]byte(`{"no":"usage"}`)); ok {
		t.Error("a response with no usage block must report ok=false")
	}
}

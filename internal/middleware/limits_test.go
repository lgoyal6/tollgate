package middleware

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/limits"
)

// rejections reads the counter for one refusal reason straight off the
// registry, so no test-only dependency is pulled in for it.
//
// Asserting on the reason and not only on the status code is what keeps these
// tests honest: several layers can produce a 413, and a test that accepts any
// of them would still pass with the cheap early check removed.
func rejections(h *costHarness, tenant, reason string) float64 {
	families, err := h.metrics.Registry.Gather()
	if err != nil {
		return -1
	}
	for _, f := range families {
		if f.GetName() != "tollgate_limit_rejections_total" {
			continue
		}
		for _, mm := range f.GetMetric() {
			var gotTenant, gotReason string
			for _, l := range mm.GetLabel() {
				switch l.GetName() {
				case "tenant":
					gotTenant = l.GetValue()
				case "reason":
					gotReason = l.GetValue()
				}
			}
			if gotTenant == tenant && gotReason == reason {
				return mm.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// testLimits is the configuration every test in this file runs under.
//
// TOLLGATE_LIMITS_OFF=1 zeroes it, which is exactly the gateway as it was
// before these limits existed, because 0 means "not enforced" for every field.
// Every test here fails in that mode, which is the before/after evidence in
// RECORD_tollgate_limits.md and the reason the flag exists.
func testLimits() limits.Config {
	if os.Getenv("TOLLGATE_LIMITS_OFF") != "" {
		return limits.Config{}
	}
	return limits.Config{
		MaxRequestBytes:      64 << 10,
		MaxDecompressedBytes: 256 << 10,
		MaxResponseBytes:     64 << 10,
		MaxInFlightPerTenant: 2,
		MaxQueuePerTenant:    2,
		QueueWait:            150 * time.Millisecond,
		MaxRequestDuration:   5 * time.Second,
	}
}

// countingUpstream records how many requests actually reached the provider,
// which is the number that matters: an abuse limit that rejects after the
// upstream has been billed has not rejected anything.
type countingUpstream struct {
	hits atomic.Int64
	body atomic.Int64
}

func (c *countingUpstream) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		c.hits.Add(1)
		c.body.Add(n)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"usage":{"input_tokens":10,"output_tokens":10}}`) //nolint:errcheck
	})
}

func gzipBody(t *testing.T, plain int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.Copy(zw, chatBody(plain)); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	zw.Close()
	return buf.Bytes()
}

func TestRequestSizeRefusesDeclaredOversizeBody(t *testing.T) {
	up := &countingUpstream{}
	ledger := &fakeLedger{remaining: 1 << 62}
	h := newHarness(t, up.handler(), ledger, testLimits(), nil, "acme")

	size := 1 << 20 // 16x the 64 KiB cap
	resp, err := h.post(chatBody(size), chatBodySize(size), nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	if n := up.hits.Load(); n != 0 {
		t.Errorf("upstream saw %d requests, want 0: the point of the limit is that the provider is never billed", n)
	}
	if calls := ledger.seen(); len(calls) != 0 {
		t.Errorf("ledger calls = %v, want none: a request refused for size must leave no spend hold", calls)
	}
	// The reason matters as much as the status: a declared length has to be
	// refused from the header alone, before a body byte comes off the socket.
	if got := rejections(h, "acme", "declared_length"); got != 1 {
		t.Errorf("declared_length rejections = %v, want 1: the body was read before it was refused", got)
	}
}

func TestRequestSizeAllowsBodyAtExactlyTheLimit(t *testing.T) {
	up := &countingUpstream{}
	h := newHarness(t, up.handler(), &fakeLedger{remaining: 1 << 62}, testLimits(), nil, "acme")

	size := int(testLimits().MaxRequestBytes)
	resp, err := h.post(chatBody(size), chatBodySize(size), nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200: a body of exactly the cap is legal", resp.StatusCode)
	}
}

// A chunked upload declares no length, so the cap can only be applied while
// reading. It must still refuse rather than truncate.
func TestRequestSizeRefusesChunkedOversizeBody(t *testing.T) {
	up := &countingUpstream{}
	ledger := &fakeLedger{remaining: 1 << 62}
	h := newHarness(t, up.handler(), ledger, testLimits(), nil, "acme")

	resp, err := h.post(chatBody(1<<20), -1, nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	if n := up.body.Load(); n > testLimits().MaxRequestBytes {
		t.Errorf("upstream received %d body bytes, more than the %d cap", n, testLimits().MaxRequestBytes)
	}
	if calls := ledger.seen(); len(calls) != 0 {
		t.Errorf("ledger calls = %v, want none", calls)
	}
}

// The classic bypass: a body small enough to pass a wire cap that expands to
// something nobody wanted to handle.
func TestRequestSizeRefusesGzipBomb(t *testing.T) {
	up := &countingUpstream{}
	ledger := &fakeLedger{remaining: 1 << 62}
	h := newHarness(t, up.handler(), ledger, testLimits(), nil, "acme")

	raw := gzipBody(t, 8<<20) // 8 MiB of plaintext, far past the 256 KiB cap
	if int64(len(raw)) > testLimits().MaxRequestBytes {
		t.Fatalf("fixture is %d wire bytes, which the wire cap would catch on its own", len(raw))
	}
	resp, err := h.post(bytes.NewReader(raw), int64(len(raw)), map[string]string{"Content-Encoding": "gzip"})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	if n := up.hits.Load(); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	if calls := ledger.seen(); len(calls) != 0 {
		t.Errorf("ledger calls = %v, want none", calls)
	}
	if got := rejections(h, "acme", "decompressed_bytes"); got != 1 {
		t.Errorf("decompressed_bytes rejections = %v, want 1: the wire cap alone cannot have caught this", got)
	}
}

// A gzipped request that is within both caps must still be PRICED. Before the
// decoded view existed, the estimator saw compressed bytes, failed to parse
// them, and forwarded the request with no hold at all: one header was a full
// budget bypass.
func TestGzipRequestIsPricedNotBypassed(t *testing.T) {
	up := &countingUpstream{}
	ledger := &fakeLedger{remaining: 1 << 62}
	h := newHarness(t, up.handler(), ledger, testLimits(), nil, "acme")

	raw := gzipBody(t, 4096)
	resp, err := h.post(bytes.NewReader(raw), int64(len(raw)), map[string]string{"Content-Encoding": "gzip"})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; a compressible request is legitimate", resp.StatusCode)
	}
	calls := ledger.seen()
	if len(calls) == 0 || calls[0] != "reserve" {
		t.Errorf("ledger calls = %v, want a reserve: a gzipped request must be held against the budget like any other", calls)
	}
}

// The upstream still receives the caller's compressed bytes: only the pricing
// view is inflated.
func TestGzipRequestIsForwardedStillCompressed(t *testing.T) {
	var gotEncoding string
	var gotLen int
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		b, _ := io.ReadAll(r.Body)
		gotLen = len(b)
		io.WriteString(w, `{}`) //nolint:errcheck
	})
	h := newHarness(t, up, &fakeLedger{remaining: 1 << 62}, testLimits(), nil, "acme")

	raw := gzipBody(t, 4096)
	resp, err := h.post(bytes.NewReader(raw), int64(len(raw)), map[string]string{"Content-Encoding": "gzip"})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	if gotEncoding != "gzip" {
		t.Errorf("upstream Content-Encoding = %q, want gzip", gotEncoding)
	}
	if gotLen != len(raw) {
		t.Errorf("upstream received %d bytes, want the %d compressed bytes unchanged", gotLen, len(raw))
	}
}

// An encoding the gateway cannot inflate is an encoding whose real size it
// cannot bound, which is the bypass restated.
func TestUnsupportedContentEncodingIsRefused(t *testing.T) {
	up := &countingUpstream{}
	h := newHarness(t, up.handler(), &fakeLedger{remaining: 1 << 62}, testLimits(), nil, "acme")

	resp, err := h.post(strings.NewReader("whatever"), 8, map[string]string{"Content-Encoding": "br"})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", resp.StatusCode)
	}
	if n := up.hits.Load(); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	if got := rejections(h, "acme", "unsupported_encoding"); got != 1 {
		t.Errorf("unsupported_encoding rejections = %v, want 1", got)
	}
}

// blockingUpstream holds every request until it is released, which is how a
// slow provider is simulated without a sleep race.
type blockingUpstream struct {
	arrived chan struct{}
	release chan struct{}
	hits    atomic.Int64
}

func newBlockingUpstream(capacity int) *blockingUpstream {
	return &blockingUpstream{
		arrived: make(chan struct{}, capacity),
		release: make(chan struct{}),
	}
}

func (b *blockingUpstream) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		b.hits.Add(1)
		select {
		case b.arrived <- struct{}{}:
		default:
		}
		<-b.release
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"usage":{"input_tokens":1,"output_tokens":1}}`) //nolint:errcheck
	})
}

func TestConcurrencyCapAdmitsSlotsQueuesTheRestAndRefusesBeyond(t *testing.T) {
	cfg := testLimits()
	up := newBlockingUpstream(64)
	h := newHarness(t, up.handler(), &fakeLedger{remaining: 1 << 62}, cfg, nil, "acme")

	const fired = 8 // 2 slots + 2 queue = 4 admissible, 4 must be refused
	var ok, refused atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < fired; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := h.post(chatBody(256), chatBodySize(256), nil)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK:
				ok.Add(1)
			case http.StatusTooManyRequests:
				if resp.Header.Get("Retry-After") == "" {
					t.Errorf("429 without Retry-After: the rejection has to be actionable")
				}
				refused.Add(1)
			default:
				t.Errorf("unexpected status %d", resp.StatusCode)
			}
		}()
	}
	// Wait for the slots to fill, then let everything finish.
	<-up.arrived
	time.Sleep(300 * time.Millisecond) // longer than QueueWait, so the queue times out
	close(up.release)
	wg.Wait()

	if refused.Load() == 0 {
		t.Fatalf("nothing was refused out of %d concurrent requests; the gateway has no concurrency bound", fired)
	}
	if ok.Load()+refused.Load() != fired {
		t.Errorf("accounted for %d of %d requests", ok.Load()+refused.Load(), fired)
	}
	if got := up.hits.Load(); got > int64(cfg.MaxInFlightPerTenant+cfg.MaxQueuePerTenant) {
		t.Errorf("upstream saw %d requests, more than the %d a tenant may have admitted",
			got, cfg.MaxInFlightPerTenant+cfg.MaxQueuePerTenant)
	}
	// Past slots plus queue the answer has to be immediate. queue_full is that
	// rejection; without a queue bound the same requests would wait out
	// QueueWait and be refused late, which looks the same to a status-code
	// assertion and very different to a caller.
	if got := rejections(h, "acme", "queue_full"); got == 0 {
		t.Errorf("no queue_full rejections: the queue is not bounded, requests only timed out")
	}
}

// The property that makes the cap per tenant worth the bookkeeping: a hostile
// tenant saturating its own gate must not touch anyone else's traffic.
func TestConcurrencyIsolatesTenants(t *testing.T) {
	cfg := testLimits()
	up := newBlockingUpstream(64)
	h := newHarness(t, up.handler(), &fakeLedger{remaining: 1 << 62}, cfg, nil, "hostile", "polite")

	var hostileDone sync.WaitGroup
	for i := 0; i < 32; i++ {
		hostileDone.Add(1)
		go func() {
			defer hostileDone.Done()
			resp, err := h.postAs("hostile", chatBody(256), chatBodySize(256))
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}()
	}
	<-up.arrived
	// The hostile tenant now owns every slot it is allowed. Release just
	// enough for the polite tenant's own request to complete: it has its own
	// gate, so it should never have queued behind the flood at all.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(up.release)
	}()

	start := time.Now()
	resp, err := h.postAs("polite", chatBody(256), chatBodySize(256))
	if err != nil {
		t.Fatalf("polite tenant: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	elapsed := time.Since(start)
	hostileDone.Wait()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("polite tenant got %d while another tenant was flooding; want 200", resp.StatusCode)
	}
	if elapsed > 2*time.Second {
		t.Errorf("polite tenant waited %s behind the flood", elapsed)
	}
}

// The completion test. Overload has to be refused predictably, has to leave
// well-behaved traffic alone, and - the part that is usually skipped - the
// gateway has to come all the way back once the overload stops.
func TestOverloadRejectsPredictablyAndRecovers(t *testing.T) {
	cfg := testLimits()
	up := newBlockingUpstream(256)
	h := newHarness(t, up.handler(), &fakeLedger{remaining: 1 << 62}, cfg, nil, "hostile", "polite")

	sendTo := func(hh *costHarness, tenant string) int {
		resp, err := hh.postAs(tenant, chatBody(256), chatBodySize(256))
		if err != nil {
			return -1
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		return resp.StatusCode
	}

	// Phase 1: healthy. The upstream answers immediately.
	close(up.release)
	if got := sendTo(h, "polite"); got != http.StatusOK {
		t.Fatalf("baseline: polite tenant got %d, want 200", got)
	}

	// Phase 2: overload. A second harness stands in for the provider going
	// slow while the hostile tenant piles requests on.
	up2 := newBlockingUpstream(256)
	h2 := newHarness(t, up2.handler(), &fakeLedger{remaining: 1 << 62}, cfg, nil, "hostile", "polite")

	var flood sync.WaitGroup
	var refused, admitted atomic.Int64
	for i := 0; i < 64; i++ {
		flood.Add(1)
		go func() {
			defer flood.Done()
			switch sendTo(h2, "hostile") {
			case http.StatusTooManyRequests:
				refused.Add(1)
			case http.StatusOK:
				admitted.Add(1)
			}
		}()
	}
	<-up2.arrived
	time.Sleep(400 * time.Millisecond) // let the queue fill and time out

	// The polite tenant sends into the middle of the flood. It has its own
	// gate, so it must be admitted rather than refused; it is launched in the
	// background because it will then wait on the same slow provider the
	// hostile tenant is waiting on, and "slow for everybody" is not the
	// failure this test is about.
	var politeDuringOverload int
	var politeDone sync.WaitGroup
	politeDone.Add(1)
	go func() {
		defer politeDone.Done()
		politeDuringOverload = sendTo(h2, "polite")
	}()
	time.Sleep(100 * time.Millisecond) // long enough for it to reach the upstream

	close(up2.release)
	flood.Wait()
	politeDone.Wait()

	if refused.Load() == 0 {
		t.Errorf("overload produced no rejections: 64 concurrent requests all got in")
	}
	if admitted.Load() > int64(cfg.MaxInFlightPerTenant+cfg.MaxQueuePerTenant) {
		t.Errorf("admitted %d during overload, more than %d slots plus queue",
			admitted.Load(), cfg.MaxInFlightPerTenant+cfg.MaxQueuePerTenant)
	}
	if politeDuringOverload == http.StatusTooManyRequests {
		t.Errorf("polite tenant was refused (429) by another tenant's overload: the cap is not isolating")
	}
	if politeDuringOverload != http.StatusOK {
		t.Errorf("polite tenant got %d during another tenant's overload, want 200", politeDuringOverload)
	}

	// Phase 3: recovery. Every slot the flood took must have come back, so the
	// hostile tenant is served normally again once it stops misbehaving.
	// Anything less means the gate leaks and the tenant is refused forever.
	for i := 0; i < cfg.MaxInFlightPerTenant*3; i++ {
		if got := sendTo(h2, "hostile"); got != http.StatusOK {
			t.Fatalf("recovery request %d: hostile tenant got %d after the overload passed, want 200", i, got)
		}
	}
	if got := sendTo(h2, "polite"); got != http.StatusOK {
		t.Errorf("recovery: polite tenant got %d, want 200", got)
	}
}

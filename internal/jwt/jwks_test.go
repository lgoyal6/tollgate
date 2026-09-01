package jwt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIDP is a JWKS endpoint whose document and health a test controls.
type fakeIDP struct {
	srv      *httptest.Server
	mu       sync.Mutex
	body     []byte
	status   int
	requests atomic.Int64
}

func newFakeIDP(t *testing.T, body []byte) *fakeIDP {
	t.Helper()
	idp := &fakeIDP{body: body, status: http.StatusOK}
	// TLS, because NewKeySource refuses a cleartext JWKS URL: a key set
	// fetched over http is a key set chosen by anyone on the path.
	idp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.requests.Add(1)
		idp.mu.Lock()
		body, status := idp.body, idp.status
		idp.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(idp.srv.Close)
	return idp
}

func (i *fakeIDP) serve(body []byte, status int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.body, i.status = body, status
}

// clock is a hand-wound test clock, so a TTL test costs no wall time.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func sourceFor(t *testing.T, idp *fakeIDP, ttl, minRefresh time.Duration) (*KeySource, *clock) {
	t.Helper()
	src, err := NewKeySource(idp.srv.URL, idp.srv.Client(), ttl, minRefresh)
	if err != nil {
		t.Fatal(err)
	}
	// httptest gives an https URL, which is what NewKeySource requires.
	c := newClock()
	src.now = c.now
	return src, c
}

func TestAFreshKeySetIsAnsweredWithoutTheNetwork(t *testing.T) {
	idp := newFakeIDP(t, keySetJSON(t, rsaSigner("k1", RS256)))
	src, clk := sourceFor(t, idp, time.Minute, 10*time.Second)

	for i := 0; i < 5; i++ {
		if _, err := src.Key(context.Background(), "k1"); err != nil {
			t.Fatal(err)
		}
		clk.advance(time.Second)
	}
	if got := idp.requests.Load(); got != 1 {
		t.Fatalf("want 1 fetch, got %d", got)
	}
}

func TestTTLExpiryRefetches(t *testing.T) {
	idp := newFakeIDP(t, keySetJSON(t, rsaSigner("k1", RS256)))
	src, clk := sourceFor(t, idp, time.Minute, time.Second)

	if _, err := src.Key(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	clk.advance(2 * time.Minute)
	if _, err := src.Key(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	if got := idp.requests.Load(); got != 2 {
		t.Fatalf("want 2 fetches, got %d", got)
	}
}

// The rotation case. A provider introduces a new signing key and starts using
// it immediately; tokens carrying the new kid arrive long before any TTL runs
// out. A cache that refreshes only on a timer rejects all of them.
func TestAnUnseenKidRefreshesEvenWhileTheSetIsFresh(t *testing.T) {
	old := rsaSigner("old", RS256)
	idp := newFakeIDP(t, keySetJSON(t, old))
	src, _ := sourceFor(t, idp, time.Hour, 10*time.Second)

	if _, err := src.Key(context.Background(), "old"); err != nil {
		t.Fatal(err)
	}
	// The provider rotates. The TTL has hours left on it.
	rotated := otherRSASigner("new", RS256)
	idp.serve(keySetJSON(t, old, rotated), http.StatusOK)

	key, err := src.Key(context.Background(), "new")
	if err != nil {
		t.Fatalf("a rotated-in key must be reachable before the TTL expires: %v", err)
	}
	if key.ID != "new" {
		t.Fatalf("got key %q", key.ID)
	}
}

// The other half of that: because an unknown kid can cause an outbound
// request, and the kid is a string an attacker writes, the miss path is a
// request amplifier pointed at the identity provider unless it is rate
// limited.
func TestAKidFloodCausesOneFetchPerWindow(t *testing.T) {
	idp := newFakeIDP(t, keySetJSON(t, rsaSigner("k1", RS256)))
	src, clk := sourceFor(t, idp, time.Hour, 30*time.Second)

	if _, err := src.Key(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	before := idp.requests.Load()

	for i := 0; i < 500; i++ {
		_, err := src.Key(context.Background(), "guess-"+strings.Repeat("x", i%7))
		if !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("want ErrUnknownKey, got %v", err)
		}
		clk.advance(10 * time.Millisecond)
	}
	if got := idp.requests.Load() - before; got != 1 {
		t.Fatalf("500 unknown kids in one window must cost 1 fetch, cost %d", got)
	}
	if s := src.Stats(); s.BlockedMisses != 499 {
		t.Fatalf("want 499 blocked misses, got %d", s.BlockedMisses)
	}

	// The window is a rate limit, not a lockout: once it passes, a genuine
	// rotation is still picked up.
	clk.advance(time.Minute)
	rotated := otherRSASigner("new", RS256)
	idp.serve(keySetJSON(t, rsaSigner("k1", RS256), rotated), http.StatusOK)
	if _, err := src.Key(context.Background(), "new"); err != nil {
		t.Fatalf("after the window a real rotation must still be seen: %v", err)
	}
}

func TestConcurrentMissesCollapseOntoOneFetch(t *testing.T) {
	idp := newFakeIDP(t, keySetJSON(t, rsaSigner("k1", RS256)))
	src, _ := sourceFor(t, idp, time.Hour, time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = src.Key(context.Background(), "k1")
		}()
	}
	wg.Wait()
	if got := idp.requests.Load(); got != 1 {
		// Without collapsing, a cold cache behind a burst of traffic is a
		// burst of identical requests at the identity provider.
		t.Fatalf("want 1 fetch, got %d", got)
	}
}

func TestAnUnreachableProviderKeepsTheKeysAlreadyInHand(t *testing.T) {
	idp := newFakeIDP(t, keySetJSON(t, rsaSigner("k1", RS256)))
	src, clk := sourceFor(t, idp, time.Minute, time.Second)

	if _, err := src.Key(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	idp.serve([]byte(`{"error":"down"}`), http.StatusInternalServerError)
	clk.advance(2 * time.Minute) // past the TTL, so a refresh is attempted

	if _, err := src.Key(context.Background(), "k1"); err != nil {
		t.Fatalf("a provider blip must not be an authentication outage: %v", err)
	}
	if s := src.Stats(); !s.ServingStale {
		t.Fatal("serving a set whose refresh failed must be visible in Stats")
	}
}

func TestAFailedProviderIsNotRetriedPerRequest(t *testing.T) {
	idp := newFakeIDP(t, keySetJSON(t, rsaSigner("k1", RS256)))
	src, clk := sourceFor(t, idp, time.Minute, 30*time.Second)

	if _, err := src.Key(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	idp.serve(nil, http.StatusBadGateway)
	clk.advance(2 * time.Minute)
	before := idp.requests.Load()
	for i := 0; i < 50; i++ {
		_, _ = src.Key(context.Background(), "k1")
		clk.advance(100 * time.Millisecond)
	}
	if got := idp.requests.Load() - before; got != 1 {
		t.Fatalf("a down provider must be retried on a backoff, got %d fetches", got)
	}
}

func TestWithNoKeySetAtAllAFailedFetchIsAnError(t *testing.T) {
	idp := newFakeIDP(t, nil)
	idp.serve(nil, http.StatusServiceUnavailable)
	src, _ := sourceFor(t, idp, time.Minute, time.Second)

	if _, err := src.Key(context.Background(), "k1"); err == nil {
		t.Fatal("nothing to fall back to, so this must fail")
	}
}

func TestAnOversizedDocumentIsRefused(t *testing.T) {
	huge := append([]byte(`{"keys":[`), []byte(strings.Repeat(" ", maxJWKSBytes+16))...)
	idp := newFakeIDP(t, append(huge, ']', '}'))
	src, _ := sourceFor(t, idp, time.Minute, time.Second)

	if _, err := src.Key(context.Background(), "k1"); err == nil {
		t.Fatal("want an error for an oversized key set")
	}
	if s := src.Stats(); s.Failures != 1 {
		t.Fatalf("want 1 failure, got %d", s.Failures)
	}
}

func TestACleartextJWKSURLIsRefused(t *testing.T) {
	if _, err := NewKeySource("http://idp.test/keys", nil, time.Minute, time.Second); err == nil {
		t.Fatal("http would make every other check in this package decorative")
	}
}

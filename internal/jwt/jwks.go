package jwt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// Key source failures.
var (
	ErrKeysUnavailable = errors.New("jwt: no key set available")
	ErrKeyFetchBlocked = errors.New("jwt: key fetch refused, too soon after the last one")
)

// maxJWKSBytes bounds the key set document.
//
// A key set is fetched over the network from a host this process does not
// control. Without a limit, whoever answers for that host decides how much
// memory the gateway allocates, and 32 keys of RSA-4096 is comfortably under
// this.
const maxJWKSBytes = 256 << 10

// KeySource keeps one issuer's JWKS current.
//
// It exists because a key set is not static and the ways it moves are all
// hostile to a naive cache:
//
//   - Rotation introduces a `kid` the cache has never seen, and tokens signed
//     with it arrive before any TTL has run out. A cache that only refreshes
//     on a timer rejects every one of them until it does.
//   - So the miss has to be able to trigger a fetch. But then a `kid` is an
//     attacker-controlled string that causes an outbound request, and a
//     stream of tokens with random kids becomes a request amplifier pointed
//     at the identity provider. So a miss may trigger at most one fetch per
//     MinRefresh.
//   - The provider will at some point be briefly unreachable. Failing closed
//     turns that into a total authentication outage, so a failed refresh
//     keeps serving the set already in hand. That trades revocation latency
//     for availability, and the trade is only defensible because revocation
//     is handled by checking that a `kid` is still live rather than by
//     expiring the whole set: see VerifiedCache.
type KeySource struct {
	url        string
	client     *http.Client
	ttl        time.Duration
	minRefresh time.Duration
	now        func() time.Time

	mu       sync.Mutex
	set      *KeySet
	loadedAt time.Time
	// lastMiss is when an unknown kid last caused a fetch. The rate limit
	// that makes kid-triggered fetching safe.
	lastMiss time.Time
	// lastFailure backs off after an unreachable provider, so an outage does
	// not turn into a fetch per request.
	lastFailure time.Time
	inflight    *fetchCall

	fetches  atomic.Uint64
	failures atomic.Uint64
	blocked  atomic.Uint64
	serving  atomic.Bool // true while answering from a set that failed to refresh
}

type fetchCall struct {
	done chan struct{}
	set  *KeySet
	err  error
}

// NewKeySource builds a source for one JWKS URL.
//
// The URL must be https. A key set fetched over cleartext is a key set chosen
// by anyone on the path, which would make every other check in this package
// decorative.
func NewKeySource(jwksURL string, client *http.Client, ttl, minRefresh time.Duration) (*KeySource, error) {
	u, err := url.Parse(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("jwt: parsing jwks url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("jwt: jwks url must be https, got %q", u.Scheme)
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if minRefresh <= 0 {
		minRefresh = 30 * time.Second
	}
	return &KeySource{
		url:        jwksURL,
		client:     client,
		ttl:        ttl,
		minRefresh: minRefresh,
		now:        time.Now,
	}, nil
}

// Key returns the verification key a token names.
//
// The four cases are the whole design, in order:
//
//	nothing loaded          -> fetch, and fail if that fails
//	loaded, fresh, hit      -> answer without touching the network
//	loaded, past its TTL    -> fetch, and fall back to what we have
//	loaded, fresh, miss     -> fetch at most once per MinRefresh
func (s *KeySource) Key(ctx context.Context, kid string) (*Key, error) {
	s.mu.Lock()
	set, loadedAt := s.set, s.loadedAt
	now := s.now()
	stale := set == nil || now.Sub(loadedAt) >= s.ttl
	miss := set != nil && !set.Has(kid)

	if !stale && !miss {
		defer s.mu.Unlock()
		return set.Lookup(kid)
	}
	// Back off from a provider that just failed, whatever the reason for
	// wanting a fetch.
	if !s.lastFailure.IsZero() && now.Sub(s.lastFailure) < s.minRefresh {
		defer s.mu.Unlock()
		if set == nil {
			return nil, ErrKeysUnavailable
		}
		return set.Lookup(kid)
	}
	if !stale && miss {
		// The kid is attacker controlled. One fetch per window, no matter how
		// many distinct kids arrive in it.
		if !s.lastMiss.IsZero() && now.Sub(s.lastMiss) < s.minRefresh {
			s.blocked.Add(1)
			defer s.mu.Unlock()
			return nil, ErrUnknownKey
		}
		s.lastMiss = now
	}
	s.mu.Unlock()

	fresh, err := s.refresh(ctx)
	if err != nil {
		if set == nil {
			return nil, err
		}
		// Serve what we have. An identity provider that is unreachable for
		// thirty seconds must not be an authentication outage.
		s.serving.Store(true)
		return set.Lookup(kid)
	}
	s.serving.Store(false)
	return fresh.Lookup(kid)
}

// Current is the key set in hand, without fetching.
//
// The verified-token cache uses this to re-establish that the key which signed
// a cached token is still one the issuer publishes.
func (s *KeySource) Current() *KeySet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set
}

// refresh fetches, collapsing concurrent callers onto one request.
//
// Written out rather than taken from x/sync because it is twenty lines and
// the thing it protects - the identity provider - is exactly what a thundering
// herd of gateway replicas would take down.
func (s *KeySource) refresh(ctx context.Context) (*KeySet, error) {
	s.mu.Lock()
	if call := s.inflight; call != nil {
		s.mu.Unlock()
		select {
		case <-call.done:
			return call.set, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &fetchCall{done: make(chan struct{})}
	s.inflight = call
	s.mu.Unlock()

	set, err := s.fetch(ctx)

	s.mu.Lock()
	call.set, call.err = set, err
	if err == nil {
		s.fetches.Add(1)
		s.set = set
		s.loadedAt = s.now()
		s.lastFailure = time.Time{}
	} else {
		s.failures.Add(1)
		s.lastFailure = s.now()
	}
	s.inflight = nil
	s.mu.Unlock()
	close(call.done)
	return set, err
}

func (s *KeySource) fetch(ctx context.Context) (*KeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwt: fetching jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwt: jwks endpoint returned %s", resp.Status)
	}
	// One byte over the limit is read on purpose, so an oversized document is
	// an error rather than a silently truncated key set that fails to parse
	// for a misleading reason.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("jwt: reading jwks: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("jwt: jwks document exceeds %d bytes", maxJWKSBytes)
	}
	return ParseKeySet(body)
}

// SourceStats is what the gateway exports about one issuer's key set.
type SourceStats struct {
	Keys int
	Age  time.Duration
	// ServingStale is true while answering from a set whose last refresh
	// failed. Worth an alert: it is the window in which a key revoked at the
	// provider is still trusted here.
	ServingStale bool
	Fetches      uint64
	Failures     uint64
	// BlockedMisses counts unknown-kid lookups refused by the rate limit,
	// which is what a kid-guessing flood looks like from here.
	BlockedMisses uint64
}

func (s *KeySource) Stats() SourceStats {
	s.mu.Lock()
	var age time.Duration
	if !s.loadedAt.IsZero() {
		age = s.now().Sub(s.loadedAt)
	}
	keys := s.set.Len()
	s.mu.Unlock()
	return SourceStats{
		Keys:          keys,
		Age:           age,
		ServingStale:  s.serving.Load(),
		Fetches:       s.fetches.Load(),
		Failures:      s.failures.Load(),
		BlockedMisses: s.blocked.Load(),
	}
}

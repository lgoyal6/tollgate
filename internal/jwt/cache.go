package jwt

import (
	"context"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"time"
)

// VerifiedCache remembers tokens that already verified.
//
// # Why
//
// An RSA-2048 verification is tens of microseconds of CPU per request, and a
// gateway does it on every single one, for a token that does not change
// between them. Caching the result turns that into a map lookup.
//
// # What it costs
//
// Time during which the gateway will honour a token that should no longer
// work. That window is bounded twice over, and the second bound is the one
// that matters:
//
//   - By TTL, clamped to the token's own exp, so a cached entry never
//     outlives the token.
//   - By key liveness. A hit re-checks that the kid which signed the token is
//     still in the issuer's published key set. So the response to a
//     compromised signing key - pull it from the JWKS, which is the only
//     revocation an OIDC provider actually offers for a stateless token - is
//     honoured within one KeySource refresh rather than at the end of this
//     cache's TTL. Without that check the cache would extend the blast radius
//     of a key compromise, which is the objection worth taking seriously.
//
// What it does not do is make a stolen but still valid token stop working.
// Nothing stateless does. That is what certificate binding is for.
//
// # Why not an LRU
//
// An LRU needs to reorder a list on every read, which means a write lock on
// the hot path, which is the path this exists to make cheap. Instead: a size
// cap, expired entries swept on insert, and arbitrary eviction past the cap.
// The failure mode of evicting the wrong entry is one RSA verification, which
// is exactly what the cache was avoiding anyway, so paying for precision here
// would cost more than being wrong.
type VerifiedCache struct {
	ttl time.Duration
	max int
	now func() time.Time

	mu      sync.RWMutex
	entries map[[32]byte]cacheEntry

	hits      atomic.Uint64
	misses    atomic.Uint64
	expiries  atomic.Uint64
	revoked   atomic.Uint64
	evictions atomic.Uint64
}

type cacheEntry struct {
	verified *Verified
	until    time.Time
}

// NewVerifiedCache builds a cache holding at most max tokens for at most ttl.
//
// The TTL is the revocation window a deployment is choosing to accept, so it
// belongs to whoever runs the gateway. Thirty seconds is the value tollgate
// ships with; see internal/config.
func NewVerifiedCache(ttl time.Duration, max int) *VerifiedCache {
	if max <= 0 {
		max = 8192
	}
	return &VerifiedCache{
		ttl:     ttl,
		max:     max,
		now:     time.Now,
		entries: make(map[[32]byte]cacheEntry, max/4),
	}
}

// Verify answers from the cache where it can and defers to the verifier
// otherwise.
//
// The cache is keyed by the digest of the token rather than by the token, so
// a heap dump of the gateway does not hand over a set of working credentials.
func (c *VerifiedCache) Verify(ctx context.Context, v *Verifier, raw string, b Binding) (*Verified, error) {
	if len(raw) > MaxTokenBytes {
		// Refuse before hashing. Hashing a megabyte to look it up in a cache
		// it cannot be in is work an attacker gets for free.
		return nil, ErrTooLarge
	}
	key := sha256.Sum256([]byte(raw))

	if hit, ok := c.lookup(v, key); ok {
		// A hit still has to satisfy the certificate binding. Skipping it
		// would mean a bound token, once cached by its rightful holder,
		// becomes spendable by anyone who copies it - which would turn the
		// cache into the exact hole binding exists to close.
		if err := checkBinding(&hit.Claims, b); err != nil {
			return nil, err
		}
		c.hits.Add(1)
		return hit, nil
	}
	c.misses.Add(1)

	verified, err := v.Verify(ctx, raw, b)
	if err != nil {
		// Failures are not cached. A negative cache would be another thing to
		// get wrong, and the errors that are expensive to reach are the ones
		// that already cost a JWKS fetch, which has its own cache.
		return nil, err
	}
	c.store(key, verified)
	return verified, nil
}

func (c *VerifiedCache) lookup(v *Verifier, key [32]byte) (*Verified, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !c.now().Before(entry.until) {
		c.expiries.Add(1)
		c.drop(key)
		return nil, false
	}
	// The key liveness check. An issuer revokes a signing key by removing it
	// from the JWKS; without this, every token that key ever signed would
	// stay good here until its own expiry.
	issuer, ok := v.issuers[entry.verified.Claims.Issuer]
	if !ok || !issuer.Keys.Current().Has(entry.verified.KeyID) {
		c.revoked.Add(1)
		c.drop(key)
		return nil, false
	}
	return entry.verified, true
}

func (c *VerifiedCache) store(key [32]byte, verified *Verified) {
	// Never past the token's own expiry: a cached entry that outlived its
	// token would be the cache inventing authority.
	until := c.now().Add(c.ttl)
	if verified.Claims.ExpiresAt.Before(until) {
		until = verified.Claims.ExpiresAt
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.evictLocked()
	}
	c.entries[key] = cacheEntry{verified: verified, until: until}
}

func (c *VerifiedCache) drop(key [32]byte) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// evictLocked makes room. Expired entries first, because they are free; then
// arbitrary ones, because choosing well is not worth a lock on every read.
func (c *VerifiedCache) evictLocked() {
	now := c.now()
	for k, e := range c.entries {
		if !now.Before(e.until) {
			delete(c.entries, k)
		}
	}
	// Map iteration order is randomised, so this is a random sample rather
	// than whichever entries happen to hash low.
	for k := range c.entries {
		if len(c.entries) < c.max {
			break
		}
		delete(c.entries, k)
		c.evictions.Add(1)
	}
}

// CacheStats is what the gateway exports about the cache.
type CacheStats struct {
	Size   int
	Hits   uint64
	Misses uint64
	// Expiries and Revocations are the two ways an entry stops counting.
	// Revocations is the interesting one: it is how often a key disappearing
	// from a JWKS invalidated a token that was otherwise still good.
	Expiries    uint64
	Revocations uint64
	Evictions   uint64
}

func (c *VerifiedCache) Stats() CacheStats {
	c.mu.RLock()
	size := len(c.entries)
	c.mu.RUnlock()
	return CacheStats{
		Size:        size,
		Hits:        c.hits.Load(),
		Misses:      c.misses.Load(),
		Expiries:    c.expiries.Load(),
		Revocations: c.revoked.Load(),
		Evictions:   c.evictions.Load(),
	}
}

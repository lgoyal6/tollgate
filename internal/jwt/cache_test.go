package jwt

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestACachedTokenSkipsTheSignatureCheck(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	c := NewVerifiedCache(30*time.Second, 128)
	c.now = clk.now
	raw := s.mint(t, header(s), goodClaims(clk))

	for i := 0; i < 10; i++ {
		if _, err := c.Verify(context.Background(), v, raw, Binding{}); err != nil {
			t.Fatal(err)
		}
	}
	st := c.Stats()
	if st.Hits != 9 || st.Misses != 1 {
		t.Fatalf("want 1 miss and 9 hits, got %+v", st)
	}
}

// The window the cache buys is bounded by the token, never by the TTL alone.
//
// Written to tell the two expiries apart. Between exp and exp+skew the token
// is still valid to the verifier but the cache entry is not, so a request in
// that gap must fall through and be re-verified rather than served from the
// cache. Past exp+skew it must fail outright.
func TestACachedEntryNeverOutlivesItsToken(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	c := NewVerifiedCache(time.Hour, 128) // deliberately longer than the token
	c.now = clk.now

	claims := goodClaims(clk)
	claims["exp"] = clk.now().Add(20 * time.Second).Unix()
	raw := s.mint(t, header(s), claims)

	if _, err := c.Verify(context.Background(), v, raw, Binding{}); err != nil {
		t.Fatal(err)
	}

	// Ten seconds past exp, which the verifier still tolerates under the
	// clock skew allowance. The cache must not.
	clk.advance(30 * time.Second)
	if _, err := c.Verify(context.Background(), v, raw, Binding{}); err != nil {
		t.Fatalf("still inside the skew window, so the verifier should accept: %v", err)
	}
	st := c.Stats()
	if st.Expiries == 0 || st.Misses != 2 {
		t.Fatalf("the entry should have expired and been re-verified, got %+v", st)
	}

	// Past exp plus skew: nothing keeps this alive.
	clk.advance(2 * clockSkew)
	if _, err := c.Verify(context.Background(), v, raw, Binding{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

// The sharp case. A signing key is compromised and pulled from the JWKS. Every
// token it ever signed is still inside its own exp and still in the cache. If
// a hit did not re-check that the kid is live, the cache would extend the
// blast radius of the compromise to the end of every token's lifetime.
func TestPullingAKeyFromTheJWKSInvalidatesItsCachedTokens(t *testing.T) {
	compromised := rsaSigner("compromised", RS256)
	kept := otherRSASigner("kept", RS256)

	idp := newFakeIDP(t, keySetJSON(t, compromised, kept))
	src, clk := sourceFor(t, idp, time.Minute, time.Second)
	v, err := NewVerifier([]*Issuer{{
		Name: testIssuer, Audience: testAudience, TenantID: testTenant, Keys: src,
	}})
	if err != nil {
		t.Fatal(err)
	}
	v.now = clk.now

	c := NewVerifiedCache(time.Hour, 128)
	c.now = clk.now

	claims := goodClaims(clk)
	claims["exp"] = clk.now().Add(2 * time.Hour).Unix() // long-lived on purpose
	raw := compromised.mint(t, header(compromised), claims)

	if _, err := c.Verify(context.Background(), v, raw, Binding{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(context.Background(), v, raw, Binding{}); err != nil {
		t.Fatal(err) // still cached, still fine
	}

	// The provider revokes the key. Nothing about the token changed: it is
	// unexpired, correctly signed, and sitting in the cache.
	idp.serve(keySetJSON(t, kept), http.StatusOK)
	clk.advance(2 * time.Minute) // past the key set TTL, so the next lookup refreshes

	// A refresh has to have happened for the gateway to know. Any request
	// naming a live key does it.
	live := kept.mint(t, header(kept), goodClaims(clk))
	if _, err := c.Verify(context.Background(), v, live, Binding{}); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Verify(context.Background(), v, raw, Binding{}); err == nil {
		t.Fatal("a token signed by a revoked key must stop working within one key set refresh, not at its own expiry")
	}
	if st := c.Stats(); st.Revocations != 1 {
		t.Fatalf("want the revocation counted, got %+v", st)
	}
}

// A hit must still satisfy the certificate binding, or the cache becomes the
// hole that binding exists to close.
func TestACacheHitStillHonoursCertificateBinding(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	c := NewVerifiedCache(time.Minute, 128)
	c.now = clk.now

	mine := selfSignedCert(t)
	claims := goodClaims(clk)
	claims["cnf"] = map[string]any{"x5t#S256": Thumbprint(mine)}
	raw := s.mint(t, header(s), claims)

	// The rightful holder warms the cache.
	if _, err := c.Verify(context.Background(), v, raw, Binding{PeerCert: mine}); err != nil {
		t.Fatal(err)
	}
	// A thief replays the same token without the certificate.
	if _, err := c.Verify(context.Background(), v, raw, Binding{}); !errors.Is(err, ErrNotBound) {
		t.Fatalf("want ErrNotBound on a cache hit, got %v", err)
	}
}

func TestFailuresAreNotCached(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	c := NewVerifiedCache(time.Minute, 128)
	c.now = clk.now

	other := otherRSASigner("k1", RS256)
	raw := other.mint(t, header(other), goodClaims(clk))
	for i := 0; i < 3; i++ {
		if _, err := c.Verify(context.Background(), v, raw, Binding{}); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature every time, got %v", err)
		}
	}
	if st := c.Stats(); st.Size != 0 {
		t.Fatalf("nothing should have been stored, got %+v", st)
	}
}

func TestTheCacheStaysUnderItsSizeCap(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	const max = 64
	c := NewVerifiedCache(time.Hour, max)
	c.now = clk.now

	for i := 0; i < max*4; i++ {
		claims := goodClaims(clk)
		claims["jti"] = string(rune('a'+i%26)) + string(rune('a'+i/26))
		if _, err := c.Verify(context.Background(), v, s.mint(t, header(s), claims), Binding{}); err != nil {
			t.Fatal(err)
		}
	}
	if st := c.Stats(); st.Size > max {
		t.Fatalf("cache grew past its cap: %+v", st)
	}
}

func TestTheCacheIsSafeUnderConcurrentUse(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	c := NewVerifiedCache(time.Minute, 32)

	tokens := make([]string, 16)
	for i := range tokens {
		claims := goodClaims(clk)
		claims["jti"] = string(rune('a' + i))
		tokens[i] = s.mint(t, header(s), claims)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := c.Verify(context.Background(), v, tokens[(i+j)%len(tokens)], Binding{}); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// The numbers behind the tradeoff. Run with:
//
//	go test ./internal/jwt/ -run '^$' -bench Verify -benchtime 2s
func BenchmarkVerifyRS256(b *testing.B) { benchVerify(b, rsaSigner("k1", RS256), nil) }
func BenchmarkVerifyES256(b *testing.B) { benchVerify(b, ecSigner("k1", ES256), nil) }
func BenchmarkVerifyPS256(b *testing.B) { benchVerify(b, rsaSigner("k1", PS256), nil) }
func BenchmarkVerifyCachedRS256(b *testing.B) {
	benchVerify(b, rsaSigner("k1", RS256), NewVerifiedCache(30*time.Second, 4096))
}

func benchVerify(b *testing.B, s *signer, c *VerifiedCache) {
	t := &testing.T{}
	v, clk, _ := verifierFor(t, s)
	if t.Failed() {
		b.Fatal("setup failed")
	}
	raw := s.mint(t, header(s), goodClaims(clk))
	ctx := context.Background()

	// Warm the key set and the cache, so the loop measures steady state
	// rather than the first fetch.
	if c == nil {
		if _, err := v.Verify(ctx, raw, Binding{}); err != nil {
			b.Fatal(err)
		}
	} else {
		if _, err := c.Verify(ctx, v, raw, Binding{}); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var err error
			if c == nil {
				_, err = v.Verify(ctx, raw, Binding{})
			} else {
				_, err = c.Verify(ctx, v, raw, Binding{})
			}
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

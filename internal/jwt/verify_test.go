package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

const (
	testIssuer   = "https://issuer.test"
	testAudience = "https://api.tollgate.test"
	testTenant   = "acme"
)

// verifierFor builds a verifier over one issuer served by a fake IdP.
func verifierFor(t *testing.T, signers ...*signer) (*Verifier, *clock, *fakeIDP) {
	t.Helper()
	idp := newFakeIDP(t, keySetJSON(t, signers...))
	src, clk := sourceFor(t, idp, time.Minute, time.Second)
	v, err := NewVerifier([]*Issuer{{
		Name:     testIssuer,
		Audience: testAudience,
		TenantID: testTenant,
		Keys:     src,
	}})
	if err != nil {
		t.Fatal(err)
	}
	v.now = clk.now
	return v, clk, idp
}

func goodClaims(clk *clock) map[string]any {
	now := clk.now()
	return map[string]any{
		"iss":   testIssuer,
		"sub":   "user-1",
		"aud":   testAudience,
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"jti":   "t-1",
		"scope": "read:things write:things",
	}
}

func TestAGoodTokenAuthenticatesItsTenant(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)

	got, err := v.Verify(context.Background(), s.mint(t, header(s), goodClaims(clk)), Binding{})
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != testTenant {
		t.Fatalf("want tenant %q, got %q", testTenant, got.TenantID)
	}
	if got.Claims.Subject != "user-1" || got.KeyID != "k1" {
		t.Fatalf("unexpected verification: %+v", got)
	}
	if !got.Claims.HasScope("write:things") || got.Claims.HasScope("admin") {
		t.Fatalf("scopes did not parse: %v", got.Claims.Scopes)
	}
}

func TestClaimPolicy(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	now := clk.now()

	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{"unknown issuer", func(c map[string]any) { c["iss"] = "https://attacker.test" }, ErrIssuerUnknown},
		{"issuer with a trailing slash is a different issuer",
			func(c map[string]any) { c["iss"] = testIssuer + "/" }, ErrIssuerUnknown},
		{"audience for another resource server",
			func(c map[string]any) { c["aud"] = "https://other.test" }, ErrAudience},
		{"no audience", func(c map[string]any) { delete(c, "aud") }, ErrAudience},
		{"audience array without us",
			func(c map[string]any) { c["aud"] = []string{"a", "b"} }, ErrAudience},
		{"expired", func(c map[string]any) { c["exp"] = now.Add(-2 * time.Hour).Unix() }, ErrExpired},
		{"no exp at all", func(c map[string]any) { delete(c, "exp") }, ErrNoExpiry},
		{"not yet valid", func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }, ErrNotYetValid},
		{"issued in the future", func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() }, ErrFromTheFuture},
		{"no subject", func(c map[string]any) { delete(c, "sub") }, ErrNoSubject},
		{"exp as a string", func(c map[string]any) { c["exp"] = "9999999999" }, ErrMalformed},
		{"aud as a number", func(c map[string]any) { c["aud"] = 7 }, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := goodClaims(clk)
			tc.mutate(c)
			_, err := v.Verify(context.Background(), s.mint(t, header(s), c), Binding{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// An audience array containing us among others is legal and must pass.
func TestAnAudienceArrayThatIncludesUsPasses(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	c := goodClaims(clk)
	c["aud"] = []string{"https://other.test", testAudience}
	if _, err := v.Verify(context.Background(), s.mint(t, header(s), c), Binding{}); err != nil {
		t.Fatal(err)
	}
}

// Both shapes of the scope claim are handled without a per-issuer setting: a
// knob whose correct value is decided by somebody else's product is a knob
// that gets set wrong.
func TestBothScopeClaimShapesParse(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)

	for _, tc := range []struct {
		name  string
		claim string
		value any
	}{
		{"RFC 9068 space-delimited scope", "scope", "a b c"},
		{"array-valued scp", "scp", []string{"a", "b", "c"}},
		{"space-delimited scp", "scp", "a b c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := goodClaims(clk)
			delete(c, "scope")
			c[tc.claim] = tc.value
			got, err := v.Verify(context.Background(), s.mint(t, header(s), c), Binding{})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"a", "b", "c"} {
				if !got.Claims.HasScope(want) {
					t.Fatalf("want scope %q in %v", want, got.Claims.Scopes)
				}
			}
		})
	}
}

// Clock skew is tolerated in both directions but only to the stated bound.
func TestClockSkewIsBoundedNotOpenEnded(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)

	c := goodClaims(clk)
	c["exp"] = clk.now().Add(-30 * time.Second).Unix()
	if _, err := v.Verify(context.Background(), s.mint(t, header(s), c), Binding{}); err != nil {
		t.Fatalf("30s inside the skew window should still pass: %v", err)
	}

	c["exp"] = clk.now().Add(-2 * clockSkew).Unix()
	if _, err := v.Verify(context.Background(), s.mint(t, header(s), c), Binding{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired past the window, got %v", err)
	}
}

// selfSignedCert builds a client certificate for the binding tests.
func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(sharedP256.Curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// RFC 8705. A bearer token is spendable by whoever holds it, which is the
// format's largest weakness: a token in a log or a proxy buffer is a working
// credential. Binding it to a client certificate means stealing the token is
// no longer enough.
func TestCertificateBoundTokens(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	mine := selfSignedCert(t)
	theirs := selfSignedCert(t)

	bound := goodClaims(clk)
	bound["cnf"] = map[string]any{"x5t#S256": Thumbprint(mine)}
	raw := s.mint(t, header(s), bound)

	t.Run("the right certificate", func(t *testing.T) {
		if _, err := v.Verify(context.Background(), raw, Binding{PeerCert: mine}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a stolen token over plain TLS", func(t *testing.T) {
		if _, err := v.Verify(context.Background(), raw, Binding{}); !errors.Is(err, ErrNotBound) {
			t.Fatalf("want ErrNotBound, got %v", err)
		}
	})
	t.Run("a stolen token with the thief's own certificate", func(t *testing.T) {
		if _, err := v.Verify(context.Background(), raw, Binding{PeerCert: theirs}); !errors.Is(err, ErrNotBound) {
			t.Fatalf("want ErrNotBound, got %v", err)
		}
	})
	t.Run("an unbound token is not made to be bound", func(t *testing.T) {
		// The issuer decides which of its tokens are sender-constrained. A
		// gateway that demanded cnf from every issuer could accept tokens
		// from almost none of them.
		if _, err := v.Verify(context.Background(), s.mint(t, header(s), goodClaims(clk)), Binding{}); err != nil {
			t.Fatal(err)
		}
	})
}

// A forged token must not cost a network round trip before it is thrown away.
func TestAnExpiredTokenCostsNoKeyFetch(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, idp := verifierFor(t, s)

	c := goodClaims(clk)
	c["exp"] = clk.now().Add(-time.Hour).Unix()
	if _, err := v.Verify(context.Background(), s.mint(t, header(s), c), Binding{}); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if got := idp.requests.Load(); got != 0 {
		t.Fatalf("checking exp is an integer comparison; it must run first, saw %d fetches", got)
	}
}

func TestAnIncompleteIssuerIsRejectedAtConstruction(t *testing.T) {
	idp := newFakeIDP(t, keySetJSON(t, rsaSigner("k1", RS256)))
	src, _ := sourceFor(t, idp, time.Minute, time.Second)
	for _, iss := range []*Issuer{
		{Audience: "a", TenantID: "t", Keys: src},
		{Name: "n", TenantID: "t", Keys: src},
		{Name: "n", Audience: "a", Keys: src},
		{Name: "n", Audience: "a", TenantID: "t"},
	} {
		if _, err := NewVerifier([]*Issuer{iss}); err == nil {
			t.Fatalf("want an error for %+v", iss)
		}
	}
}

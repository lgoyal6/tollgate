package jwt

import (
	"context"
	"crypto"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// A verifier written by hand is only worth having if it is at least as strict
// as one that thousands of deployments have already attacked. This runs the
// whole adversarial corpus through github.com/golang-jwt/jwt as well, and
// asserts two things:
//
//  1. Nothing this package accepts is refused by golang-jwt. That is the
//     property that matters: over-acceptance is the failure mode of a
//     hand-written verifier, and this rules it out over the corpus.
//  2. Every case where the two disagree is a case where this package is
//     stricter, and carries a written reason. A divergence that is not on the
//     list fails the test, so the list cannot rot as either side changes.
//
// golang-jwt is configured here the way a careful engineer would configure it:
// WithValidMethods, WithIssuer, WithAudience, WithExpirationRequired and
// WithIssuedAt. Comparing against a deliberately misconfigured baseline would
// prove nothing. Note what that means for the headline case: with
// WithValidMethods set, golang-jwt refuses the HS256 confusion attack too.
// The claim is not that it is unsafe, it is that its safety is a property of
// the call site remembering an option, and this package's safety is a property
// of there being no HMAC code to reach.
//
// The comparison is over the verifier only. Both sides are fed the same
// KeySet, so key-set policy - weak moduli, duplicate kids, points off the
// curve - is out of scope here and tested in keys_test.go.

func gojwtParser() *gojwt.Parser {
	return gojwt.NewParser(
		gojwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"}),
		gojwt.WithIssuer(testIssuer),
		gojwt.WithAudience(testAudience),
		gojwt.WithExpirationRequired(),
		gojwt.WithIssuedAt(),
	)
}

// keyfuncFrom is the realistic keyfunc: look the kid up in the same key set
// this package uses, and refuse if it is not there.
func keyfuncFrom(set *KeySet) gojwt.Keyfunc {
	return func(tok *gojwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		key, err := set.Lookup(kid)
		if err != nil {
			return nil, err
		}
		return key.Pub.(crypto.PublicKey), nil
	}
}

func TestDifferentialAgainstGolangJWT(t *testing.T) {
	s := rsaSigner("k1", RS256)
	ec := ecSigner("ec1", ES256)
	v, clk, _ := verifierFor(t, s, ec)
	set := keySet(t, s, ec)

	// golang-jwt reads the wall clock, so wind the fake clock to now. The
	// corpus's time-based cases are built relative to clk, which keeps them
	// meaningful to both verifiers.
	clk.mu.Lock()
	clk.t = time.Now()
	clk.mu.Unlock()

	parser := gojwtParser()
	keyfunc := keyfuncFrom(set)

	var divergences int
	for _, tc := range corpus() {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.build(t, clk)

			_, mineErr := v.Verify(context.Background(), raw, Binding{})
			_, theirsErr := parser.Parse(raw, keyfunc)

			if mineErr == nil {
				t.Fatalf("this package accepted an attack token (%s)", tc.class)
			}
			theyAccepted := theirsErr == nil

			switch {
			case !theyAccepted && tc.golangJWTAccepts:
				t.Fatalf("this case is recorded as a divergence but golang-jwt now "+
					"refuses it too (%v). Remove the golangJWTAccepts flag.", theirsErr)
			case theyAccepted && !tc.golangJWTAccepts:
				t.Fatalf("golang-jwt accepts this and the corpus does not say so. "+
					"Either it is a genuine divergence that needs a written reason, "+
					"or the case is not testing what it claims (%s).", tc.class)
			case theyAccepted:
				if tc.why == "" {
					t.Fatal("a divergence without a reason is not a decision")
				}
				divergences++
			}
		})
	}

	// A differential with no divergences means the corpus is not exercising
	// anything the two implementations disagree about, which would make this
	// test decoration.
	if divergences == 0 {
		t.Fatal("no divergences found, so this test is not measuring anything")
	}
	t.Logf("%d of %d corpus cases are refused only here", divergences, len(corpus()))
}

// The other direction: a token both implementations should accept. Without
// this, a verifier that refuses everything passes the differential.
func TestBothImplementationsAcceptAGoodToken(t *testing.T) {
	s := rsaSigner("k1", RS256)
	v, clk, _ := verifierFor(t, s)
	set := keySet(t, s)
	clk.mu.Lock()
	clk.t = time.Now()
	clk.mu.Unlock()

	raw := s.mint(t, header(s), goodClaims(clk))
	if _, err := v.Verify(context.Background(), raw, Binding{}); err != nil {
		t.Fatalf("this package: %v", err)
	}
	if _, err := gojwtParser().Parse(raw, keyfuncFrom(set)); err != nil {
		t.Fatalf("golang-jwt: %v", err)
	}
}

package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func plainClaims() map[string]any {
	return map[string]any{"iss": "https://issuer.test", "sub": "u1", "exp": 4102444800}
}

func header(s *signer) map[string]any {
	return map[string]any{"alg": string(s.alg), "kid": s.kid, "typ": "JWT"}
}

// verifyWith is the raw parse-then-check-signature path, without any of the
// claim policy that Verifier adds. These tests are about the JWS layer.
func verifyWith(t *testing.T, set *KeySet, raw string) error {
	t.Helper()
	tok, err := Parse(raw)
	if err != nil {
		return err
	}
	key, err := set.Lookup(tok.Header.Kid)
	if err != nil {
		return err
	}
	return tok.Verify(key.Pub, key.Alg)
}

func TestEverySupportedAlgorithmRoundTrips(t *testing.T) {
	for _, alg := range []Algorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384} {
		t.Run(string(alg), func(t *testing.T) {
			var s *signer
			if strings.HasPrefix(string(alg), "ES") {
				s = ecSigner("k1", alg)
			} else {
				s = rsaSigner("k1", alg)
			}
			set := keySet(t, s)
			raw := s.mint(t, header(s), plainClaims())
			if err := verifyWith(t, set, raw); err != nil {
				t.Fatalf("a token this package signed should verify: %v", err)
			}
		})
	}
}

func TestAValidSignatureFromTheWrongKeyIsRefused(t *testing.T) {
	good := rsaSigner("k1", RS256)
	// Same kid, different private key: the forger knows which key id to claim.
	impostor := otherRSASigner("k1", RS256)
	set := keySet(t, good)
	raw := impostor.mint(t, header(impostor), plainClaims())
	if err := verifyWith(t, set, raw); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestTamperedPayloadIsRefused(t *testing.T) {
	s := rsaSigner("k1", RS256)
	set := keySet(t, s)
	raw := s.mint(t, header(s), plainClaims())

	parts := strings.Split(raw, ".")
	forged, err := json.Marshal(map[string]any{"iss": "https://issuer.test", "sub": "admin", "exp": 4102444800})
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = b64.EncodeToString(forged)
	if err := verifyWith(t, set, strings.Join(parts, ".")); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

// The classic confusion attack: take the RSA public key, which is public, and
// use its bytes as an HMAC secret. It works against any verifier that lets the
// token's `alg` choose the verification function. This package has no HMAC
// code at all, so the attack is refused at the algorithm check rather than at
// a comparison that somebody could later get wrong.
func TestRS256ToHS256ConfusionIsRefused(t *testing.T) {
	s := rsaSigner("k1", RS256)
	set := keySet(t, s)

	secret := s.publicKeyPKIX(t)
	h := map[string]any{"alg": "HS256", "kid": s.kid, "typ": "JWT"}
	signingInput := encodeSegments(t, h, plainClaims())
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	raw := signingInput + "." + b64.EncodeToString(mac.Sum(nil))

	if err := verifyWith(t, set, raw); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("want ErrUnsupportedAlg, got %v", err)
	}
}

// A token whose header names an algorithm the key is not published for. The
// key is the same RSA key either way, so this is not a cryptographic failure:
// it is the policy that a key does one job.
func TestHeaderAlgorithmMustMatchTheKeysAlgorithm(t *testing.T) {
	s := rsaSigner("k1", RS256)
	set := keySet(t, s) // publishes alg: RS256

	ps := rsaSigner("k1", PS256) // same private key, signs PS256
	raw := ps.mint(t, header(ps), plainClaims())

	if err := verifyWith(t, set, raw); !errors.Is(err, ErrAlgMismatch) {
		t.Fatalf("want ErrAlgMismatch, got %v", err)
	}
}

func TestStructuralRefusals(t *testing.T) {
	s := rsaSigner("k1", RS256)
	valid := s.mint(t, header(s), plainClaims())
	parts := strings.Split(valid, ".")

	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"empty", "", ErrMalformed},
		{"one segment", parts[0], ErrMalformed},
		{"two segments", parts[0] + "." + parts[1], ErrMalformed},
		{"four segments", valid + "." + parts[2], ErrMalformed},
		{"empty signature segment", parts[0] + "." + parts[1] + ".", ErrMalformed},
		{"empty header segment", "." + parts[1] + "." + parts[2], ErrMalformed},
		{"not base64", "!!!." + parts[1] + "." + parts[2], ErrMalformed},
		{"oversized", strings.Repeat("a", MaxTokenBytes+1), ErrTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// JWS forbids base64 padding, and Go's decoder is happy to be lenient about
// the unused bits in the final quantum unless told not to be. Both make one
// token have several spellings, which matters to anything downstream that
// keys on the raw string.
func TestBase64MustBeRawAndStrict(t *testing.T) {
	s := rsaSigner("k1", RS256)
	raw := s.mint(t, header(s), plainClaims())
	parts := strings.Split(raw, ".")

	t.Run("padded segment", func(t *testing.T) {
		h, err := json.Marshal(header(s))
		if err != nil {
			t.Fatal(err)
		}
		padHeader := padded.EncodeToString(h)
		if !strings.Contains(padHeader, "=") {
			t.Skip("this header happens to encode without padding")
		}
		if _, err := Parse(padHeader + "." + parts[1] + "." + parts[2]); !errors.Is(err, ErrMalformed) {
			t.Fatalf("want ErrMalformed, got %v", err)
		}
	})

	t.Run("non-canonical trailing bits", func(t *testing.T) {
		// "eyJ" style prefixes end on a quantum boundary, so build a segment
		// whose final character sets bits the decoder should be discarding.
		// 'A' and 'B' decode to the same byte under lenient decoding.
		lenient := b64.EncodeToString([]byte{0xff})
		mutated := lenient[:len(lenient)-1] + "B"
		if mutated == lenient {
			t.Skip("no alternative spelling for this quantum")
		}
		if _, err := Parse(mutated + "." + parts[1] + "." + parts[2]); !errors.Is(err, ErrMalformed) {
			t.Fatalf("want ErrMalformed, got %v", err)
		}
	})
}

func TestHeaderPolicy(t *testing.T) {
	s := rsaSigner("k1", RS256)

	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{"alg none", func(h map[string]any) { h["alg"] = "none" }, ErrUnsupportedAlg},
		{"alg HS256", func(h map[string]any) { h["alg"] = "HS256" }, ErrUnsupportedAlg},
		{"alg absent", func(h map[string]any) { delete(h, "alg") }, ErrUnsupportedAlg},
		{"embedded jwk", func(h map[string]any) { h["jwk"] = map[string]any{"kty": "RSA"} }, ErrHeaderKey},
		{"jku url", func(h map[string]any) { h["jku"] = "https://attacker.test/keys" }, ErrHeaderKey},
		{"x5u url", func(h map[string]any) { h["x5u"] = "https://attacker.test/c.pem" }, ErrHeaderKey},
		{"x5c chain", func(h map[string]any) { h["x5c"] = []string{"MIIB"} }, ErrHeaderKey},
		{"crit", func(h map[string]any) { h["crit"] = []string{"exp"} }, ErrCritical},
		{"enc means JWE", func(h map[string]any) { h["enc"] = "A128GCM" }, ErrMalformed},
		{"no kid", func(h map[string]any) { delete(h, "kid") }, ErrNoKeyID},
		{"foreign typ", func(h map[string]any) { h["typ"] = "id_token+jwt" }, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := header(s)
			tc.mutate(h)
			raw := s.mint(t, h, plainClaims())
			if _, err := Parse(raw); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// encoding/json takes the last of a repeated member without complaint, so two
// parsers reading the same token can disagree about what it says.
func TestDuplicateMembersAreRefused(t *testing.T) {
	claims := b64.EncodeToString([]byte(`{"sub":"u1","exp":4102444800}`))

	t.Run("header", func(t *testing.T) {
		h := b64.EncodeToString([]byte(`{"alg":"RS256","kid":"k1","alg":"none"}`))
		if _, err := Parse(h + "." + claims + ".AAAA"); !errors.Is(err, ErrDuplicateField) {
			t.Fatalf("want ErrDuplicateField, got %v", err)
		}
	})

	t.Run("claims", func(t *testing.T) {
		h := b64.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`))
		dup := b64.EncodeToString([]byte(`{"sub":"u1","sub":"admin","exp":4102444800}`))
		tok, err := Parse(h + "." + dup + ".AAAA")
		if err != nil {
			t.Fatalf("the header is fine, so Parse should get as far as the claims: %v", err)
		}
		if err := checkNoDuplicateMembers(tok.claims); !errors.Is(err, ErrDuplicateField) {
			t.Fatalf("want ErrDuplicateField, got %v", err)
		}
	})

	t.Run("nested objects are not top-level keys", func(t *testing.T) {
		// The walk must not mistake a member of a nested object for a repeat
		// of a top-level one.
		body := []byte(`{"a":{"b":1},"b":{"b":2},"c":[{"b":3},{"b":4}]}`)
		if err := checkNoDuplicateMembers(body); err != nil {
			t.Fatalf("nested repeats are legal: %v", err)
		}
	})
}

func TestECDSASignatureEncoding(t *testing.T) {
	s := ecSigner("k1", ES256)
	set := keySet(t, s)
	h := header(s)
	c := plainClaims()
	signingInput := encodeSegments(t, h, c)

	t.Run("DER is refused", func(t *testing.T) {
		// A DER signature is a valid ECDSA signature and an invalid JWS one.
		// Accepting it would give a single credential many wire forms.
		der := s.signASN1(t, ES256, []byte(signingInput))
		raw := mintWithSignature(t, h, c, der)
		if err := verifyWith(t, set, raw); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got %v", err)
		}
	})

	t.Run("wrong width is refused", func(t *testing.T) {
		sig := s.sign(t, ES256, []byte(signingInput))
		raw := mintWithSignature(t, h, c, sig[:len(sig)-1])
		if err := verifyWith(t, set, raw); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got %v", err)
		}
	})

	t.Run("zero signature is refused", func(t *testing.T) {
		raw := mintWithSignature(t, h, c, make([]byte, 64))
		if err := verifyWith(t, set, raw); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got %v", err)
		}
	})
}

// A P-256 token verified against a P-384 key and the other way round. The
// curve is what fixes the algorithm, so this is caught before any arithmetic.
func TestCurveIsBoundToAlgorithm(t *testing.T) {
	p256 := ecSigner("k1", ES256)
	p384 := ecSigner("k1", ES384)
	set := keySet(t, p384) // the published key is P-384, so alg is ES384
	raw := p256.mint(t, header(p256), plainClaims())
	if err := verifyWith(t, set, raw); !errors.Is(err, ErrAlgMismatch) {
		t.Fatalf("want ErrAlgMismatch, got %v", err)
	}
}

func TestUnknownKidIsNotAFallbackToTheOtherKeys(t *testing.T) {
	s := rsaSigner("k1", RS256)
	set := keySet(t, s)
	h := header(s)
	h["kid"] = "k-does-not-exist"
	raw := s.mint(t, h, plainClaims())
	if err := verifyWith(t, set, raw); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

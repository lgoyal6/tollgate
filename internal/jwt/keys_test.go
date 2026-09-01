package jwt

import (
	"encoding/json"
	"errors"
	"testing"
)

func jwksWith(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	out, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestKeySetSkipsWhatItCannotUseAndKeepsTheRest(t *testing.T) {
	good := rsaSigner("good", RS256).jwk()
	set, err := ParseKeySet(jwksWith(t,
		good,
		map[string]any{"kty": "oct", "kid": "symmetric", "k": "AAAA"},
		map[string]any{"kty": "OKP", "kid": "ed25519", "crv": "Ed25519", "x": "AAAA"},
		map[string]any{"kty": "RSA", "kid": "for-encryption", "use": "enc", "n": good["n"], "e": good["e"]},
	))
	if err != nil {
		t.Fatalf("a set with one usable key is usable: %v", err)
	}
	// A real key set holds keys for jobs this gateway does not do. Refusing
	// the document because of them would make an unrelated change at the IdP
	// an outage here.
	if set.Len() != 1 || !set.Has("good") {
		t.Fatalf("want just the signing key, got %v", set.IDs())
	}
}

func TestAKeySetWithNothingUsableIsAnError(t *testing.T) {
	_, err := ParseKeySet(jwksWith(t, map[string]any{"kty": "oct", "kid": "s", "k": "AAAA"}))
	if !errors.Is(err, ErrEmptyKeySet) {
		// Silently installing an empty set would turn a misconfigured JWKS
		// URL into "every token is invalid" with no signal saying why.
		t.Fatalf("want ErrEmptyKeySet, got %v", err)
	}
}

func TestTwoKeysWithOneKidRefuseTheWholeDocument(t *testing.T) {
	a := rsaSigner("dup", RS256).jwk()
	b := otherRSASigner("dup", RS256).jwk()
	if _, err := ParseKeySet(jwksWith(t, a, b)); !errors.Is(err, ErrBadJWK) {
		// Which key wins would otherwise depend on map iteration order.
		t.Fatalf("want ErrBadJWK, got %v", err)
	}
}

func TestWeakRSAKeysAreNotInstalled(t *testing.T) {
	weak := weakRSASigner("weak").jwk()
	if _, err := ParseKeySet(jwksWith(t, weak)); !errors.Is(err, ErrEmptyKeySet) {
		t.Fatalf("a 1024-bit key must not be usable, got %v", err)
	}
}

func TestRSAJWKPolicy(t *testing.T) {
	base := rsaSigner("k1", RS256).jwk()
	with := func(mutate func(map[string]any)) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		mutate(out)
		return out
	}

	cases := []struct {
		name string
		key  map[string]any
	}{
		{"no kid", with(func(m map[string]any) { delete(m, "kid") })},
		{"leading zero in modulus", with(func(m map[string]any) {
			// RFC 7518 6.3.1.1 wants the minimum octets. Without that rule one
			// key has unboundedly many spellings.
			raw, _ := b64.DecodeString(base["n"].(string))
			m["n"] = b64.EncodeToString(append([]byte{0x00}, raw...))
		})},
		{"even exponent", with(func(m map[string]any) { m["e"] = b64.EncodeToString([]byte{0x02}) })},
		{"exponent 1", with(func(m map[string]any) { m["e"] = b64.EncodeToString([]byte{0x01}) })},
		{"unsupported alg", with(func(m map[string]any) { m["alg"] = "HS256" })},
		{"key_ops without verify", with(func(m map[string]any) { m["key_ops"] = []string{"encrypt"} })},
		{"padded base64 modulus", with(func(m map[string]any) {
			raw, _ := b64.DecodeString(base["n"].(string))
			m["n"] = padded.EncodeToString(raw)
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKeySet(jwksWith(t, tc.key)); err == nil {
				t.Fatal("this key should not have installed")
			}
		})
	}
}

func TestRSAJWKWithoutAlgIsRS256Only(t *testing.T) {
	k := rsaSigner("k1", RS256).jwk()
	delete(k, "alg")
	set, err := ParseKeySet(jwksWith(t, k))
	if err != nil {
		t.Fatal(err)
	}
	key, err := set.Lookup("k1")
	if err != nil {
		t.Fatal(err)
	}
	if key.Alg != RS256 {
		t.Fatalf("want RS256, got %s", key.Alg)
	}
	// The consequence: a PS256 token against that key is refused rather than
	// quietly accepted, which is the direction an unstated algorithm should
	// fail in.
	ps := rsaSigner("k1", PS256)
	if err := verifyWith(t, set, ps.mint(t, header(ps), plainClaims())); !errors.Is(err, ErrAlgMismatch) {
		t.Fatalf("want ErrAlgMismatch, got %v", err)
	}
}

func TestECJWKPolicy(t *testing.T) {
	base := ecSigner("k1", ES256).jwk()
	with := func(mutate func(map[string]any)) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		mutate(out)
		return out
	}

	cases := []struct {
		name string
		key  map[string]any
	}{
		{"unsupported curve", with(func(m map[string]any) { m["crv"] = "P-521" })},
		{"alg contradicts curve", with(func(m map[string]any) { m["alg"] = "ES384" })},
		{"short coordinate", with(func(m map[string]any) {
			raw, _ := b64.DecodeString(base["x"].(string))
			m["x"] = b64.EncodeToString(raw[1:])
		})},
		{"point not on the curve", with(func(m map[string]any) {
			raw, _ := b64.DecodeString(base["y"].(string))
			raw[len(raw)-1] ^= 0x01
			m["y"] = b64.EncodeToString(raw)
		})},
		{"point at infinity", with(func(m map[string]any) {
			m["x"] = b64.EncodeToString(make([]byte, 32))
			m["y"] = b64.EncodeToString(make([]byte, 32))
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKeySet(jwksWith(t, tc.key)); err == nil {
				t.Fatal("this key should not have installed")
			}
		})
	}
}

func TestKeySetSizeIsBounded(t *testing.T) {
	// The document comes from a remote host. Without a bound that host, or
	// anyone who can answer for it, chooses how much memory this process holds.
	keys := make([]map[string]any, 0, maxKeysPerSet+1)
	for i := 0; i <= maxKeysPerSet; i++ {
		k := rsaSigner("k", RS256).jwk()
		k["kid"] = string(rune('a'+i%26)) + string(rune('a'+i/26))
		keys = append(keys, k)
	}
	if _, err := ParseKeySet(jwksWith(t, keys...)); !errors.Is(err, ErrBadJWK) {
		t.Fatalf("want ErrBadJWK, got %v", err)
	}
}

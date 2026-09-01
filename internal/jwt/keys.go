package jwt

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
)

// Key set failures.
var (
	ErrBadJWK      = errors.New("jwt: malformed JWK")
	ErrWeakKey     = errors.New("jwt: key is too weak to trust")
	ErrUnknownKey  = errors.New("jwt: no key with that kid")
	ErrEmptyKeySet = errors.New("jwt: key set has no usable keys")
)

// minRSABits is the floor for an RSA modulus.
//
// RFC 7518 section 4.2 requires 2048 for RS256, and a 1024-bit modulus is
// within reach of an attacker who wants it. Accepting a short key because an
// issuer published one would make the gateway's security a property of
// somebody else's config.
const minRSABits = 2048

// maxKeysPerSet bounds how many keys one JWKS document may install. A key set
// is fetched from a remote host; without a bound, that host - or anyone who
// can answer for it - chooses how much memory the gateway holds.
const maxKeysPerSet = 32

// Key is one public key together with the single algorithm it may verify.
//
// One algorithm, not a set. This is the invariant the whole package rests on:
// the token's `alg` header never selects a verifier, it is only ever compared
// against this field. See the package comment.
type Key struct {
	ID  string
	Alg Algorithm
	Pub crypto.PublicKey
}

// KeySet is an immutable set of verification keys indexed by `kid`.
type KeySet struct {
	byID map[string]*Key
}

// Lookup finds the key a token names. Missing is an error, never a fallback:
// a verifier that tries the other keys turns an unknown kid into N public key
// operations and makes the set only as strong as its weakest member.
func (s *KeySet) Lookup(kid string) (*Key, error) {
	if s == nil {
		return nil, ErrUnknownKey
	}
	key, ok := s.byID[kid]
	if !ok {
		return nil, ErrUnknownKey
	}
	return key, nil
}

// Has reports whether a kid is still in this set.
//
// Exists for the verified-token cache: a cache hit has to re-establish that
// the key which signed the token is still one the issuer publishes, or a key
// revoked at the IdP would keep buying access until the token's own expiry.
func (s *KeySet) Has(kid string) bool {
	if s == nil {
		return false
	}
	_, ok := s.byID[kid]
	return ok
}

// IDs returns the kids in the set, for logging and tests.
func (s *KeySet) IDs() []string {
	out := make([]string, 0, len(s.byID))
	for id := range s.byID {
		out = append(out, id)
	}
	return out
}

func (s *KeySet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byID)
}

// jwk is the wire form of one key. Only the members this package acts on.
type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Alg    string   `json:"alg"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`

	N string `json:"n"` // RSA modulus
	E string `json:"e"` // RSA exponent

	Crv string `json:"crv"` // EC curve
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// ParseKeySet reads a JWKS document.
//
// Keys it cannot use are skipped rather than fatal: a real key set holds
// encryption keys and algorithms this gateway does not verify, and refusing
// the whole document because one member is an X25519 key would make an
// unrelated change at the IdP an outage here. A document with no usable key
// at all is an error, because that is indistinguishable from a misconfigured
// endpoint and should not silently become "nothing verifies".
func ParseKeySet(data []byte) (*KeySet, error) {
	var doc jwkSet
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, ErrBadJWK
	}
	if len(doc.Keys) > maxKeysPerSet {
		return nil, ErrBadJWK
	}
	set := &KeySet{byID: make(map[string]*Key, len(doc.Keys))}
	for i := range doc.Keys {
		key, err := parseJWK(&doc.Keys[i])
		if err != nil {
			continue
		}
		if _, dup := set.byID[key.ID]; dup {
			// Two keys claiming one kid makes "the key this token names"
			// ambiguous, and which one wins would depend on map iteration
			// order. Refuse the document rather than pick.
			return nil, ErrBadJWK
		}
		set.byID[key.ID] = key
	}
	if len(set.byID) == 0 {
		return nil, ErrEmptyKeySet
	}
	return set, nil
}

func parseJWK(k *jwk) (*Key, error) {
	if k.Kid == "" {
		return nil, ErrBadJWK
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, ErrBadJWK
	}
	if len(k.KeyOps) > 0 && !contains(k.KeyOps, "verify") {
		return nil, ErrBadJWK
	}
	switch k.Kty {
	case "RSA":
		return parseRSAJWK(k)
	case "EC":
		return parseECJWK(k)
	default:
		return nil, ErrBadJWK
	}
}

// parseRSAJWK builds an RSA verification key.
//
// An RSA JWK that does not declare `alg` is treated as RS256 and nothing else.
// RS256 is RFC 7518's mandatory-to-implement RSA algorithm and what every IdP
// in practice publishes; an issuer that signs with PS256 and does not say so
// is refused. That is the right way round: the cost of being wrong here is a
// 401 against a misconfigured issuer, and the cost of guessing generously is
// that "the algorithm comes from the key" stops being true.
func parseRSAJWK(k *jwk) (*Key, error) {
	alg := Algorithm(k.Alg)
	if k.Alg == "" {
		alg = RS256
	}
	switch alg {
	case RS256, RS384, RS512, PS256, PS384, PS512:
	default:
		return nil, ErrBadJWK
	}

	nBytes, err := decodeUInt(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := decodeUInt(k.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if n.BitLen() < minRSABits {
		return nil, ErrWeakKey
	}
	// e must be an odd integer strictly between 1 and n. crypto/rsa stores it
	// as an int, so anything that does not fit is refused rather than
	// truncated into something that would silently verify differently.
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Bit(0) == 0 {
		return nil, ErrBadJWK
	}
	return &Key{
		ID:  k.Kid,
		Alg: alg,
		Pub: &rsa.PublicKey{N: n, E: int(e.Int64())},
	}, nil
}

// parseECJWK builds an EC verification key.
//
// The curve fixes the algorithm outright, so an EC key cannot be talked into
// a different digest by anything a token says. A declared `alg` that
// contradicts the curve is a contradiction in the key set and is refused.
func parseECJWK(k *jwk) (*Key, error) {
	var (
		curve elliptic.Curve
		ecdhC ecdh.Curve
		alg   Algorithm
		size  int
	)
	switch k.Crv {
	case "P-256":
		curve, ecdhC, alg, size = elliptic.P256(), ecdh.P256(), ES256, 32
	case "P-384":
		curve, ecdhC, alg, size = elliptic.P384(), ecdh.P384(), ES384, 48
	default:
		return nil, ErrBadJWK
	}
	if k.Alg != "" && Algorithm(k.Alg) != alg {
		return nil, ErrBadJWK
	}

	// RFC 7518 section 6.2.1.2: coordinates are zero-padded to the full
	// coordinate size. A short encoding is a different spelling of the same
	// point, and accepting both would give one key two wire forms.
	x, err := decodeFixed(k.X, size)
	if err != nil {
		return nil, err
	}
	y, err := decodeFixed(k.Y, size)
	if err != nil {
		return nil, err
	}

	// Validate through crypto/ecdh, which rejects a point that is not on the
	// curve and rejects the point at infinity. Constructing an ecdsa.PublicKey
	// from unchecked coordinates and calling ecdsa.Verify on it is undefined
	// behaviour by that package's own documentation.
	point := append([]byte{0x04}, append(x, y...)...)
	if _, err := ecdhC.NewPublicKey(point); err != nil {
		return nil, ErrBadJWK
	}
	return &Key{
		ID:  k.Kid,
		Alg: alg,
		Pub: &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
	}, nil
}

// decodeUInt decodes a base64url big-endian unsigned integer.
//
// RFC 7518 section 6.3.1.1 requires the minimum number of octets, so a leading
// zero byte is refused. Without that, one RSA key has unboundedly many JWK
// spellings, which matters to anything that compares key material rather than
// parsing it.
func decodeUInt(s string) ([]byte, error) {
	if s == "" {
		return nil, ErrBadJWK
	}
	out, err := b64.DecodeString(s)
	if err != nil || len(out) == 0 || out[0] == 0x00 {
		return nil, ErrBadJWK
	}
	return out, nil
}

// decodeFixed decodes a base64url value that must be exactly size bytes.
func decodeFixed(s string, size int) ([]byte, error) {
	if s == "" {
		return nil, ErrBadJWK
	}
	out, err := b64.DecodeString(s)
	if err != nil || len(out) != size {
		return nil, ErrBadJWK
	}
	return out, nil
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

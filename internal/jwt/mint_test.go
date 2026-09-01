package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

// Test signing side. The package only verifies, so the tests need their own
// issuer: a verifier tested against tokens produced by the same code that
// verifies them is testing a round trip, not a format.

type signer struct {
	kid     string
	alg     Algorithm
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
	tooWeak bool // 1024-bit RSA, for the weak key test
}

// Generated once per process. RSA-2048 keygen is ~50ms and the corpus mints
// dozens of tokens; regenerating per case would dominate the suite.
var (
	sharedRSA  *rsa.PrivateKey
	sharedRSA2 *rsa.PrivateKey
	weakRSA    *rsa.PrivateKey
	sharedP256 *ecdsa.PrivateKey
	sharedP384 *ecdsa.PrivateKey
)

func init() {
	var err error
	if sharedRSA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	if sharedRSA2, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	if weakRSA, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		panic(err)
	}
	if sharedP256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		panic(err)
	}
	if sharedP384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
		panic(err)
	}
}

func rsaSigner(kid string, alg Algorithm) *signer {
	return &signer{kid: kid, alg: alg, rsaKey: sharedRSA}
}

func otherRSASigner(kid string, alg Algorithm) *signer {
	return &signer{kid: kid, alg: alg, rsaKey: sharedRSA2}
}

func weakRSASigner(kid string) *signer {
	return &signer{kid: kid, alg: RS256, rsaKey: weakRSA, tooWeak: true}
}

func ecSigner(kid string, alg Algorithm) *signer {
	s := &signer{kid: kid, alg: alg}
	if alg == ES384 {
		s.ecKey = sharedP384
	} else {
		s.ecKey = sharedP256
	}
	return s
}

// jwk renders this signer's public half as a JWKS member.
func (s *signer) jwk() map[string]any {
	if s.rsaKey != nil {
		return map[string]any{
			"kty": "RSA",
			"kid": s.kid,
			"alg": string(s.alg),
			"use": "sig",
			"n":   b64.EncodeToString(s.rsaKey.N.Bytes()),
			"e":   b64.EncodeToString(big.NewInt(int64(s.rsaKey.E)).Bytes()),
		}
	}
	size := (s.ecKey.Curve.Params().BitSize + 7) / 8
	crv := "P-256"
	if size == 48 {
		crv = "P-384"
	}
	return map[string]any{
		"kty": "EC",
		"kid": s.kid,
		"crv": crv,
		"use": "sig",
		"x":   b64.EncodeToString(leftPad(s.ecKey.X.Bytes(), size)),
		"y":   b64.EncodeToString(leftPad(s.ecKey.Y.Bytes(), size)),
	}
}

// keySetJSON renders a JWKS document holding these signers.
func keySetJSON(t *testing.T, signers ...*signer) []byte {
	t.Helper()
	keys := make([]map[string]any, 0, len(signers))
	for _, s := range signers {
		keys = append(keys, s.jwk())
	}
	out, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func keySet(t *testing.T, signers ...*signer) *KeySet {
	t.Helper()
	set, err := ParseKeySet(keySetJSON(t, signers...))
	if err != nil {
		t.Fatalf("building key set: %v", err)
	}
	return set
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// mint builds a signed compact JWS. header and claims are written as given, so
// a test can put anything at all in either.
func (s *signer) mint(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	signingInput := encodeSegments(t, header, claims)
	sig := s.sign(t, s.alg, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(sig)
}

// mintWithSignature builds a token whose signature is supplied verbatim, for
// forgeries that are not simply "signed by the wrong key".
func mintWithSignature(t *testing.T, header, claims map[string]any, sig []byte) string {
	t.Helper()
	return encodeSegments(t, header, claims) + "." + b64.EncodeToString(sig)
}

func encodeSegments(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(h) + "." + b64.EncodeToString(c)
}

func (s *signer) sign(t *testing.T, alg Algorithm, input []byte) []byte {
	t.Helper()
	h, ok := hashFor(alg)
	if !ok {
		t.Fatalf("test signer cannot produce %s", alg)
	}
	sum := digest(h, input)
	switch alg {
	case RS256, RS384, RS512:
		sig, err := rsa.SignPKCS1v15(rand.Reader, s.rsaKey, h, sum)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case PS256, PS384, PS512:
		sig, err := rsa.SignPSS(rand.Reader, s.rsaKey, h, sum, &rsa.PSSOptions{
			SaltLength: h.Size(), Hash: h,
		})
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case ES256, ES384:
		r, ss, err := ecdsa.Sign(rand.Reader, s.ecKey, sum)
		if err != nil {
			t.Fatal(err)
		}
		size := (s.ecKey.Curve.Params().BitSize + 7) / 8
		return append(leftPad(r.Bytes(), size), leftPad(ss.Bytes(), size)...)
	}
	t.Fatalf("unreachable alg %s", alg)
	return nil
}

// signASN1 produces the DER form of an ECDSA signature, which RFC 7518 does
// not use and this package must refuse.
func (s *signer) signASN1(t *testing.T, alg Algorithm, input []byte) []byte {
	t.Helper()
	h, _ := hashFor(alg)
	sum := digest(h, input)
	sig, err := ecdsa.SignASN1(rand.Reader, s.ecKey, sum)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// publicKeyDER is the RSA public key in the shape an algorithm-confusion
// attack would use as an HMAC secret.
func (s *signer) publicKeyPKIX(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(s.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (s *signer) publicKey() crypto.PublicKey {
	if s.rsaKey != nil {
		return &s.rsaKey.PublicKey
	}
	return &s.ecKey.PublicKey
}

// padded is base64 *with* padding, which JWS forbids.
var padded = base64.URLEncoding

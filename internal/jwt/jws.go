// Package jwt verifies JWS-signed JSON Web Tokens presented to the gateway.
//
// # Why this is not a library call
//
// Every interesting way a JWT deployment fails is in the part a library either
// gets wrong or hands straight back to the caller: which algorithm the token
// is allowed to be signed with, which key that algorithm is allowed to use,
// what the header is allowed to say, and what happens when the key set moves.
// A verifier that is one `Parse` call away from correct is also one
// misconfiguration away from accepting `alg: none`. So the policy is spelled
// out here, in code, where it can be attacked by a test.
//
// # Three structural decisions
//
// **No symmetric algorithms exist in this package.** There is no HMAC code
// path at all. The classic RS256-to-HS256 confusion attack works by getting a
// verifier to treat an RSA public key as an HMAC secret; that attack cannot be
// expressed against a verifier that cannot compute an HMAC. This is a
// capability removed rather than a check added, and checks are what get
// bypassed.
//
// **The algorithm comes from the key, not from the token.** A JWK declares
// what it may be used for, either explicitly through its own `alg` member or
// implicitly through its curve. The token's `alg` header is only ever compared
// against that; it never selects a verifier. An attacker who controls the
// header therefore controls nothing.
//
// **A key is found by `kid` or not at all.** Trying every key in the set until
// one verifies turns a key set holding one weak key into a key set that is as
// weak as its weakest member, and turns an unknown `kid` into N public key
// operations. Tokens without a `kid` are refused.
//
// The header members that carry keys - `jwk`, `jku`, `x5u`, `x5c` - are
// refused outright rather than ignored. Ignoring them is correct today and
// becomes a vulnerability the moment somebody adds a code path that reads the
// header for something else.
package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
)

// Algorithm is a JWS algorithm this package is prepared to verify. Asymmetric
// only, deliberately: see the package comment.
type Algorithm string

const (
	RS256 Algorithm = "RS256" // RSASSA-PKCS1-v1_5 with SHA-256
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS256 Algorithm = "PS256" // RSASSA-PSS with SHA-256
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256" // ECDSA on P-256 with SHA-256
	ES384 Algorithm = "ES384" // ECDSA on P-384 with SHA-384
)

// Structural and cryptographic failures. Callers map every one of these to a
// single opaque 401: which of them fired is a fact about our key set and our
// policy, and telling an attacker is free help.
var (
	ErrMalformed      = errors.New("jwt: malformed token")
	ErrTooLarge       = errors.New("jwt: token exceeds size limit")
	ErrUnsupportedAlg = errors.New("jwt: unsupported algorithm")
	ErrHeaderKey      = errors.New("jwt: token carries its own key material")
	ErrCritical       = errors.New("jwt: unrecognised critical header")
	ErrNoKeyID        = errors.New("jwt: token has no kid")
	ErrAlgMismatch    = errors.New("jwt: algorithm is not the one this key may be used with")
	ErrBadSignature   = errors.New("jwt: signature does not verify")
	ErrDuplicateField = errors.New("jwt: duplicate JSON member")
)

// Size limits, applied before anything is parsed.
//
// A verifier that base64-decodes first and checks size second has already done
// the attacker's allocation for them. These are generous next to a real access
// token (typically under 2 KB) and mean a request body-sized Authorization
// header is rejected at a string length comparison.
const (
	MaxTokenBytes  = 8 << 10
	maxHeaderBytes = 4 << 10
	maxClaimBytes  = 8 << 10
)

// b64 is the only decoder used here. Raw (JWS forbids padding) and Strict
// (the final quantum's unused bits must be zero).
//
// Non-strict decoding is a smuggling primitive: several distinct base64
// strings decode to the same bytes, so a signature computed over one of them
// verifies a token whose wire bytes are a different string. Anything
// downstream that keys on the raw token - a cache, a revocation list, a log -
// then sees two identities for one credential.
var b64 = base64.RawURLEncoding.Strict()

// Header is the JOSE header, including the members that are refused.
type Header struct {
	Alg Algorithm `json:"alg"`
	Kid string    `json:"kid"`
	Typ string    `json:"typ"`

	// Refused when present. Parsed so their presence is detectable; see
	// checkHeaderPolicy.
	Jwk  json.RawMessage `json:"jwk"`
	Jku  string          `json:"jku"`
	X5u  string          `json:"x5u"`
	X5c  json.RawMessage `json:"x5c"`
	Crit []string        `json:"crit"`
	Enc  string          `json:"enc"`
}

// Token is a parsed but not yet verified JWS.
//
// Nothing in it is trustworthy until Verify has returned nil. The type does
// not try to enforce that with state, because a bool that means "trusted" is
// exactly the bool that gets read before it is set. Verify is the only way to
// get claims out at all: see Verifier.
type Token struct {
	Header Header
	// claims is the decoded payload, held raw until the signature is checked.
	claims []byte
	// signingInput is `header.payload` exactly as it arrived on the wire.
	// Re-encoding it would be wrong: the signature covers the bytes the
	// issuer sent, not the bytes a round trip through our JSON encoder
	// happens to produce.
	signingInput []byte
	signature    []byte
}

// Parse splits a compact JWS and applies every check that does not need a key.
//
// It deliberately does all the structural work before any cryptography: an
// attacker should not be able to make the gateway do a public key operation by
// sending garbage.
func Parse(raw string) (*Token, error) {
	if len(raw) == 0 {
		return nil, ErrMalformed
	}
	if len(raw) > MaxTokenBytes {
		return nil, ErrTooLarge
	}

	// Exactly two separators. Splitting with SplitN(3) would silently accept a
	// JWE-shaped five-segment token by folding the last three into one.
	first := indexByte(raw, '.')
	if first < 0 {
		return nil, ErrMalformed
	}
	second := indexByte(raw[first+1:], '.')
	if second < 0 {
		return nil, ErrMalformed
	}
	second += first + 1
	if indexByte(raw[second+1:], '.') >= 0 {
		return nil, ErrMalformed
	}
	headerSeg, claimSeg, sigSeg := raw[:first], raw[first+1:second], raw[second+1:]
	if headerSeg == "" || claimSeg == "" || sigSeg == "" {
		// An empty signature segment is what `alg: none` looks like on the
		// wire, and it is refused here as well as at the algorithm check.
		return nil, ErrMalformed
	}

	headerJSON, err := decodeSegment(headerSeg, maxHeaderBytes)
	if err != nil {
		return nil, err
	}
	claimJSON, err := decodeSegment(claimSeg, maxClaimBytes)
	if err != nil {
		return nil, err
	}
	signature, err := b64.DecodeString(sigSeg)
	if err != nil {
		return nil, ErrMalformed
	}

	var header Header
	if err := strictUnmarshal(headerJSON, &header); err != nil {
		return nil, err
	}
	if err := checkHeaderPolicy(&header); err != nil {
		return nil, err
	}

	return &Token{
		Header:       header,
		claims:       claimJSON,
		signingInput: []byte(raw[:second]),
		signature:    signature,
	}, nil
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func decodeSegment(seg string, limit int) ([]byte, error) {
	// Bound the decode by the encoded length so an oversized segment never
	// gets an allocation. 4 base64 characters carry 3 bytes.
	if b64.DecodedLen(len(seg)) > limit {
		return nil, ErrTooLarge
	}
	out, err := b64.DecodeString(seg)
	if err != nil {
		return nil, ErrMalformed
	}
	return out, nil
}

// strictUnmarshal rejects trailing data and duplicate top-level members.
//
// encoding/json takes the last of a repeated member and says nothing. That is
// a parser-differential primitive: a token holding two `alg` members is read
// one way by us and the other way by anything else in the path that looks at
// the same bytes, and the two disagree about what was signed.
func strictUnmarshal(data []byte, v any) error {
	if err := checkNoDuplicateMembers(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return ErrMalformed
	}
	// Exactly one JSON value, nothing after it. A second value in the segment
	// would be invisible to Decode and visible to a different parser.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrMalformed
	}
	return nil
}

// Unknown members are *not* rejected. RFC 7515 section 4 requires a verifier
// to ignore header members it does not recognise unless they are listed in
// `crit`, and real issuers send them: `x5t` from Auth0 and Entra, `nonce` from
// an OIDC hybrid flow. The members that matter are refused by name in
// checkHeaderPolicy instead, which is the check that has a test.

// checkNoDuplicateMembers walks the top-level object's keys.
//
// Top level only, and on purpose: every member this package acts on is at the
// top level, and a recursive walk would be code with no test that can fail.
func checkNoDuplicateMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return ErrMalformed
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		// A JWT header and a JWT payload are both JSON objects. Anything else
		// is not a JWT, whatever it decodes to.
		return ErrMalformed
	}
	seen := map[string]struct{}{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return ErrMalformed
		}
		if delim, ok := tok.(json.Delim); ok && delim == '}' {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return ErrMalformed
		}
		if _, dup := seen[key]; dup {
			return ErrDuplicateField
		}
		seen[key] = struct{}{}
		if err := skipValue(dec); err != nil {
			return ErrMalformed
		}
	}
}

// skipValue consumes one complete JSON value, including a nested container.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || (delim != '{' && delim != '[') {
		return nil
	}
	for depth := 1; depth > 0; {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func checkHeaderPolicy(h *Header) error {
	if len(h.Jwk) > 0 || h.Jku != "" || h.X5u != "" || len(h.X5c) > 0 {
		// A token that carries or points at its own key is asking to be
		// trusted on its own say-so. Refused rather than ignored: ignoring is
		// correct only until somebody adds a reader for these fields.
		return ErrHeaderKey
	}
	if h.Enc != "" {
		// `enc` means this is a JWE, not a JWS. We do not decrypt.
		return ErrMalformed
	}
	if len(h.Crit) > 0 {
		// RFC 7515 section 4.1.11: a verifier that does not understand a
		// critical extension must reject. We understand none of them.
		return ErrCritical
	}
	switch h.Typ {
	case "", "JWT", "jwt", "at+jwt", "application/at+jwt":
		// RFC 8725 section 3.11 explicit typing. Absent is tolerated because
		// real issuers omit it; anything else is a token minted for a
		// different purpose and must not be spent here.
	default:
		return ErrMalformed
	}
	if _, ok := hashFor(h.Alg); !ok {
		// Catches `none`, every HMAC family, and anything invented. Note that
		// this is a sanity check only: the algorithm that actually gets used
		// is the key's, checked in Verify.
		return ErrUnsupportedAlg
	}
	if h.Kid == "" {
		return ErrNoKeyID
	}
	return nil
}

// hashFor maps an algorithm to its digest, and reports whether this package
// knows the algorithm at all.
func hashFor(alg Algorithm) (crypto.Hash, bool) {
	switch alg {
	case RS256, PS256, ES256:
		return crypto.SHA256, true
	case RS384, PS384, ES384:
		return crypto.SHA384, true
	case RS512, PS512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func digest(h crypto.Hash, data []byte) []byte {
	var fn hash.Hash
	switch h {
	case crypto.SHA256:
		fn = sha256.New()
	case crypto.SHA384:
		fn = sha512.New384()
	default:
		fn = sha512.New()
	}
	fn.Write(data)
	return fn.Sum(nil)
}

// Verify checks the signature against a key that has already been established
// as permitted to sign with `alg`.
//
// The `alg` argument is the *key's* algorithm, resolved by the caller from the
// JWK. Passing the token's header algorithm here would undo the whole design.
func (t *Token) Verify(pub crypto.PublicKey, alg Algorithm) error {
	if t.Header.Alg != alg {
		return ErrAlgMismatch
	}
	h, ok := hashFor(alg)
	if !ok {
		return ErrUnsupportedAlg
	}
	sum := digest(h, t.signingInput)

	switch alg {
	case RS256, RS384, RS512:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrAlgMismatch
		}
		if err := rsa.VerifyPKCS1v15(key, h, sum, t.signature); err != nil {
			return ErrBadSignature
		}
		return nil

	case PS256, PS384, PS512:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrAlgMismatch
		}
		// RFC 7518 section 3.5: the salt length equals the digest length.
		// rsa.PSSSaltLengthAuto would accept a signature made with a shorter
		// salt, which is a valid PSS signature but not a valid JWS one.
		opts := &rsa.PSSOptions{SaltLength: h.Size(), Hash: h}
		if err := rsa.VerifyPSS(key, h, sum, t.signature, opts); err != nil {
			return ErrBadSignature
		}
		return nil

	case ES256, ES384:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return ErrAlgMismatch
		}
		return verifyECDSA(key, sum, t.signature)
	}
	return ErrUnsupportedAlg
}

// verifyECDSA checks a fixed-width R||S signature.
//
// RFC 7518 section 3.4 defines the JWS encoding as the two integers
// left-padded to the curve's coordinate size and concatenated. It is *not*
// ASN.1 DER, and accepting DER here would be a real weakness rather than a
// kindness: DER is a variable-length encoding, so the same signature has many
// valid spellings, and a gateway that accepts all of them hands a cache or a
// replay filter keyed on the token several identities for one credential.
// ecdsa.VerifyASN1 is therefore not used.
func verifyECDSA(key *ecdsa.PublicKey, sum, sig []byte) error {
	size := (key.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*size {
		return ErrBadSignature
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	// ecdsa.Verify rejects these too; being explicit means the zero-signature
	// case is a named property rather than a fact about somebody else's code.
	n := key.Curve.Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return ErrBadSignature
	}
	if !ecdsa.Verify(key, sum, r, s) {
		return ErrBadSignature
	}
	return nil
}

// SigningInput is the exact bytes the signature covers. Exposed for tests that
// need to forge a signature over a token they built.
func (t *Token) SigningInput() []byte { return t.signingInput }

func (t *Token) String() string {
	return fmt.Sprintf("jwt[alg=%s kid=%s]", t.Header.Alg, t.Header.Kid)
}

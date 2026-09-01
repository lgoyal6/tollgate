package jwt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claim failures. Like the JWS errors, callers collapse all of these into one
// opaque 401.
var (
	ErrIssuerUnknown = errors.New("jwt: issuer is not configured")
	ErrAudience      = errors.New("jwt: token is not for this gateway")
	ErrExpired       = errors.New("jwt: token has expired")
	ErrNotYetValid   = errors.New("jwt: token is not valid yet")
	ErrFromTheFuture = errors.New("jwt: token was issued in the future")
	ErrNoSubject     = errors.New("jwt: token has no sub")
	ErrNoExpiry      = errors.New("jwt: token has no exp")
	ErrNotBound      = errors.New("jwt: token is bound to a client certificate that was not presented")
)

// clockSkew is how far apart this gateway and an issuer's clock may be.
//
// Not configurable. Sixty seconds is what NTP-synchronised hosts actually
// differ by, and the only reason to raise it is to paper over a broken clock,
// which is a thing to fix rather than to tolerate. Every second of skew is a
// second a revoked token stays spendable.
const clockSkew = 60 * time.Second

// Claims is the subset of the payload the gateway acts on.
//
// Everything else in the token is ignored on purpose. A gateway that forwards
// arbitrary claims into routing or rate limiting decisions has made the
// issuer's payload part of its own configuration.
type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt time.Time
	NotBefore time.Time
	IssuedAt  time.Time
	ID        string
	Scopes    []string
	// CertThumbprint is RFC 8705's cnf["x5t#S256"], present when the issuer
	// bound this token to a client certificate.
	CertThumbprint string
}

// rawClaims mirrors the wire form. `aud` and `scope` both have two legal
// shapes in the wild, and both are handled rather than configured: a knob
// whose correct setting is determined by the issuer is a knob that will be set
// wrong.
type rawClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	ExpiresAt json.RawMessage `json:"exp"`
	NotBefore json.RawMessage `json:"nbf"`
	IssuedAt  json.RawMessage `json:"iat"`
	ID        string          `json:"jti"`
	// RFC 8693 and RFC 9068 use a space-delimited string; Entra and a few
	// others use an array.
	Scope json.RawMessage `json:"scope"`
	Scp   json.RawMessage `json:"scp"`
	Cnf   *struct {
		X5tS256 string `json:"x5t#S256"`
	} `json:"cnf"`
}

// Issuer is one identity provider the gateway will accept tokens from.
type Issuer struct {
	// Name is the exact `iss` value. Compared exactly: an issuer that differs
	// by a trailing slash is a different issuer, and normalising invites the
	// confusion this check exists to prevent.
	Name string
	// Audience is the value that must appear in `aud`. A token minted for a
	// different resource server must not be spendable here, which is the
	// whole point of the claim.
	Audience string
	// TenantID is the gateway tenant a token from this issuer authenticates
	// as. The mapping lives here rather than in a claim: letting the token
	// name its own tenant would let an issuer's users pick whose rate limit
	// and whose upstream credential they spend.
	TenantID string
	Keys     *KeySource
}

// Verified is a token that passed every check.
type Verified struct {
	Claims   Claims
	TenantID string
	// KeyID is the kid that signed it, kept so a cache hit can re-check that
	// the key is still one the issuer publishes.
	KeyID string
}

// Binding is what the transport can prove about the caller.
//
// Separate from the token on purpose: the token says which certificate it
// expects, and only the TLS layer can say which one was actually presented.
type Binding struct {
	PeerCert *x509.Certificate
}

// Verifier checks tokens against a fixed set of issuers.
type Verifier struct {
	issuers map[string]*Issuer
	now     func() time.Time
}

// NewVerifier builds a verifier over the configured issuers.
func NewVerifier(issuers []*Issuer) (*Verifier, error) {
	byName := make(map[string]*Issuer, len(issuers))
	for _, iss := range issuers {
		if iss.Name == "" || iss.Audience == "" || iss.TenantID == "" || iss.Keys == nil {
			return nil, fmt.Errorf("jwt: issuer %q is incompletely configured", iss.Name)
		}
		if _, dup := byName[iss.Name]; dup {
			return nil, fmt.Errorf("jwt: issuer %q configured twice", iss.Name)
		}
		byName[iss.Name] = iss
	}
	return &Verifier{issuers: byName, now: time.Now}, nil
}

// Looks like a JWS: three dot-separated segments. Used to decide which
// credential type a bearer value is, before any parsing.
func LooksLikeJWT(raw string) bool {
	return strings.Count(raw, ".") == 2
}

// Verify authenticates a token.
//
// The order is deliberate. Everything that costs nothing runs before anything
// that costs a public key operation or a network round trip, so an attacker
// cannot make the gateway do work by sending nonsense.
func (v *Verifier) Verify(ctx context.Context, raw string, binding Binding) (*Verified, error) {
	token, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	claims, err := parseClaims(token.claims)
	if err != nil {
		return nil, err
	}
	issuer, ok := v.issuers[claims.Issuer]
	if !ok {
		return nil, ErrIssuerUnknown
	}
	// Time and audience before signature: they are string and integer
	// comparisons, and an expired token should not cost an RSA verification.
	if err := v.checkTime(&claims); err != nil {
		return nil, err
	}
	if !audienceContains(claims.Audience, issuer.Audience) {
		return nil, ErrAudience
	}
	if claims.Subject == "" {
		return nil, ErrNoSubject
	}
	if err := checkBinding(&claims, binding); err != nil {
		return nil, err
	}

	// This is the first step that can touch the network, and it is reached
	// with a kid the attacker wrote and a signature nobody has checked yet.
	// It cannot be ordered any later - verifying needs the key - so the
	// defence is the rate limit inside KeySource, not the ordering here.
	key, err := issuer.Keys.Key(ctx, token.Header.Kid)
	if err != nil {
		return nil, err
	}
	if err := token.Verify(key.Pub, key.Alg); err != nil {
		return nil, err
	}
	return &Verified{Claims: claims, TenantID: issuer.TenantID, KeyID: key.ID}, nil
}

func (v *Verifier) checkTime(c *Claims) error {
	now := v.now()
	if c.ExpiresAt.IsZero() {
		// RFC 9068 requires exp on an access token. A token that never
		// expires is a password with extra steps.
		return ErrNoExpiry
	}
	if now.After(c.ExpiresAt.Add(clockSkew)) {
		return ErrExpired
	}
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore.Add(-clockSkew)) {
		return ErrNotYetValid
	}
	if !c.IssuedAt.IsZero() && c.IssuedAt.After(now.Add(clockSkew)) {
		// An iat in the future means one of the clocks is wrong or the token
		// was minted to outlive a revocation.
		return ErrFromTheFuture
	}
	return nil
}

// checkBinding enforces RFC 8705 sender-constrained tokens.
//
// A bearer token is spendable by whoever holds it, which is the single largest
// weakness of the format: a token in a log, a proxy buffer or a browser
// extension is a working credential. A token carrying cnf["x5t#S256"] is only
// spendable by the holder of the private key for that certificate, so stealing
// the token is no longer enough.
//
// The check is one-directional by design: a token *without* cnf is accepted
// over any transport. Requiring binding for every token would be the stronger
// policy and would also mean the gateway could not accept tokens from an
// issuer that does not implement RFC 8705, which is most of them. The issuer
// decides which of its tokens are sender-constrained; the gateway's job is to
// honour that decision rather than to second-guess it.
func checkBinding(c *Claims, b Binding) error {
	if c.CertThumbprint == "" {
		return nil
	}
	if b.PeerCert == nil {
		return ErrNotBound
	}
	sum := sha256.Sum256(b.PeerCert.Raw)
	want := b64.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(want), []byte(c.CertThumbprint)) != 1 {
		return ErrNotBound
	}
	return nil
}

func parseClaims(data []byte) (Claims, error) {
	var raw rawClaims
	if err := strictUnmarshal(data, &raw); err != nil {
		return Claims{}, err
	}
	out := Claims{
		Issuer:  raw.Issuer,
		Subject: raw.Subject,
		ID:      raw.ID,
	}
	var err error
	if out.Audience, err = parseAudience(raw.Audience); err != nil {
		return Claims{}, err
	}
	if out.ExpiresAt, err = parseTime(raw.ExpiresAt); err != nil {
		return Claims{}, err
	}
	if out.NotBefore, err = parseTime(raw.NotBefore); err != nil {
		return Claims{}, err
	}
	if out.IssuedAt, err = parseTime(raw.IssuedAt); err != nil {
		return Claims{}, err
	}
	if out.Scopes, err = parseScopes(raw.Scope, raw.Scp); err != nil {
		return Claims{}, err
	}
	if raw.Cnf != nil {
		out.CertThumbprint = raw.Cnf.X5tS256
	}
	return out, nil
}

// parseAudience accepts the two shapes RFC 7519 allows and nothing else.
func parseAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, ErrMalformed
	}
	return many, nil
}

func audienceContains(auds []string, want string) bool {
	for _, a := range auds {
		// Exact, and constant time. The audience is not secret, but a
		// comparison that returns early on the first differing byte is a
		// habit worth not having in an auth path.
		if subtle.ConstantTimeCompare([]byte(a), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// parseTime reads a NumericDate.
//
// RFC 7519 says these are numbers. A JSON string is refused rather than
// coerced, and that refusal has to be written by hand: encoding/json will
// happily unmarshal `"9999999999"` into a json.Number, so a type that looks
// strict is not. Coercion is how one token is expired to one parser and
// eternal to another.
func parseTime(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 {
		return time.Time{}, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return time.Time{}, ErrMalformed
	}
	if trimmed[0] == '"' {
		return time.Time{}, ErrMalformed
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return time.Time{}, nil
	}
	var secs float64
	if err := json.Unmarshal(trimmed, &secs); err != nil {
		return time.Time{}, ErrMalformed
	}
	// Beyond this a float64 cannot represent whole seconds, and a date that
	// far out is not a date, it is an overflow.
	if secs < 0 || secs > 1<<53 {
		return time.Time{}, ErrMalformed
	}
	sec := int64(secs)
	return time.Unix(sec, int64((secs-float64(sec))*1e9)).UTC(), nil
}

func parseScopes(scope, scp json.RawMessage) ([]string, error) {
	if len(scope) > 0 {
		var s string
		if err := json.Unmarshal(scope, &s); err != nil {
			return nil, ErrMalformed
		}
		return strings.Fields(s), nil
	}
	if len(scp) > 0 {
		var many []string
		if err := json.Unmarshal(scp, &many); err == nil {
			return many, nil
		}
		var one string
		if err := json.Unmarshal(scp, &one); err != nil {
			return nil, ErrMalformed
		}
		return strings.Fields(one), nil
	}
	return nil, nil
}

// HasScope reports whether the token carries a scope.
func (c *Claims) HasScope(want string) bool {
	if want == "" {
		return true
	}
	for _, s := range c.Scopes {
		if s == want {
			return true
		}
	}
	return false
}

// Thumbprint is RFC 8705's x5t#S256 for a certificate, exported so an issuer
// (or a test) can compute what it must put in cnf.
func Thumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return b64.EncodeToString(sum[:])
}

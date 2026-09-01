package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The attack corpus.
//
// Each case is a token an attacker would actually send, labelled with the
// class of bug it belongs to. The corpus is the point of writing the verifier
// out rather than importing one: a check nobody has attacked is a comment.
//
// Every case must be refused. TestDifferentialAgainstGolangJWT then runs the
// same corpus through github.com/golang-jwt/jwt to establish that this
// package never accepts anything a mainstream implementation refuses, and
// that every place the two differ is a place this package is stricter, listed
// with a reason.

type attack struct {
	name string
	// class is the family the bug belongs to, so the corpus reads as a threat
	// model rather than a list of strings.
	class string
	build func(t *testing.T, clk *clock) string
	// golangJWTAccepts records that golang-jwt, configured as carefully as a
	// competent engineer would configure it, accepts this token. Every one of
	// these is a deliberate divergence and needs a reason.
	golangJWTAccepts bool
	why              string
}

// mutateBase64Tail returns a spelling of seg that decodes to the same bytes
// under a lenient decoder and is refused by a strict one, or "" when the
// segment lands on a quantum boundary and has no alternative spelling.
func mutateBase64Tail(seg string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var mask byte
	switch len(seg) % 4 {
	case 2:
		mask = 0x0F // 4 unused bits in the final quantum
	case 3:
		mask = 0x03 // 2 unused bits
	default:
		return ""
	}
	last := byte(strings.IndexByte(alphabet, seg[len(seg)-1]))
	alt := last | (mask & 0x01)
	if alt == last {
		alt = last | mask
	}
	if alt == last {
		return ""
	}
	return seg[:len(seg)-1] + string(alphabet[alt])
}

func corpus() []attack {
	rsa1 := rsaSigner("k1", RS256)
	other := otherRSASigner("k1", RS256)
	ec := ecSigner("ec1", ES256)

	// claims returns a payload that is valid in every respect, so a case only
	// ever fails for the reason it is testing.
	claims := func(clk *clock) map[string]any { return goodClaims(clk) }

	return []attack{
		{
			name:  "alg none with an empty signature",
			class: "CWE-347 signature verification bypass",
			build: func(t *testing.T, clk *clock) string {
				h := map[string]any{"alg": "none", "kid": "k1", "typ": "JWT"}
				return encodeSegments(t, h, claims(clk)) + "."
			},
		},
		{
			name:  "alg None, capitalised, to slip a case-sensitive deny list",
			class: "CWE-347 signature verification bypass",
			build: func(t *testing.T, clk *clock) string {
				h := map[string]any{"alg": "None", "kid": "k1", "typ": "JWT"}
				return encodeSegments(t, h, claims(clk)) + ".AAAA"
			},
		},
		{
			name:  "RS256 to HS256 confusion, MAC keyed with the RSA public key",
			class: "CVE-2016-10555 algorithm confusion",
			build: func(t *testing.T, clk *clock) string {
				input := encodeSegments(t, map[string]any{"alg": "HS256", "kid": "k1", "typ": "JWT"}, claims(clk))
				mac := hmac.New(sha256.New, rsa1.publicKeyPKIX(t))
				mac.Write([]byte(input))
				return input + "." + b64.EncodeToString(mac.Sum(nil))
			},
		},
		{
			name:  "PS256 signature against a key published as RS256",
			class: "algorithm substitution",
			build: func(t *testing.T, clk *clock) string {
				ps := rsaSigner("k1", PS256)
				return ps.mint(t, header(ps), claims(clk))
			},
			golangJWTAccepts: true,
			why: "the JWKS publishes this key with alg RS256. golang-jwt has no " +
				"notion of what a key is published for: it checks the header " +
				"algorithm against an operator-supplied list, and PS256 is on any " +
				"realistic list, so the same RSA key verifies either way. This is " +
				"the whole point of taking the algorithm from the key. Being fair " +
				"about it: an operator who lists only RS256 gets the same refusal " +
				"from golang-jwt. The difference is that there the safety is a " +
				"property of somebody having enumerated the methods correctly, and " +
				"here it is a property of the issuer's own key metadata.",
		},
		{
			name:  "key smuggled in the jwk header member",
			class: "CVE-2018-0114 self-signed token",
			build: func(t *testing.T, clk *clock) string {
				h := header(other)
				h["jwk"] = other.jwk()
				return other.mint(t, h, claims(clk))
			},
		},
		{
			name:  "jku pointing at a key set the attacker controls",
			class: "CVE-2018-0114 self-signed token",
			build: func(t *testing.T, clk *clock) string {
				h := header(rsa1)
				h["jku"] = "https://attacker.test/.well-known/jwks.json"
				return rsa1.mint(t, h, claims(clk))
			},
			golangJWTAccepts: true,
			why: "golang-jwt ignores jku and verifies against the key the keyfunc " +
				"returned, so it is safe here only because the call site never reads " +
				"the member. Refused rather than ignored: ignoring is correct until " +
				"somebody adds a reader for it.",
		},
		{
			name:  "x5u pointing at a certificate the attacker controls",
			class: "CVE-2018-0114 self-signed token",
			build: func(t *testing.T, clk *clock) string {
				h := header(rsa1)
				h["x5u"] = "https://attacker.test/c.pem"
				return rsa1.mint(t, h, claims(clk))
			},
			golangJWTAccepts: true,
			why:              "same as jku: ignored there, refused here.",
		},
		{
			name:  "x5c carrying an attacker certificate chain",
			class: "CVE-2018-0114 self-signed token",
			build: func(t *testing.T, clk *clock) string {
				h := header(rsa1)
				h["x5c"] = []string{"MIIBkTCB+w=="}
				return rsa1.mint(t, h, claims(clk))
			},
			golangJWTAccepts: true,
			why:              "same as jku: ignored there, refused here.",
		},
		{
			name:  "unrecognised critical header extension",
			class: "RFC 7515 4.1.11 must-understand violation",
			build: func(t *testing.T, clk *clock) string {
				h := header(rsa1)
				h["crit"] = []string{"exp-policy"}
				return rsa1.mint(t, h, claims(clk))
			},
			golangJWTAccepts: true,
			why: "RFC 7515 requires a verifier that does not understand a member " +
				"listed in crit to reject. golang-jwt does not implement crit at all, " +
				"so it accepts a token whose issuer said the token is invalid without " +
				"honouring that extension.",
		},
		{
			name:  "two alg members, the second saying none",
			class: "parser differential",
			build: func(t *testing.T, clk *clock) string {
				c, err := json.Marshal(claims(clk))
				if err != nil {
					t.Fatal(err)
				}
				// Ordered so a last-wins parser reads RS256 and verifies
				// happily, while a first-wins parser reads none. That is the
				// dangerous direction: the two agree the token is fine and
				// disagree about what made it fine.
				h := b64.EncodeToString([]byte(`{"alg":"none","kid":"k1","alg":"RS256"}`))
				input := h + "." + b64.EncodeToString(c)
				return input + "." + b64.EncodeToString(rsa1.sign(t, RS256, []byte(input)))
			},
			golangJWTAccepts: true,
			why: "encoding/json takes the last repeated member and says nothing, so " +
				"golang-jwt reads RS256, verifies, and accepts. Any parser that " +
				"takes the first member instead reads none. Two readers of the same " +
				"bytes must not be able to disagree about what algorithm was used, " +
				"so the duplicate itself is the thing refused here.",
		},
		{
			name:  "two sub members, the second an administrator",
			class: "parser differential",
			build: func(t *testing.T, clk *clock) string {
				c := claims(clk)
				delete(c, "sub")
				body, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				// Splice a repeated sub into the payload object.
				spliced := `{"sub":"user-1","sub":"admin",` + string(body[1:])
				h, err := json.Marshal(header(rsa1))
				if err != nil {
					t.Fatal(err)
				}
				input := b64.EncodeToString(h) + "." + b64.EncodeToString([]byte(spliced))
				return input + "." + b64.EncodeToString(rsa1.sign(t, RS256, []byte(input)))
			},
			golangJWTAccepts: true,
			why: "the same differential in the payload. Whichever sub the gateway " +
				"logs is not necessarily the one an upstream reading the same token " +
				"would act on.",
		},
		{
			name:  "non-canonical base64, signed over the mutated bytes",
			class: "encoding malleability",
			build: func(t *testing.T, clk *clock) string {
				h, err := json.Marshal(header(rsa1))
				if err != nil {
					t.Fatal(err)
				}
				// Pad the payload until it does not land on a quantum
				// boundary, so the case is deterministic rather than a
				// property of how long today's claims happen to be.
				var alt string
				for n := 0; n < 3 && alt == ""; n++ {
					body := claims(clk)
					body["pad"] = strings.Repeat("x", n)
					c, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					alt = mutateBase64Tail(b64.EncodeToString(c))
				}
				if alt == "" {
					t.Fatal("no padding produced a segment with spare bits")
				}
				input := b64.EncodeToString(h) + "." + alt
				return input + "." + b64.EncodeToString(rsa1.sign(t, RS256, []byte(input)))
			},
			golangJWTAccepts: true,
			why: "golang-jwt decodes with RawURLEncoding rather than its Strict form, " +
				"so one credential has several wire spellings that all verify. " +
				"Anything downstream keyed on the raw token - a cache, a replay " +
				"filter, an audit log - then sees several identities for one token.",
		},
		{
			name:  "base64 with padding",
			class: "encoding malleability",
			build: func(t *testing.T, clk *clock) string {
				h, err := json.Marshal(header(rsa1))
				if err != nil {
					t.Fatal(err)
				}
				c, err := json.Marshal(claims(clk))
				if err != nil {
					t.Fatal(err)
				}
				input := base64.URLEncoding.EncodeToString(h) + "." + base64.URLEncoding.EncodeToString(c)
				return input + "." + b64.EncodeToString(rsa1.sign(t, RS256, []byte(input)))
			},
		},
		{
			name:  "signature stripped",
			class: "CWE-347 signature verification bypass",
			build: func(t *testing.T, clk *clock) string {
				parts := strings.Split(rsa1.mint(t, header(rsa1), claims(clk)), ".")
				return parts[0] + "." + parts[1] + "."
			},
		},
		{
			name:  "payload swapped under a valid signature",
			class: "CWE-347 signature verification bypass",
			build: func(t *testing.T, clk *clock) string {
				parts := strings.Split(rsa1.mint(t, header(rsa1), claims(clk)), ".")
				c := claims(clk)
				c["sub"] = "admin"
				body, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				return parts[0] + "." + b64.EncodeToString(body) + "." + parts[2]
			},
		},
		{
			name:  "signed by a different key claiming the same kid",
			class: "key confusion",
			build: func(t *testing.T, clk *clock) string {
				return other.mint(t, header(other), claims(clk))
			},
		},
		{
			name:  "unknown kid, to make the gateway fetch on demand",
			class: "key fetch amplification",
			build: func(t *testing.T, clk *clock) string {
				h := header(rsa1)
				h["kid"] = "kid-that-does-not-exist"
				return rsa1.mint(t, h, claims(clk))
			},
		},
		{
			name:  "no kid at all",
			class: "key confusion",
			build: func(t *testing.T, clk *clock) string {
				h := header(rsa1)
				delete(h, "kid")
				return rsa1.mint(t, h, claims(clk))
			},
		},
		{
			name:  "ECDSA signature in DER rather than fixed-width R||S",
			class: "encoding malleability",
			build: func(t *testing.T, clk *clock) string {
				h, c := header(ec), claims(clk)
				input := encodeSegments(t, h, c)
				return input + "." + b64.EncodeToString(ec.signASN1(t, ES256, []byte(input)))
			},
		},
		{
			name:  "ECDSA signature of all zeroes",
			class: "CVE-2022-21449 zero signature",
			build: func(t *testing.T, clk *clock) string {
				return mintWithSignature(t, header(ec), claims(clk), make([]byte, 64))
			},
		},
		{
			name:  "expired an hour ago",
			class: "expiry bypass",
			build: func(t *testing.T, clk *clock) string {
				c := claims(clk)
				c["exp"] = clk.now().Add(-time.Hour).Unix()
				return rsa1.mint(t, header(rsa1), c)
			},
		},
		{
			name:  "no exp at all",
			class: "expiry bypass",
			build: func(t *testing.T, clk *clock) string {
				c := claims(clk)
				delete(c, "exp")
				return rsa1.mint(t, header(rsa1), c)
			},
		},
		{
			name:  "exp as a string, to be coerced by a lenient parser",
			class: "type confusion",
			build: func(t *testing.T, clk *clock) string {
				c := claims(clk)
				c["exp"] = "99999999999"
				return rsa1.mint(t, header(rsa1), c)
			},
		},
		{
			name:  "token minted for a different resource server",
			class: "audience confusion",
			build: func(t *testing.T, clk *clock) string {
				c := claims(clk)
				c["aud"] = "https://someone-elses-api.test"
				return rsa1.mint(t, header(rsa1), c)
			},
		},
		{
			name:  "issuer differing only by a trailing slash",
			class: "issuer confusion",
			build: func(t *testing.T, clk *clock) string {
				c := claims(clk)
				c["iss"] = testIssuer + "/"
				return rsa1.mint(t, header(rsa1), c)
			},
		},
		{
			name:  "typ says this is an id_token, not an access token",
			class: "RFC 8725 3.11 cross-purpose token",
			build: func(t *testing.T, clk *clock) string {
				h := header(rsa1)
				h["typ"] = "id_token+jwt"
				return rsa1.mint(t, h, claims(clk))
			},
			golangJWTAccepts: true,
			why: "golang-jwt does not check typ, so a token minted for a different " +
				"purpose by the same issuer is spendable as an access token here.",
		},
		{
			name:  "a JWE, whose header names a content encryption algorithm",
			class: "format confusion",
			build: func(t *testing.T, clk *clock) string {
				h := header(rsa1)
				h["enc"] = "A128GCM"
				return rsa1.mint(t, h, claims(clk))
			},
			golangJWTAccepts: true,
			why: "a five-segment JWE is refused by both, but a JWS-shaped token " +
				"carrying enc is only refused here. It is not a JWS and must not be " +
				"read as one.",
		},
		{
			name:  "a megabyte of base64 in the Authorization header",
			class: "resource exhaustion",
			build: func(t *testing.T, clk *clock) string {
				c := claims(clk)
				c["padding"] = strings.Repeat("A", 1<<20)
				return rsa1.mint(t, header(rsa1), c)
			},
			golangJWTAccepts: true,
			why: "golang-jwt has no size limit, so it base64-decodes and JSON-parses " +
				"whatever arrives before deciding anything. The limit here is checked " +
				"against the string length, before any allocation.",
		},
		{
			name:  "five segments, a JWE by shape",
			class: "format confusion",
			build: func(t *testing.T, clk *clock) string {
				return rsa1.mint(t, header(rsa1), claims(clk)) + ".AAAA.BBBB"
			},
		},
		{
			name:  "empty string",
			class: "format confusion",
			build: func(t *testing.T, clk *clock) string { return "" },
		},
	}
}

func TestAdversarialCorpusIsRefused(t *testing.T) {
	s := rsaSigner("k1", RS256)
	ec := ecSigner("ec1", ES256)
	v, clk, _ := verifierFor(t, s, ec)

	for _, tc := range corpus() {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.build(t, clk)
			if _, err := v.Verify(context.Background(), raw, Binding{}); err == nil {
				t.Fatalf("%s: accepted, and it should not have been", tc.class)
			}
		})
	}
}

// The positive control. A corpus that refuses everything proves nothing, so a
// well-formed token from the same issuer, minted the same way, must pass.
func TestTheCorpusHarnessAcceptsAGoodToken(t *testing.T) {
	s := rsaSigner("k1", RS256)
	ec := ecSigner("ec1", ES256)
	v, clk, _ := verifierFor(t, s, ec)
	if _, err := v.Verify(context.Background(), s.mint(t, header(s), goodClaims(clk)), Binding{}); err != nil {
		t.Fatalf("the harness rejects a valid token, so the corpus proves nothing: %v", err)
	}
}

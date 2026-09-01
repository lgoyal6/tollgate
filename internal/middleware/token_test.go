package middleware

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/jwt"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/ratelimit"
	"github.com/lgoyal6/tollgate/internal/store"
)

// The end-to-end shape: a token from a configured issuer must come out of the
// chain as a tenant with scopes, so that route scope enforcement, per-tenant
// rate limiting and usage accounting keep working without a second code path
// each. internal/jwt tests the verification; this tests the adaptation.

const (
	tokenIssuer   = "https://issuer.test"
	tokenAudience = "https://api.tollgate.test"
)

var b64raw = base64.RawURLEncoding

type testIDP struct {
	key *rsa.PrivateKey
	srv *httptest.Server
}

func newTestIDP(t *testing.T) *testIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIDP{key: key}
	idp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64raw.EncodeToString(key.N.Bytes()),
			"e": b64raw.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(idp.srv.Close)
	return idp
}

func (i *testIDP) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := b64raw.EncodeToString(h) + "." + b64raw.EncodeToString(c)
	sum := sha256Sum(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64raw.EncodeToString(sig)
}

func (i *testIDP) tokenAuth(t *testing.T, tenantID string) *TokenAuth {
	t.Helper()
	src, err := jwt.NewKeySource(i.srv.URL, i.srv.Client(), time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jwt.NewVerifier([]*jwt.Issuer{{
		Name: tokenIssuer, Audience: tokenAudience, TenantID: tenantID, Keys: src,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return &TokenAuth{Verifier: v, Cache: jwt.NewVerifiedCache(30*time.Second, 64)}
}

func tokenClaims(scope string) map[string]any {
	return map[string]any{
		"iss": tokenIssuer, "sub": "user-1", "aud": tokenAudience,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(), "scope": scope,
	}
}

func tokenChain(t *testing.T, snap *store.Snapshot, tokens *TokenAuth) http.Handler {
	t.Helper()
	m := observability.NewMetrics()
	snapshots := func() *store.Snapshot { return snap }
	return Chain(echoAuthHandler,
		Recover(testLogger), RequestID(), Metrics(m),
		Auth(snapshots, m, tokens), Router(snapshots),
		RateLimit(ratelimit.NewMemoryLimiter(), true, m, testLogger),
	)
}

// echoAuthHandler reports what reached the upstream, so the test can assert
// the gateway credential was stripped.
var echoAuthHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Saw-Authorization", r.Header.Get("Authorization"))
	w.WriteHeader(http.StatusOK)
})

func doRequest(t *testing.T, h http.Handler, path, credential string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestATokenAuthenticatesAsItsIssuersTenant(t *testing.T) {
	snap, _ := testSnapshot(t)
	idp := newTestIDP(t)
	h := tokenChain(t, snap, idp.tokenAuth(t, "acme"))

	rec := doRequest(t, h, "/api/thing", idp.mint(t, tokenClaims("read")))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("X-Saw-Authorization"); got != "" {
		t.Fatalf("the gateway credential reached the upstream: %q", got)
	}
}

// The scope claim has to drive the same route enforcement an API key's scopes
// do, or a token would be a way around it.
func TestTokenScopesAreEnforcedAtTheRoute(t *testing.T) {
	snap, _ := testSnapshot(t)
	idp := newTestIDP(t)
	h := tokenChain(t, snap, idp.tokenAuth(t, "acme"))

	// /admin/ requires the "admin" scope.
	if rec := doRequest(t, h, "/admin/x", idp.mint(t, tokenClaims("read"))); rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 without the scope, got %d", rec.Code)
	}
	if rec := doRequest(t, h, "/admin/x", idp.mint(t, tokenClaims("read admin"))); rec.Code != http.StatusOK {
		t.Fatalf("want 200 with the scope, got %d", rec.Code)
	}
}

// Turning the token path on must not change what an API key does.
func TestAPIKeysStillWorkWithTokensEnabled(t *testing.T) {
	snap, key := testSnapshot(t)
	idp := newTestIDP(t)
	h := tokenChain(t, snap, idp.tokenAuth(t, "acme"))

	if rec := doRequest(t, h, "/api/thing", key); rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
}

// And leaving it off must leave a JWT with nowhere to go, rather than falling
// through into the key path as something half-parsed.
func TestATokenIsRefusedWhenTheOIDCPathIsOff(t *testing.T) {
	snap, _ := testSnapshot(t)
	idp := newTestIDP(t)
	h := tokenChain(t, snap, nil)

	if rec := doRequest(t, h, "/api/thing", idp.mint(t, tokenClaims("read"))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestTokensForAnUnknownTenantAreRefused(t *testing.T) {
	snap, _ := testSnapshot(t)
	idp := newTestIDP(t)
	// The issuer is mapped to a tenant that is not in the snapshot.
	h := tokenChain(t, snap, idp.tokenAuth(t, "no-such-tenant"))

	if rec := doRequest(t, h, "/api/thing", idp.mint(t, tokenClaims("read"))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

// Every rejection says the same thing, whatever went wrong. A distinguishable
// message would tell an attacker whether an issuer is configured, whether a
// tenant exists, or whether a kid is real.
func TestEveryTokenRejectionLooksTheSame(t *testing.T) {
	snap, _ := testSnapshot(t)
	idp := newTestIDP(t)
	h := tokenChain(t, snap, idp.tokenAuth(t, "acme"))

	bad := []string{
		idp.mint(t, map[string]any{"iss": "https://attacker.test", "sub": "u", "aud": tokenAudience, "exp": time.Now().Add(time.Hour).Unix()}),
		idp.mint(t, map[string]any{"iss": tokenIssuer, "sub": "u", "aud": "https://other.test", "exp": time.Now().Add(time.Hour).Unix()}),
		idp.mint(t, map[string]any{"iss": tokenIssuer, "sub": "u", "aud": tokenAudience, "exp": time.Now().Add(-time.Hour).Unix()}),
		"aaa.bbb.ccc",
	}
	var bodies []string
	for _, raw := range bad {
		rec := doRequest(t, h, "/api/thing", raw)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d for %q", rec.Code, raw)
		}
		body := rec.Body.String()
		// The request id differs per request; the error message must not.
		bodies = append(bodies, body[strings.Index(body, `"error"`):strings.Index(body, `"request_id"`)])
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("rejections are distinguishable:\n%s\n%s", bodies[0], b)
		}
	}
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

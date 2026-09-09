// Package replay is the scripted attack harness behind
// scripts/run-security-ops-eval.sh.
//
// What it is: seven scenarios driven through the real middleware chain, in
// one process, against httptest upstreams and an in-memory config snapshot.
// The chain is the gateway's own - the same Auth, Router, RateLimit,
// Concurrency, Budget and proxy, assembled in the same order - so the events
// it produces come from the controls themselves and not from a model of them.
//
// What it is not: a distributed test, a load test, or evidence about anybody
// else's deployment. There is no Redis, no Postgres, no second replica and no
// network. Every incident in the results is one this file caused on purpose,
// seconds earlier, and every detection delay is measured inside a script that
// controls its own timing. Those are stated in the report rather than left
// for a reader to work out.
package replay

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/jwt"
	"github.com/lgoyal6/tollgate/internal/store"
)

const (
	issuerReplay   = "https://issuer-replay.test"
	issuerBinding  = "https://issuer-binding.test"
	tokenAudience  = "https://gateway.tollgate.test"
	tenantReplay   = "replay-co"
	tenantBinding  = "bind-co"
	tenantSpend    = "spend-co"
	tenantMetadata = "meta-co"
	tenantBurst    = "burst-co"
	tenantCascadeA = "cascade-a"
	tenantCascadeB = "cascade-b"
)

var b64raw = base64.RawURLEncoding

// fixtures is everything the scenarios need that outlives a single run:
// upstreams, certificates, credentials and the identity provider. Rebuilt
// per process, not per run, so the two determinism runs are the same replay
// rather than two different ones that happen to look alike.
type fixtures struct {
	healthy *httptest.Server
	llm     *httptest.Server
	// flaky serves the cascade: a path that never answers, a path that
	// answers instantly, and a path that answers only the second time it is
	// asked for one request id. All on ONE host, because the breaker is per
	// host and the cascade scenario is about what one upstream does to
	// everybody behind it.
	flaky *httptest.Server

	idp *identityProvider

	certLegitimate *x509.Certificate
	certThief      *x509.Certificate

	keys map[string]auth.GeneratedKey
	// forgedBurstKey is a real key id carrying somebody else's secret, which
	// is what a credential-stuffing attempt looks like from inside the
	// gateway: the id resolves, the hash does not match.
	forgedBurstKey string

	snapshot *store.Snapshot
}

func newFixtures() (*fixtures, error) {
	f := &fixtures{keys: map[string]auth.GeneratedKey{}}

	f.healthy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	f.llm = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		// The upstream reports whatever token counts the caller's own
		// X-Replay-Usage header asks for, so the malicious and benign legs
		// differ in exactly one thing: what the provider says the request
		// cost. Everything else about the two runs is identical.
		in, out := usageFor(r.Header.Get("X-Replay-Usage"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "msg_replay",
			"echo":  len(body),
			"usage": map[string]int64{"input_tokens": in, "output_tokens": out},
		})
	}))
	f.flaky = httptest.NewServer(newFlakyUpstream())

	var err error
	if f.certLegitimate, err = newSelfSignedCert("replay-client-legitimate"); err != nil {
		return nil, err
	}
	if f.certThief, err = newSelfSignedCert("replay-client-thief"); err != nil {
		return nil, err
	}
	if f.idp, err = newIdentityProvider(); err != nil {
		return nil, err
	}
	if err := f.buildSnapshot(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fixtures) close() {
	f.healthy.Close()
	f.llm.Close()
	f.flaky.Close()
	f.idp.server.Close()
}

// usageFor maps a leg's label to the token counts the upstream reports.
func usageFor(label string) (in, out int64) {
	if label == "spike" {
		return 20_000, 30_000
	}
	return 200, 100
}

// healthHeader lets a leg ask this upstream to be healthy. It is how the
// benign replay sends the SAME requests on the SAME routes to the SAME host
// without the attack: the only difference between the two cascade legs is
// whether the upstream answers.
const healthHeader = "X-Replay-Health"

// newFlakyUpstream is the cascade's single host. One host, not two, because
// the circuit breaker is per host and the whole point of this scenario is
// what one upstream does to every tenant behind it.
func newFlakyUpstream() http.Handler {
	// hedgeSeen counts attempts per request id, so the second attempt of one
	// request answers while the first is still waiting. Keyed by request id
	// rather than by a bare counter, so the handler behaves identically on
	// every run. Locked because the two hedge attempts arrive concurrently.
	var mu sync.Mutex
	hedgeSeen := map[string]int{}

	healthy := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/slow/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(healthHeader) == "healthy" {
			healthy(w)
			return
		}
		<-r.Context().Done()
	})
	mux.HandleFunc("/probe/", func(w http.ResponseWriter, r *http.Request) {
		healthy(w)
	})
	mux.HandleFunc("/hedge/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(healthHeader) == "healthy" {
			healthy(w)
			return
		}
		id := r.Header.Get("X-Request-Id")
		mu.Lock()
		hedgeSeen[id]++
		first := hedgeSeen[id] == 1
		mu.Unlock()
		if first {
			// The primary. It never answers; the backup attempt does.
			<-r.Context().Done()
			return
		}
		healthy(w)
	})
	return mux
}

// identityProvider mints the tokens the two token scenarios use.
type identityProvider struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

func newIdentityProvider() (*identityProvider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("replay: generating issuer key: %w", err)
	}
	idp := &identityProvider{key: key}
	idp.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "replay-k1", "alg": "RS256", "use": "sig",
			"n": b64raw.EncodeToString(key.N.Bytes()),
			"e": b64raw.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	return idp, nil
}

// mint signs a token. thumbprint, when set, is RFC 8705's cnf claim: the
// certificate the issuer says this token may only be presented with.
func (i *identityProvider) mint(issuer, subject, jti, scope, thumbprint string, lifetime time.Duration) (string, error) {
	claims := map[string]any{
		"iss":   issuer,
		"sub":   subject,
		"aud":   tokenAudience,
		"jti":   jti,
		"scope": scope,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(lifetime).Unix(),
	}
	if thumbprint != "" {
		claims["cnf"] = map[string]string{"x5t#S256": thumbprint}
	}
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": "replay-k1", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64raw.EncodeToString(header) + "." + b64raw.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64raw.EncodeToString(sig), nil
}

// tokenAuth builds the OIDC half of the chain: two issuers, each mapped to
// one tenant, both served by the one key set above.
func (f *fixtures) tokenAuth() (*jwt.Verifier, error) {
	var issuers []*jwt.Issuer
	for _, entry := range []struct{ name, tenant string }{
		{issuerReplay, tenantReplay},
		{issuerBinding, tenantBinding},
	} {
		source, err := jwt.NewKeySource(f.idp.server.URL, f.idp.server.Client(), time.Minute, time.Second)
		if err != nil {
			return nil, fmt.Errorf("replay: key source for %s: %w", entry.name, err)
		}
		issuers = append(issuers, &jwt.Issuer{
			Name: entry.name, Audience: tokenAudience, TenantID: entry.tenant, Keys: source,
		})
	}
	return jwt.NewVerifier(issuers)
}

// newSelfSignedCert is a client certificate. Only its bytes matter here: RFC
// 8705 binds a token to the SHA-256 of the presented leaf, and the gateway
// never validates the chain itself - the listener's tls.Config does that, and
// this harness drives the chain rather than the listener.
func newSelfSignedCert(commonName string) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("replay: generating client key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("replay: creating client certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// peerState is what the chain sees of a client certificate.
func peerState(cert *x509.Certificate) *tls.ConnectionState {
	if cert == nil {
		return nil
	}
	return &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{cert}}
}

// buildSnapshot is the whole configuration this evaluation runs against:
// seven tenants, their routes, their keys and their limiter policies.
//
// It is built in memory rather than loaded from Postgres because a route row
// that reaches the snapshot without passing the management API is exactly the
// case the request-time upstream check exists for, and because the completion
// commands must run with no database.
func (f *fixtures) buildSnapshot() error {
	mkKey := func(name, tenant string, status store.KeyStatus, grace *time.Time) (*store.APIKey, error) {
		gen, err := auth.Generate()
		if err != nil {
			return nil, err
		}
		f.keys[name] = gen
		return &store.APIKey{
			ID: gen.ID, TenantID: tenant, SecretHash: gen.SecretHash,
			Status: status, GraceUntil: grace,
		}, nil
	}
	graceUntil := time.Now().Add(24 * time.Hour)

	rotated, err := mkKey("spend-rotated", tenantSpend, store.KeyGrace, &graceUntil)
	if err != nil {
		return err
	}
	metaKey, err := mkKey("metadata", tenantMetadata, store.KeyActive, nil)
	if err != nil {
		return err
	}
	burstKey, err := mkKey("burst", tenantBurst, store.KeyActive, nil)
	if err != nil {
		return err
	}
	cascadeAKey, err := mkKey("cascade-a", tenantCascadeA, store.KeyActive, nil)
	if err != nil {
		return err
	}
	cascadeBKey, err := mkKey("cascade-b", tenantCascadeB, store.KeyActive, nil)
	if err != nil {
		return err
	}
	stranger, err := auth.Generate()
	if err != nil {
		return err
	}
	// A real key id carrying a stranger's secret.
	parts := strings.SplitN(stranger.Plaintext, "_", 3)
	f.forgedBurstKey = "tg_" + burstKey.ID + "_" + parts[2]

	roomy := func(id, name string) *store.Tenant {
		return &store.Tenant{
			ID: id, Name: name, Enabled: true,
			RLAlgorithm: store.AlgoSlidingWindow, RLWindow: time.Second, RLLimit: 200,
		}
	}
	tenants := []*store.Tenant{
		roomy(tenantReplay, "Replay Co"),
		roomy(tenantBinding, "Binding Co"),
		roomy(tenantSpend, "Spend Co"),
		roomy(tenantMetadata, "Metadata Co"),
		{
			// The burst tenant's policy is the only tight one, and it is the
			// same in both legs: what differs between them is the arrival
			// pattern, because arrival pattern is what a burst is.
			ID: tenantBurst, Name: "Burst Co", Enabled: true,
			RLAlgorithm: store.AlgoSlidingWindow, RLWindow: 250 * time.Millisecond, RLLimit: 6,
		},
		roomy(tenantCascadeA, "Cascade A"),
		roomy(tenantCascadeB, "Cascade B"),
	}

	healthy, err := url.Parse(f.healthy.URL)
	if err != nil {
		return err
	}
	llm, err := url.Parse(f.llm.URL)
	if err != nil {
		return err
	}
	flaky, err := url.Parse(f.flaky.URL)
	if err != nil {
		return err
	}
	metadata, err := url.Parse("http://169.254.169.254")
	if err != nil {
		return err
	}

	routes := []*store.Route{
		{ID: 1, TenantID: tenantReplay, PathPrefix: "/api/", Upstream: healthy, Timeout: 2 * time.Second},
		{ID: 2, TenantID: tenantBinding, PathPrefix: "/api/", Upstream: healthy, Timeout: 2 * time.Second},
		{ID: 3, TenantID: tenantSpend, PathPrefix: "/llm/", Upstream: llm, Timeout: 2 * time.Second, StripPrefix: true},
		// The row an operator would never write and a migration might: the
		// gateway's own credential injection points at the instance metadata
		// service.
		{ID: 4, TenantID: tenantMetadata, PathPrefix: "/meta/", Upstream: metadata, Timeout: time.Second},
		// The row that must keep working: a private upstream is not an SSRF
		// attempt, it is how this repo's compose and kind deployments run.
		{ID: 5, TenantID: tenantMetadata, PathPrefix: "/private/", Upstream: healthy, Timeout: 2 * time.Second},
		{ID: 6, TenantID: tenantBurst, PathPrefix: "/api/", Upstream: healthy, Timeout: 2 * time.Second},
	}
	for i, tenant := range []string{tenantCascadeA, tenantCascadeB} {
		base := int64(10 + i*10)
		routes = append(routes,
			&store.Route{ID: base + 1, TenantID: tenant, PathPrefix: "/slow/", Upstream: flaky,
				Timeout: 40 * time.Millisecond, RetryMax: 4},
			&store.Route{ID: base + 2, TenantID: tenant, PathPrefix: "/probe/", Upstream: flaky,
				Timeout: 2 * time.Second},
			&store.Route{ID: base + 3, TenantID: tenant, PathPrefix: "/hedge/", Upstream: flaky,
				Timeout: 3 * time.Second, HedgeEnabled: true, HedgeDelay: 20 * time.Millisecond},
		)
	}

	f.snapshot = store.SnapshotForTest(tenants, routes, []*store.APIKey{
		rotated, metaKey, burstKey, cascadeAKey, cascadeBKey,
	})
	return nil
}

// quietLogger keeps the gateway's own logging out of the harness's output.
// The events are the harness's product and they go to the timeline; a
// recovered panic or a proxy warning here would be noise in front of them.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

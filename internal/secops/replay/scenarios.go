package replay

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/lgoyal6/tollgate/internal/budget"
	"github.com/lgoyal6/tollgate/internal/jwt"
	"github.com/lgoyal6/tollgate/internal/limits"
	"github.com/lgoyal6/tollgate/internal/middleware"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/proxy"
	"github.com/lgoyal6/tollgate/internal/ratelimit"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/secops"
	"github.com/lgoyal6/tollgate/internal/store"
)

// harnessBreakerConfig is the breaker at harness scale.
//
// Same breaker, same state machine, smaller numbers: six samples instead of
// twenty and a quarter-second cooldown instead of five, so a scripted cascade
// takes under a second instead of a minute. The shape of what is being
// observed is unchanged, and the numbers are reported in the results so no
// reader has to guess which ones produced them.
func harnessBreakerConfig() resilience.BreakerConfig {
	cfg := resilience.DefaultBreakerConfig()
	cfg.MinRequests = 6
	cfg.Cooldown = 250 * time.Millisecond
	return cfg
}

// harnessLimits mirrors the gateway's shipped abuse bounds. None of them are
// the subject of a scenario; they are here because the chain runs with them
// and a harness that quietly dropped a middleware would not be running the
// gateway's chain.
func harnessLimits() limits.Config {
	return limits.Config{
		MaxRequestBytes:      8 << 20,
		MaxDecompressedBytes: 8 << 20,
		MaxResponseBytes:     32 << 20,
		MaxInFlightPerTenant: 64,
		MaxQueuePerTenant:    128,
		QueueWait:            time.Second,
		MaxRequestDuration:   60 * time.Second,
	}
}

// memoryLedger is the budget ledger with no database.
//
// The real one is rows in Postgres and is tested against a real Postgres in
// internal/budget. This exists so the Budget middleware is in the chain at
// all, because the spend anomaly detector observes its settlement: a harness
// that left Budget out would be evaluating a chain the gateway does not run.
// It never refuses, so nothing in these results depends on it deciding
// anything.
type memoryLedger struct {
	mu      sync.Mutex
	settled int64
	calls   int
}

func (l *memoryLedger) Reserve(context.Context, string, string, int64, string) (budget.Status, error) {
	unlimited := int64(1) << 40
	return budget.Status{Remaining: &unlimited}, nil
}

func (l *memoryLedger) Settle(_ context.Context, _, _ string, actual int64) (budget.Status, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.settled += actual
	l.calls++
	return budget.Status{}, nil
}

func (l *memoryLedger) Release(context.Context, string, string, string) error       { return nil }
func (l *memoryLedger) MarkUncertain(context.Context, string, string, string) error { return nil }

// harness is one pass: a fresh chain, a fresh recorder, fresh limiter and
// breaker state.
//
// Fresh per pass on purpose. Reusing them would let the malicious pass leave
// a half-open breaker, a spent rate limit window or a filled replay filter
// behind for the benign pass, and every one of those makes the benign result
// easier to get right for a reason that is not detection.
type harness struct {
	fx       *fixtures
	recorder *secops.Recorder
	handler  http.Handler
	ledger   *memoryLedger
}

func newHarness(fx *fixtures, rec *secops.Recorder) (*harness, error) {
	verifier, err := fx.tokenAuth()
	if err != nil {
		return nil, err
	}
	h := &harness{fx: fx, recorder: rec, ledger: &memoryLedger{}}

	logger := quietLogger()
	metrics := observability.NewMetrics()
	breakers := resilience.NewBreakerGroup(harnessBreakerConfig())
	px := proxy.New(proxy.Options{
		Breakers:       breakers,
		HedgingEnabled: true,
		MaxBodyBuffer:  1 << 20,
		MaxIdlePerHost: 8,
		Limits:         harnessLimits(),
		Logger:         logger,
		Metrics:        metrics,
	})
	snapshots := func() *store.Snapshot { return fx.snapshot }
	tokens := &middleware.TokenAuth{
		Verifier: verifier,
		// The cache is on because it is on by default in the gateway, and
		// because a repeat presentation of one token is precisely the path
		// the replay scenario exercises. It re-checks certificate binding on
		// every hit, so it cannot hide the second scenario.
		Cache: jwt.NewVerifiedCache(30*time.Second, 256),
	}

	// The gateway's chain, in the gateway's order. CurrentAuthorization is
	// the one layer absent: it is a targeted Postgres query, and these
	// commands run with no database.
	h.handler = middleware.Chain(px,
		middleware.Recover(logger),
		secops.Observe(rec),
		middleware.RequestID(),
		middleware.Metrics(metrics),
		middleware.Tracing("tollgate-secops-replay"),
		middleware.Auth(snapshots, metrics, tokens),
		middleware.Router(snapshots),
		middleware.RequestSize(harnessLimits(), metrics),
		middleware.RateLimit(ratelimit.NewMemoryLimiter(), true, metrics, logger),
		middleware.Concurrency(harnessLimits(), metrics),
		middleware.Budget(h.ledger, false, logger),
	)
	return h, nil
}

// call is one scripted request.
type call struct {
	method  string
	path    string
	bearer  string
	apiKey  string
	cert    *x509.Certificate
	body    string
	headers map[string]string
}

func (h *harness) do(c call) int {
	var body *strings.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(c.method, c.path, body)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(c.method, c.path, nil)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	req.TLS = peerState(c.cert)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec.Code
}

// legOutcome is what one scenario leg did, kept so the results can say what
// was actually sent rather than only what was detected.
type legOutcome struct {
	Scenario string   `json:"scenario"`
	Requests int      `json:"requests_sent"`
	Statuses []int    `json:"response_statuses"`
	Notes    []string `json:"notes"`
}

func (l *legOutcome) send(h *harness, c call) {
	l.Requests++
	l.Statuses = append(l.Statuses, h.do(c))
}

// legs are the six malicious scenarios. Each one runs in both passes; the
// benign flag is what "without the attack" means for that scenario, and each
// leg says so in its own notes.
func legs() []func(*harness, bool) (legOutcome, error) {
	return []func(*harness, bool) (legOutcome, error){
		legStolenTokenReplay,
		legCertBindingMismatch,
		legProviderKeyAnomaly,
		legSSRFMetadata,
		legAuthRateBurst,
		legUpstreamCascade,
	}
}

// legStolenTokenReplay: one token, three presentations. Malicious means the
// second and third come from a different peer.
func legStolenTokenReplay(h *harness, malicious bool) (legOutcome, error) {
	out := legOutcome{Scenario: "stolen_token_replay"}
	jti := "jti-replay-benign"
	if malicious {
		jti = "jti-replay-stolen"
	}
	// No cnf claim: an unbound token, which is what most issuers mint. That
	// is the whole reason this scenario ends in "allowed".
	token, err := h.fx.idp.mint(issuerReplay, "user-replay", jti, "read", "", 5*time.Minute)
	if err != nil {
		return out, err
	}
	thief := h.fx.certThief
	if !malicious {
		thief = h.fx.certLegitimate
	}
	out.send(h, call{method: http.MethodGet, path: "/api/thing", bearer: token, cert: h.fx.certLegitimate})
	out.send(h, call{method: http.MethodGet, path: "/api/thing", bearer: token, cert: thief})
	out.send(h, call{method: http.MethodGet, path: "/api/thing", bearer: token, cert: thief})
	out.Notes = append(out.Notes,
		"three presentations of one unbound token",
		conditional(malicious,
			"presentations two and three come from a different client certificate",
			"all three presentations come from the certificate that first used it"))
	return out, nil
}

// legCertBindingMismatch: a token the issuer bound to one certificate,
// presented with another.
func legCertBindingMismatch(h *harness, malicious bool) (legOutcome, error) {
	out := legOutcome{Scenario: "cert_binding_mismatch"}
	jti := "jti-bound-benign"
	if malicious {
		jti = "jti-bound-stolen"
	}
	token, err := h.fx.idp.mint(issuerBinding, "user-bound", jti, "read",
		jwt.Thumbprint(h.fx.certLegitimate), 5*time.Minute)
	if err != nil {
		return out, err
	}
	presented := h.fx.certLegitimate
	if malicious {
		presented = h.fx.certThief
	}
	for i := 0; i < 2; i++ {
		out.send(h, call{method: http.MethodGet, path: "/api/thing", bearer: token, cert: presented})
	}
	out.Notes = append(out.Notes,
		"two presentations of a token the issuer bound to one certificate",
		conditional(malicious,
			"presented with a different certificate, which the binding control refuses",
			"presented with the certificate it is bound to"))
	return out, nil
}

// legProviderKeyAnomaly: a key inside its rotation grace window, used twenty
// times. Malicious means the provider reports a spike.
func legProviderKeyAnomaly(h *harness, malicious bool) (legOutcome, error) {
	out := legOutcome{Scenario: "provider_key_anomaly"}
	usage := "normal"
	if malicious {
		usage = "spike"
	}
	key := h.fx.keys["spend-rotated"].Plaintext
	for i := 0; i < 20; i++ {
		out.send(h, call{
			method:  http.MethodPost,
			path:    "/llm/v1/messages",
			apiKey:  key,
			body:    `{"model":"claude-sonnet-5","max_tokens":8000}`,
			headers: map[string]string{"X-Replay-Usage": usage},
		})
	}
	out.Notes = append(out.Notes,
		"twenty requests on the same rotated key still inside its grace window",
		conditional(malicious,
			"the provider reports 20k in and 30k out per request: 510,000 micros each",
			"the provider reports 200 in and 100 out per request: 2,100 micros each"))
	return out, nil
}

// legSSRFMetadata: a request on a route whose upstream is the instance
// metadata service. The benign counterpart is the private upstream this
// repo's own deployments use, which must not be refused.
func legSSRFMetadata(h *harness, malicious bool) (legOutcome, error) {
	out := legOutcome{Scenario: "ssrf_metadata_attempt"}
	path := "/private/thing"
	if malicious {
		path = "/meta/latest/meta-data/iam/security-credentials/"
	}
	key := h.fx.keys["metadata"].Plaintext
	for i := 0; i < 2; i++ {
		out.send(h, call{method: http.MethodGet, path: path, apiKey: key})
	}
	out.Notes = append(out.Notes,
		conditional(malicious,
			"two requests on a route whose upstream is 169.254.169.254",
			"two requests on a route whose upstream is a private address, which must NOT be refused"))
	return out, nil
}

// legAuthRateBurst: twelve credentials plus twenty requests. Malicious means
// the credentials are forged and the twenty arrive at once.
func legAuthRateBurst(h *harness, malicious bool) (legOutcome, error) {
	out := legOutcome{Scenario: "auth_rate_burst"}
	real := h.fx.keys["burst"].Plaintext
	credential := real
	if malicious {
		credential = h.fx.forgedBurstKey
	}
	// pace is what separates a burst from ordinary traffic: identical
	// requests, identical policy, different arrival pattern.
	pace := 80 * time.Millisecond
	if malicious {
		pace = 0
	}
	for i := 0; i < 12; i++ {
		out.send(h, call{method: http.MethodGet, path: "/api/thing", apiKey: credential})
		sleep(pace)
	}
	for i := 0; i < 20; i++ {
		out.send(h, call{method: http.MethodGet, path: "/api/thing", apiKey: real})
		sleep(pace)
	}
	out.Notes = append(out.Notes,
		"twelve credential presentations then twenty requests, on one tenant",
		conditional(malicious,
			"the twelve carry a real key id with somebody else's secret, and the twenty arrive inside one limiter window",
			"all thirty two carry the tenant's own key, paced at 80ms so they stay inside the tenant's own policy"))
	return out, nil
}

// legUpstreamCascade: one upstream, two tenants, then a recovery.
func legUpstreamCascade(h *harness, malicious bool) (legOutcome, error) {
	out := legOutcome{Scenario: "upstream_timeout_cascade"}
	health := map[string]string{}
	if !malicious {
		health[healthHeader] = "healthy"
	}
	keyA := h.fx.keys["cascade-a"].Plaintext
	keyB := h.fx.keys["cascade-b"].Plaintext

	out.send(h, call{method: http.MethodGet, path: "/slow/one", apiKey: keyA, headers: health})
	out.send(h, call{method: http.MethodGet, path: "/slow/one", apiKey: keyB, headers: health})
	out.send(h, call{method: http.MethodGet, path: "/slow/two", apiKey: keyA, headers: health})

	// Let the breaker cool down and close again, so the recovery below is a
	// hedge winning rather than a breaker refusing. The probes are ordinary
	// successful requests and record nothing.
	sleep(harnessBreakerConfig().Cooldown + 60*time.Millisecond)
	for i := 0; i < 3; i++ {
		out.send(h, call{method: http.MethodGet, path: "/probe/x", apiKey: keyA, headers: health})
	}
	out.send(h, call{method: http.MethodGet, path: "/hedge/x", apiKey: keyA, headers: health})

	out.Notes = append(out.Notes,
		"seven requests from two tenants to one upstream host, on the same routes in both legs",
		conditional(malicious,
			"the upstream never answers, so attempts time out, the shared breaker opens on both tenants, and the last request is carried by a hedge",
			"the same upstream answers, so nothing times out, the breaker stays closed and no hedge fires"))
	return out, nil
}

func conditional(cond bool, whenTrue, whenFalse string) string {
	if cond {
		return whenTrue
	}
	return whenFalse
}

// sleep is the only place this harness waits. Zero means do not wait at all,
// which is what a burst is.
func sleep(d time.Duration) {
	if d <= 0 {
		return
	}
	time.Sleep(d)
}

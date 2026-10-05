package proxy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

// A route plan is two upstreams and an order. Most of what follows is about the
// second upstream NOT being contacted: a fallback that fires when it should not
// sends somebody's request - and somebody's money - to a provider that was
// never asked to answer it.

// upstream records what reached it, so a test can assert on zero requests as
// easily as on the body of the first one.
type upstream struct {
	*httptest.Server
	hits    atomic.Int64
	bodies  chan string
	headers chan http.Header
}

func newUpstream(t *testing.T, handle func(w http.ResponseWriter, r *http.Request)) *upstream {
	t.Helper()
	u := &upstream{
		bodies:  make(chan string, 8),
		headers: make(chan http.Header, 8),
	}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		select {
		case u.bodies <- string(body):
		default:
		}
		select {
		case u.headers <- r.Header.Clone():
		default:
		}
		handle(w, r)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) host(t *testing.T) string {
	t.Helper()
	parsed, err := url.Parse(u.URL)
	if err != nil {
		t.Fatalf("parsing %q: %v", u.URL, err)
	}
	return parsed.Host
}

func always(status int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }
}

// planOver builds a route with one fallback, the way the router would.
func planOver(t *testing.T, primary, fallback string, mutate func(*store.Route)) *store.RoutePlan {
	t.Helper()
	route := routeTo(t, primary, func(r *store.Route) {
		if fallback != "" {
			// A fallback is an attempt out of the route's existing ceiling, so
			// a route with no retries has none to give it. The admin layer
			// refuses that configuration; these tests configure a usable one.
			r.RetryMax = 1
		}
		if mutate != nil {
			mutate(r)
		}
	})
	if fallback != "" {
		u, err := url.Parse(fallback)
		if err != nil {
			t.Fatalf("parsing %q: %v", fallback, err)
		}
		route.FallbackUpstream = u
	}
	return store.PlanFor(route)
}

// sendPlan drives the proxy with a plan installed, as the router would.
func sendPlan(p *Proxy, plan *store.RoutePlan, req *http.Request) (*httptest.ResponseRecorder, *reqctx.Info) {
	info := &reqctx.Info{RequestID: "req-test-1", TenantID: "acme"}
	ctx := reqctx.WithInfo(req.Context(), info)
	ctx = reqctx.WithRoute(ctx, plan.Route)
	ctx = reqctx.WithPlan(ctx, plan)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req.WithContext(ctx))
	return rec, info
}

func get(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://gw.example"+path, nil)
	req.RemoteAddr = "203.0.113.7:1234"
	return req
}

func post(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://gw.example"+path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.7:1234"
	req.ContentLength = int64(len(body))
	return req
}

// --------------------------------------------------------------- the plan

func TestPlanForARouteWithNoFallbackHasOneCandidate(t *testing.T) {
	plan := planOver(t, "http://primary.invalid", "", nil)
	if len(plan.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(plan.Candidates))
	}
	if plan.Primary().Fallback {
		t.Error("the only candidate is marked as a fallback")
	}
	if plan.HasFallback() {
		t.Error("HasFallback on a single-upstream route")
	}
}

func TestPlanOrderIsPrimaryThenFallback(t *testing.T) {
	plan := planOver(t, "http://primary.invalid", "http://backup.invalid", nil)
	if got := plan.Order(); got != "primary.invalid,backup.invalid" {
		t.Fatalf("order = %q", got)
	}
	if !plan.Candidates[1].Fallback {
		t.Error("second candidate is not marked as the fallback")
	}
}

func TestThePlanCarriesNoRequestBytes(t *testing.T) {
	// The type exists to make this true by construction: the proxy owns
	// bodies, credentials and connections, and the plan owns the order.
	plan := planOver(t, "http://primary.invalid", "http://backup.invalid", func(r *store.Route) {
		r.UpstreamAuthHeader = "x-api-key"
		r.UpstreamAuthEnv = "PRIMARY_KEY"
		r.FallbackAuthHeader = "x-api-key"
		r.FallbackAuthEnv = "BACKUP_KEY"
	})
	for _, c := range plan.Candidates {
		// A candidate names where a credential comes from. It never holds one.
		if c.AuthEnv == "" {
			t.Fatal("candidate lost its credential source")
		}
		if strings.Contains(fmt.Sprint(c), "secret") {
			t.Error("candidate rendered something that looks like a value")
		}
	}
}

// ------------------------------------------------- the single-upstream path

func TestASingleUpstreamRouteIsUnchanged(t *testing.T) {
	primary := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok") //nolint:errcheck
	})
	p := testProxy(t, Options{})

	rec, info := sendPlan(p, planOver(t, primary.URL, "", nil), get("/api/x"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if info.Fallback {
		t.Error("a route with no fallback reported one")
	}
	if got := primary.hits.Load(); got != 1 {
		t.Errorf("primary hits = %d, want 1", got)
	}
}

func TestAPrimarySuccessNeverContactsTheFallback(t *testing.T) {
	primary := newUpstream(t, always(http.StatusOK))
	fallback := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{})

	rec, info := sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), get("/api/x"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := fallback.hits.Load(); got != 0 {
		t.Fatalf("fallback hits = %d, want 0", got)
	}
	if info.Fallback {
		t.Error("info says the fallback served a request the primary answered")
	}
}

// --------------------------------------------------------- when it may fire

func TestAReplayableRequestFailsOverOnA503(t *testing.T) {
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "from the fallback") //nolint:errcheck
	})
	p := testProxy(t, Options{})

	rec, info := sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), get("/api/x"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
	}
	if rec.Body.String() != "from the fallback" {
		t.Errorf("body = %q", rec.Body.String())
	}
	if !info.Fallback {
		t.Error("info does not record that the fallback served this")
	}
	if info.Upstream != fallback.host(t) {
		t.Errorf("info.Upstream = %q, want the fallback", info.Upstream)
	}
}

func TestAPrimaryTransportFailureFailsOver(t *testing.T) {
	dead := newUpstream(t, always(http.StatusOK))
	deadURL := dead.URL
	dead.Close() // nothing is listening there any more

	fallback := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{})

	rec, _ := sendPlan(p, planOver(t, deadURL, fallback.URL, nil), get("/api/x"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := fallback.hits.Load(); got != 1 {
		t.Errorf("fallback hits = %d, want 1", got)
	}
}

func TestAnOpenPrimaryBreakerFailsOver(t *testing.T) {
	primary := newUpstream(t, always(http.StatusInternalServerError))
	fallback := newUpstream(t, always(http.StatusOK))

	// Trip the primary's breaker, then check the plan routes around it. The
	// breaker is keyed on the host, so the fallback has its own and is
	// unaffected - which is the entire reason a standby is worth having.
	cfg := resilience.DefaultBreakerConfig()
	cfg.MinRequests = 1
	cfg.FailureRatio = 0.1
	p := testProxy(t, Options{Breakers: resilience.NewBreakerGroup(cfg)})
	plan := planOver(t, primary.URL, fallback.URL, nil)

	for i := 0; i < 4; i++ {
		sendPlan(p, plan, get("/api/x"))
	}
	before := fallback.hits.Load()
	rec, _ := sendPlan(p, plan, get("/api/x"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the fallback's 200", rec.Code)
	}
	if fallback.hits.Load() <= before {
		t.Error("the fallback was never tried with the primary breaker open")
	}
}

func TestTheFallbackGetsTheByteIdenticalBodyAfterThePrimaryConsumedIt(t *testing.T) {
	// NEGATIVE CONTROL 1. The primary reads the body to the end and then
	// refuses. The fallback must still receive exactly the original bytes: a
	// gateway that replayed a drained reader would send an empty request and
	// the upstream would answer something plausible and wrong.
	const payload = `{"q":"the quick brown fox","n":42}`
	// newUpstream reads and records the body before the handler runs, which is
	// what "the primary consumed it" means here: the bytes were taken off the
	// wire at the primary, and the fallback still has to receive them.
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{})

	// A GET with a body: idempotent, replayable, and the only way to reach
	// failover with bytes to compare.
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", strings.NewReader(payload))
	req.RemoteAddr = "203.0.113.7:1234"
	req.ContentLength = int64(len(payload))

	rec, _ := sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if primarySaw := <-primary.bodies; primarySaw != payload {
		t.Fatalf("the primary did not consume the body: %q", primarySaw)
	}
	got := <-fallback.bodies
	if got != payload {
		t.Fatalf("fallback body = %q, want the original %q", got, payload)
	}
	if sha256.Sum256([]byte(got)) != sha256.Sum256([]byte(payload)) {
		t.Error("fallback body differs from the original by digest")
	}
}

// --------------------------------------------------- when it must NOT fire

func TestAPostNeverFailsOver(t *testing.T) {
	// NEGATIVE CONTROL 2. A completion is a POST that may already have been
	// generated and billed upstream. "It returned 503" is not evidence that it
	// did nothing, so a second provider must not be asked the same question.
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{})

	rec, info := sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), post("/api/x", `{"prompt":"hi"}`))

	if got := fallback.hits.Load(); got != 0 {
		t.Fatalf("fallback hits = %d, want 0 for a POST", got)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want the primary's 503 relayed", rec.Code)
	}
	if info.Fallback {
		t.Error("info claims a fallback that never ran")
	}
}

func TestAnUnknownLengthRequestNeverFailsOver(t *testing.T) {
	// NEGATIVE CONTROL 3. A chunked upload is never buffered, so there is
	// nothing to send twice. Failing over here would forward a body the
	// gateway no longer has.
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{})

	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", strings.NewReader("streamed"))
	req.RemoteAddr = "203.0.113.7:1234"
	req.ContentLength = -1 // chunked: no declared length

	rec, _ := sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), req)

	if got := fallback.hits.Load(); got != 0 {
		t.Fatalf("fallback hits = %d, want 0 for an unbuffered request", got)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want the primary's 503 relayed", rec.Code)
	}
}

func TestARequestOverTheBufferLimitNeverFailsOver(t *testing.T) {
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{MaxBodyBuffer: 8})

	body := strings.Repeat("x", 64)
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.7:1234"
	req.ContentLength = int64(len(body))

	sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), req)

	if got := fallback.hits.Load(); got != 0 {
		t.Fatalf("fallback hits = %d, want 0 for a body past the buffer limit", got)
	}
}

func TestAPartialResponseNeverStartsAFallback(t *testing.T) {
	// NEGATIVE CONTROL 4. Once the status line and some bytes are on the wire,
	// there is no way to un-send them. A second upstream's answer would be
	// spliced onto the first one's, and the client would have no way to tell.
	primary := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "the first half") //nolint:errcheck
		w.(http.Flusher).Flush()
		// Close without sending the rest: the declared length is a lie.
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
			}
		}
	})
	fallback := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{})

	rec, _ := sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), get("/api/x"))

	if got := fallback.hits.Load(); got != 0 {
		t.Fatalf("fallback hits = %d, want 0 once bytes have been written", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want the 200 already sent", rec.Code)
	}
}

func TestACancelledClientContextNeverStartsAFallback(t *testing.T) {
	primary := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	fallback := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{})

	ctx, cancel := context.WithCancel(context.Background())
	req := get("/api/x").WithContext(ctx)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), req)

	if got := fallback.hits.Load(); got != 0 {
		t.Fatalf("fallback hits = %d, want 0 after the client went away", got)
	}
}

func TestFourXXNeverFailsOver(t *testing.T) {
	// A 401 means the credential is wrong, a 403 means the caller may not, and
	// a 429 means slow down. Asking a second provider gets the same answer one
	// more time, out of somebody else's quota.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			primary := newUpstream(t, always(status))
			fallback := newUpstream(t, always(http.StatusOK))
			p := testProxy(t, Options{})

			rec, _ := sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), get("/api/x"))

			if got := fallback.hits.Load(); got != 0 {
				t.Fatalf("fallback hits = %d, want 0 for a %d", got, status)
			}
			if rec.Code != status {
				t.Errorf("status = %d, want the primary's %d relayed", rec.Code, status)
			}
		})
	}
}

// ------------------------------------------------------------ the ceilings

func TestAFallbackSpendsTheExistingAttemptCeilingNotASecondOne(t *testing.T) {
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, always(http.StatusServiceUnavailable))
	p := testProxy(t, Options{})

	// retry_max 2 -> three attempts for the whole request, however many
	// upstreams it touches.
	plan := planOver(t, primary.URL, fallback.URL, func(r *store.Route) { r.RetryMax = 2 })
	_, info := sendPlan(p, plan, get("/api/x"))

	total := primary.hits.Load() + fallback.hits.Load()
	if total > 3 {
		t.Fatalf("upstream attempts = %d (primary %d, fallback %d), ceiling is 3",
			total, primary.hits.Load(), fallback.hits.Load())
	}
	if info.Attempts > 3 {
		t.Errorf("info.Attempts = %d, ceiling is 3", info.Attempts)
	}
	if fallback.hits.Load() == 0 {
		t.Error("the fallback never got a turn inside the ceiling")
	}
}

func TestAnExhaustedCeilingLeavesNothingForTheFallback(t *testing.T) {
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{})

	// retry_max 0 with a fallback is refused by the admin layer, but a row can
	// still arrive this way through a migration or a direct UPDATE. The proxy
	// has to stay safe rather than assume the validation ran: one attempt in
	// total, it goes to the primary, and the relayed 503 is exactly what this
	// route did before it had a fallback at all.
	plan := planOver(t, primary.URL, fallback.URL, func(r *store.Route) { r.RetryMax = 0 })
	rec, _ := sendPlan(p, plan, get("/api/x"))

	if got := primary.hits.Load(); got != 1 {
		t.Fatalf("primary hits = %d, want 1", got)
	}
	if got := fallback.hits.Load(); got != 0 {
		t.Fatalf("fallback hits = %d, want 0 with no attempts left", got)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want the primary's 503 relayed", rec.Code)
	}
}

// -------------------------------------------------------------- credentials

func TestTheFallbackUsesItsOwnCredentialSource(t *testing.T) {
	var primaryKey, fallbackKey string
	primary := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		primaryKey = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	fallback := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		fallbackKey = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
	})
	t.Setenv("TOLLGATE_TEST_PRIMARY_KEY", "primary-secret")
	t.Setenv("TOLLGATE_TEST_FALLBACK_KEY", "fallback-secret")

	p := testProxy(t, Options{})
	plan := planOver(t, primary.URL, fallback.URL, func(r *store.Route) {
		r.UpstreamAuthHeader = "x-api-key"
		r.UpstreamAuthEnv = "TOLLGATE_TEST_PRIMARY_KEY"
		r.FallbackAuthHeader = "x-api-key"
		r.FallbackAuthEnv = "TOLLGATE_TEST_FALLBACK_KEY"
	})
	rec, _ := sendPlan(p, plan, get("/api/x"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if primaryKey != "primary-secret" {
		t.Errorf("primary saw %q", primaryKey)
	}
	if fallbackKey != "fallback-secret" {
		t.Fatalf("fallback saw %q, want its own credential", fallbackKey)
	}
}

func TestTheFallbackNeverReceivesThePrimarysCredential(t *testing.T) {
	// A fallback is usually a different provider. Sharing the primary's env
	// var would send one provider's key to another one, which is worse than
	// the outage the fallback exists to survive.
	var fallbackHeaders http.Header
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		fallbackHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	t.Setenv("TOLLGATE_TEST_PRIMARY_KEY", "primary-secret")

	p := testProxy(t, Options{})
	plan := planOver(t, primary.URL, fallback.URL, func(r *store.Route) {
		r.UpstreamAuthHeader = "x-api-key"
		r.UpstreamAuthEnv = "TOLLGATE_TEST_PRIMARY_KEY"
		// No fallback credential configured at all.
	})
	sendPlan(p, plan, get("/api/x"))

	for name, values := range fallbackHeaders {
		for _, v := range values {
			if strings.Contains(v, "primary-secret") {
				t.Fatalf("the primary's credential reached the fallback in %s", name)
			}
		}
	}
}

func TestNoCallerCredentialReachesEitherUpstream(t *testing.T) {
	var primaryAuth, fallbackAuth string
	primary := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		primaryAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	fallback := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		fallbackAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	t.Setenv("TOLLGATE_TEST_FALLBACK_KEY", "fallback-secret")

	p := testProxy(t, Options{})
	plan := planOver(t, primary.URL, fallback.URL, func(r *store.Route) {
		r.FallbackAuthHeader = "x-api-key"
		r.FallbackAuthEnv = "TOLLGATE_TEST_FALLBACK_KEY"
	})
	// The auth middleware strips the caller's key before the proxy is reached;
	// this asserts the proxy does not put one back on either candidate.
	sendPlan(p, plan, get("/api/x"))

	if primaryAuth != "" {
		t.Errorf("primary saw an Authorization header: %q", primaryAuth)
	}
	if fallbackAuth != "" {
		t.Errorf("fallback saw an Authorization header: %q", fallbackAuth)
	}
}

func TestAMissingFallbackCredentialDoesNotSendAnUnauthenticatedRequest(t *testing.T) {
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, always(http.StatusOK))

	p := testProxy(t, Options{})
	plan := planOver(t, primary.URL, fallback.URL, func(r *store.Route) {
		r.FallbackAuthHeader = "x-api-key"
		r.FallbackAuthEnv = "TOLLGATE_TEST_UNSET_KEY" // not in the environment
	})
	rec, _ := sendPlan(p, plan, get("/api/x"))

	if got := fallback.hits.Load(); got != 0 {
		t.Fatalf("fallback hits = %d: an unauthenticated request was sent", got)
	}
	if rec.Code == http.StatusOK {
		t.Error("the gateway reported success without reaching any upstream")
	}
}

// --------------------------------------------------------- path and routing

func TestBothCandidatesSeeTheSamePath(t *testing.T) {
	var primaryPath, fallbackPath string
	primary := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		primaryPath = r.URL.Path
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	fallback := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		fallbackPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	p := testProxy(t, Options{})
	plan := planOver(t, primary.URL, fallback.URL, func(r *store.Route) { r.StripPrefix = true })

	sendPlan(p, plan, get("/api/widgets"))

	if primaryPath != "/widgets" || fallbackPath != "/widgets" {
		t.Fatalf("paths = %q and %q, want both /widgets", primaryPath, fallbackPath)
	}
}

func TestAPlanIsDerivedWhenOnlyARouteIsInstalled(t *testing.T) {
	// Callers that predate plans install a route and nothing else. The plan
	// that route implies is a single candidate, which is what it always was.
	primary := newUpstream(t, always(http.StatusOK))
	p := testProxy(t, Options{})

	rec, _ := send(p, routeTo(t, primary.URL, nil), get("/api/x"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

// ------------------------------------------------------------ observability

func TestTheLogNamesTheCandidateOrderAndTheChosenOneWithoutSecrets(t *testing.T) {
	const payload = `{"prompt":"the secret passphrase is swordfish"}`
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, always(http.StatusOK))
	t.Setenv("TOLLGATE_TEST_PRIMARY_KEY", "primary-secret-value")
	t.Setenv("TOLLGATE_TEST_FALLBACK_KEY", "fallback-secret-value")

	var logs strings.Builder
	p := testProxy(t, Options{})
	p.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	plan := planOver(t, primary.URL, fallback.URL, func(r *store.Route) {
		r.UpstreamAuthHeader = "x-api-key"
		r.UpstreamAuthEnv = "TOLLGATE_TEST_PRIMARY_KEY"
		r.FallbackAuthHeader = "x-api-key"
		r.FallbackAuthEnv = "TOLLGATE_TEST_FALLBACK_KEY"
	})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", strings.NewReader(payload))
	req.RemoteAddr = "203.0.113.7:1234"
	req.ContentLength = int64(len(payload))
	sendPlan(p, plan, req)

	written := logs.String()
	if !strings.Contains(written, plan.Order()) {
		t.Errorf("the log does not name the candidate order %q:\n%s", plan.Order(), written)
	}
	if !strings.Contains(written, fallback.host(t)) {
		t.Errorf("the log does not name the chosen candidate:\n%s", written)
	}
	// The log is the one place a secret escapes without anybody noticing,
	// because nothing about a log line looks like a credential store.
	for _, forbidden := range []string{"primary-secret-value", "fallback-secret-value", "swordfish"} {
		if strings.Contains(written, forbidden) {
			t.Errorf("the log leaked %q:\n%s", forbidden, written)
		}
	}
}

func TestTheFailoverLogSaysWhy(t *testing.T) {
	primary := newUpstream(t, always(http.StatusServiceUnavailable))
	fallback := newUpstream(t, always(http.StatusOK))

	var logs strings.Builder
	p := testProxy(t, Options{})
	p.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	sendPlan(p, planOver(t, primary.URL, fallback.URL, nil), get("/api/x"))

	if !strings.Contains(logs.String(), "503") {
		t.Errorf("the failover log does not say what the primary answered:\n%s", logs.String())
	}
}

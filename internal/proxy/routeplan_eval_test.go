package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

// TestOrderedRoutePlanEvaluation measures what the route plan does to a fixed
// scripted workload, and writes results/route-plan-eval.json.
//
// **What this is not.** Two httptest servers and a proxy, in one process, on one
// machine, with synthetic requests. The "outage" is a handler that was told to
// return 503. Nothing here is a datacenter, a provider, a network partition or a
// real failover, and the success rates below are arithmetic about a scripted
// condition rather than evidence about availability. In particular it says
// nothing about LLM traffic, which is POST and therefore never fails over at
// all -- see TestAPostNeverFailsOver.
//
// Latency figures are wall-clock on a loopback interface and are not
// deterministic; the *behaviour* is. Read them for the shape of the overhead,
// not as a benchmark.
const evalRequests = 300

type armResult struct {
	Arm                  string  `json:"arm"`
	Requests             int     `json:"requests"`
	Succeeded            int     `json:"succeeded"`
	SuccessRatePercent   float64 `json:"success_rate_percent"`
	Attempts             int     `json:"upstream_attempts"`
	AttemptsPerRequest   float64 `json:"attempts_per_request"`
	Fallbacks            int     `json:"fallbacks_used"`
	BodyIntegrityFailure int     `json:"body_integrity_failures"`
	PrimaryHits          int64   `json:"primary_hits"`
	FallbackHits         int64   `json:"fallback_hits"`
	P50ms                float64 `json:"p50_ms"`
	P95ms                float64 `json:"p95_ms"`
	P99ms                float64 `json:"p99_ms"`
}

func percentile(sorted []time.Duration, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return float64(sorted[i].Microseconds()) / 1000.0
}

// runArm drives one scripted arm and returns its measurements.
//
// Dedicated servers rather than the newUpstream helper: that one records the
// body before the handler runs, which is exactly right for asserting on what
// arrived and exactly wrong here, where the handler has to read the bytes
// itself to check them.
func runArm(t *testing.T, name string, primaryStatus int, withFallback bool) armResult {
	t.Helper()

	var mismatches, primaryHits, fallbackHits atomic.Int64

	// Each request carries a payload only it uses, so a body that arrived
	// truncated after the primary drained it, or arrived at the wrong
	// upstream, is visible rather than merely plausible.
	var mu sync.Mutex
	expected := map[string]bool{}

	serve := func(status int, hits *atomic.Int64) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			ok := expected[string(body)]
			mu.Unlock()
			if !ok {
				mismatches.Add(1)
			}
			w.WriteHeader(status)
		}
	}

	primary := httptest.NewServer(serve(primaryStatus, &primaryHits))
	t.Cleanup(primary.Close)
	fallback := httptest.NewServer(serve(http.StatusOK, &fallbackHits))
	t.Cleanup(fallback.Close)

	// A breaker that cannot open inside this run. The arms are being compared
	// on what the route plan does; a breaker tripping partway through one of
	// them would replace the thing being measured with a different mechanism.
	// The breaker-open path has its own test.
	cfg := resilience.DefaultBreakerConfig()
	cfg.MinRequests = evalRequests * 10

	p := testProxy(t, Options{Breakers: resilience.NewBreakerGroup(cfg)})
	p.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	fallbackURL := ""
	if withFallback {
		fallbackURL = fallback.URL
	}
	plan := planOver(t, primary.URL, fallbackURL, func(r *store.Route) { r.RetryMax = 1 })

	result := armResult{Arm: name, Requests: evalRequests}
	durations := make([]time.Duration, 0, evalRequests)

	for i := 0; i < evalRequests; i++ {
		payload := fmt.Sprintf(`{"n":%d,"pad":%q}`, i, strings.Repeat("x", 64))
		mu.Lock()
		expected[payload] = true
		mu.Unlock()

		req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/x", strings.NewReader(payload))
		req.RemoteAddr = "203.0.113.7:1234"
		req.ContentLength = int64(len(payload))

		start := time.Now()
		rec, info := sendPlan(p, plan, req)
		durations = append(durations, time.Since(start))

		if rec.Code == http.StatusOK {
			result.Succeeded++
		}
		result.Attempts += info.Attempts
		if info.Fallback {
			result.Fallbacks++
		}
	}

	sort.Slice(durations, func(a, b int) bool { return durations[a] < durations[b] })
	result.SuccessRatePercent = 100 * float64(result.Succeeded) / float64(result.Requests)
	result.AttemptsPerRequest = float64(result.Attempts) / float64(result.Requests)
	result.BodyIntegrityFailure = int(mismatches.Load())
	result.PrimaryHits = primaryHits.Load()
	result.FallbackHits = fallbackHits.Load()
	result.P50ms = percentile(durations, 0.50)
	result.P95ms = percentile(durations, 0.95)
	result.P99ms = percentile(durations, 0.99)
	return result
}

func TestOrderedRoutePlanEvaluation(t *testing.T) {
	arms := []armResult{
		runArm(t, "failing_primary_single_upstream", http.StatusServiceUnavailable, false),
		runArm(t, "failing_primary_ordered_plan", http.StatusServiceUnavailable, true),
		runArm(t, "all_healthy_single_upstream", http.StatusOK, false),
		runArm(t, "all_healthy_ordered_plan", http.StatusOK, true),
	}

	by := map[string]armResult{}
	for _, a := range arms {
		by[a.Arm] = a
		t.Logf("%-34s success %6.2f%%  attempts/req %.2f  fallbacks %3d  p50 %6.3fms  p95 %6.3fms  p99 %6.3fms  body-integrity failures %d",
			a.Arm, a.SuccessRatePercent, a.AttemptsPerRequest, a.Fallbacks, a.P50ms, a.P95ms, a.P99ms, a.BodyIntegrityFailure)
	}

	failSingle := by["failing_primary_single_upstream"]
	failPlan := by["failing_primary_ordered_plan"]
	healthySingle := by["all_healthy_single_upstream"]
	healthyPlan := by["all_healthy_ordered_plan"]

	// The properties, which are deterministic and are what this asserts on.
	// The numbers above are reported, not asserted: a latency threshold in a
	// unit test is a flake with a date on it.
	for _, a := range arms {
		if a.BodyIntegrityFailure != 0 {
			t.Errorf("%s: %d requests reached an upstream with the wrong body", a.Arm, a.BodyIntegrityFailure)
		}
	}
	if failSingle.Succeeded != 0 {
		t.Errorf("the single-upstream arm succeeded %d times against a failing primary", failSingle.Succeeded)
	}
	if failPlan.Succeeded != evalRequests {
		t.Errorf("the ordered-plan arm succeeded %d/%d against a failing primary", failPlan.Succeeded, evalRequests)
	}
	if failPlan.Fallbacks != evalRequests {
		t.Errorf("fallbacks used = %d, want one per request", failPlan.Fallbacks)
	}
	if healthyPlan.FallbackHits != 0 {
		t.Errorf("the fallback was contacted %d times with a healthy primary", healthyPlan.FallbackHits)
	}
	if healthyPlan.Attempts != healthySingle.Attempts {
		t.Errorf("a healthy request cost %d attempts with a plan and %d without",
			healthyPlan.Attempts, healthySingle.Attempts)
	}

	report := map[string]any{
		"generated_by":     "go test ./internal/proxy -run TestOrderedRoutePlanEvaluation",
		"requests_per_arm": evalRequests,
		"evidence_boundary": map[string]any{
			"runs_on": "one local host, in a single Go process",
			"traffic": "synthetic scripted requests through the real proxy against httptest upstreams",
			"not_claimed": []string{
				"no datacenter, no provider, no network partition, no real failover",
				"the outage is a handler that was told to return 503",
				"latency is loopback wall-clock and is measured, not deterministic",
				"says nothing about LLM traffic: that is POST, which never fails over",
				"no availability claim: the success rates are arithmetic about a scripted condition",
			},
		},
		"harness": map[string]any{
			"method":          "GET with a buffered body: the only shape that is both idempotent and replayable",
			"route_retry_max": 1,
			"attempt_ceiling": 2,
			"breaker":         "configured not to open inside a run, so the plan is what is measured",
			"body_integrity":  "every request carries a payload only it uses; each upstream verifies what it received",
		},
		"arms": arms,
		"differences": map[string]any{
			"success_rate_points_gained_during_primary_outage": failPlan.SuccessRatePercent - failSingle.SuccessRatePercent,
			"extra_attempts_per_request_during_outage":         failPlan.AttemptsPerRequest - failSingle.AttemptsPerRequest,
			"extra_attempts_per_request_when_all_healthy":      healthyPlan.AttemptsPerRequest - healthySingle.AttemptsPerRequest,
			"p50_overhead_ms_when_all_healthy":                 healthyPlan.P50ms - healthySingle.P50ms,
			"p95_overhead_ms_when_all_healthy":                 healthyPlan.P95ms - healthySingle.P95ms,
			"p99_overhead_ms_when_all_healthy":                 healthyPlan.P99ms - healthySingle.P99ms,
			"fallback_contacts_when_all_healthy":               healthyPlan.FallbackHits,
			"body_integrity_failures_total":                    failPlan.BodyIntegrityFailure + healthyPlan.BodyIntegrityFailure,
		},
	}

	out := filepath.Join("..", "..", "results", "route-plan-eval.json")
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("encoding the report: %v", err)
	}
	if err := os.WriteFile(out, append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("writing %s: %v", out, err)
	}
	t.Logf("wrote %s", out)
}

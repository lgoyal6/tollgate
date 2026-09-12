package store

import (
	"net/url"
	"testing"
	"time"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}

func routeWithFallback(t *testing.T, fallback string) *Route {
	t.Helper()
	r := &Route{
		ID: 1, TenantID: "acme", PathPrefix: "/api/",
		Upstream: mustURL(t, "http://primary.invalid"),
		Timeout:  2 * time.Second, RetryMax: 1,
		UpstreamAuthHeader: "x-api-key", UpstreamAuthEnv: "PRIMARY_KEY",
	}
	if fallback != "" {
		r.FallbackUpstream = mustURL(t, fallback)
		r.FallbackAuthHeader = "x-api-key"
		r.FallbackAuthEnv = "BACKUP_KEY"
	}
	return r
}

func TestARouteWithNoFallbackPlansOneCandidate(t *testing.T) {
	plan := PlanFor(routeWithFallback(t, ""))
	if len(plan.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(plan.Candidates))
	}
	if plan.HasFallback() {
		t.Error("HasFallback on a single-upstream route")
	}
}

func TestThePlanCarriesEachCandidatesOwnCredentialSource(t *testing.T) {
	// Not the primary's. A fallback is usually a different provider, and one
	// shared environment variable is how one provider's key reaches another.
	plan := PlanFor(routeWithFallback(t, "http://backup.invalid"))
	if got := plan.Primary().AuthEnv; got != "PRIMARY_KEY" {
		t.Errorf("primary credential source = %q", got)
	}
	if got := plan.Candidates[1].AuthEnv; got != "BACKUP_KEY" {
		t.Errorf("fallback credential source = %q, want its own", got)
	}
}

func TestCandidateRolesAreStable(t *testing.T) {
	plan := PlanFor(routeWithFallback(t, "http://backup.invalid"))
	if plan.Primary().Role() != "primary" {
		t.Errorf("primary role = %q", plan.Primary().Role())
	}
	if plan.Candidates[1].Role() != "fallback" {
		t.Errorf("fallback role = %q", plan.Candidates[1].Role())
	}
}

func TestThePlanIsTheSameEveryTimeForOneSnapshot(t *testing.T) {
	// The order has to be a property of the configuration, not of the moment a
	// request arrived, or two requests a second apart take different paths and
	// nobody can reproduce either.
	route := routeWithFallback(t, "http://backup.invalid")
	first, second := PlanFor(route), PlanFor(route)
	if first.Order() != second.Order() {
		t.Fatalf("order changed between plans: %q then %q", first.Order(), second.Order())
	}
}

func TestPlanRouteMatchesTheSameRouteAsMatchRoute(t *testing.T) {
	route := routeWithFallback(t, "http://backup.invalid")
	snap := SnapshotForTest(nil, []*Route{route}, nil)

	matched, ok := snap.MatchRoute("acme", "/api/widgets")
	if !ok {
		t.Fatal("MatchRoute found nothing")
	}
	plan, ok := snap.PlanRoute("acme", "/api/widgets")
	if !ok {
		t.Fatal("PlanRoute found nothing")
	}
	if plan.Route != matched {
		t.Error("PlanRoute and MatchRoute disagree about the route")
	}
}

func TestPlanRouteFindsNothingWhenTheRouteDoesNot(t *testing.T) {
	snap := SnapshotForTest(nil, []*Route{routeWithFallback(t, "")}, nil)
	if _, ok := snap.PlanRoute("acme", "/nowhere"); ok {
		t.Error("PlanRoute invented a route")
	}
}

// ------------------------------------------------------------- validation

func validRoute() RouteSpec {
	return RouteSpec{
		TenantID: "acme", PathPrefix: "/api/", Upstream: "http://primary.invalid",
		Timeout: time.Second, HedgeDelay: time.Second, RetryMax: 1,
	}
}

func TestAFallbackNeedsARetryToSpend(t *testing.T) {
	// The fallback is an attempt out of the route's existing ceiling. A route
	// with no retries has one attempt and the primary takes it, so this row
	// would describe a standby that can never be reached. Better an error now
	// than an outage the standby did not cover.
	spec := validRoute()
	spec.RetryMax = 0
	spec.FallbackUpstream = "http://backup.invalid"
	if err := spec.Validate(); err == nil {
		t.Fatal("a fallback was accepted on a route with no retries")
	}
}

func TestAFallbackMustDifferFromThePrimary(t *testing.T) {
	spec := validRoute()
	spec.FallbackUpstream = spec.Upstream
	if err := spec.Validate(); err == nil {
		t.Fatal("a fallback pointing at the primary was accepted")
	}
}

func TestFallbackCredentialsNeedAFallbackUpstream(t *testing.T) {
	spec := validRoute()
	spec.FallbackAuthHeader = "x-api-key"
	spec.FallbackAuthEnv = "BACKUP_KEY"
	if err := spec.Validate(); err == nil {
		t.Fatal("fallback credentials were accepted with no fallback upstream")
	}
}

func TestFallbackAuthHeaderAndEnvMustBeSetTogether(t *testing.T) {
	spec := validRoute()
	spec.FallbackUpstream = "http://backup.invalid"
	spec.FallbackAuthHeader = "x-api-key"
	if err := spec.Validate(); err == nil {
		t.Fatal("a fallback auth header was accepted with no env var to read")
	}
}

func TestOnlyAnEmptyFallbackSpecIsAClear(t *testing.T) {
	if !(FallbackSpec{}).Cleared() {
		t.Fatal("the zero fallback spec no longer clears a route")
	}
	for name, spec := range map[string]FallbackSpec{
		"upstream":    {Upstream: "http://backup.invalid"},
		"auth header": {AuthHeader: "x-api-key"},
		"auth env":    {AuthEnv: "BACKUP_KEY"},
		"auth prefix": {AuthPrefix: "Bearer "},
	} {
		t.Run(name, func(t *testing.T) {
			if spec.Cleared() {
				t.Fatal("a partially populated fallback spec was treated as a clear")
			}
		})
	}
}

func TestAForbiddenFallbackUpstreamIsRefused(t *testing.T) {
	// The same check the primary gets, for the same reason: a fallback is the
	// second place this gateway would attach the shared credential and connect.
	spec := validRoute()
	spec.FallbackUpstream = "http://169.254.169.254/latest/meta-data/"
	if err := spec.Validate(); err == nil {
		t.Fatal("a fallback pointed at the metadata service was accepted")
	}
}

func TestARouteWithNoFallbackStillValidates(t *testing.T) {
	spec := validRoute()
	spec.RetryMax = 0
	if err := spec.Validate(); err != nil {
		t.Fatalf("an ordinary single-upstream route was refused: %v", err)
	}
}

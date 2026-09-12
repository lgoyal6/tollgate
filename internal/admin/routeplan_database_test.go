package admin

import (
	"context"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/store"
)

func createRoutePlanTenant(t *testing.T, st *store.Store, tenant string) {
	t.Helper()
	ctx := context.Background()
	_, _ = st.Pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenant)
	t.Cleanup(func() {
		_, _ = st.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenant)
	})
	if err := st.CreateTenant(ctx, store.TenantSpec{
		ID: tenant, Name: "Route Plan Database Test", Enabled: true,
		Algorithm: store.AlgoTokenBucket, Rate: 1, Burst: 1,
		Window: time.Second, Limit: 1,
	}); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
}

func routePlanSpec(tenant, path string, retries int) store.RouteSpec {
	return store.RouteSpec{
		TenantID: tenant, PathPrefix: path, Upstream: "http://primary.invalid",
		Timeout: time.Second, RetryMax: retries, HedgeDelay: time.Second,
		UpstreamAuthHeader: "x-primary-key", UpstreamAuthEnv: "PRIMARY_KEY",
	}
}

func routeIDForPath(t *testing.T, st *store.Store, tenant, path string) int64 {
	t.Helper()
	routes, err := st.ListRoutes(context.Background(), tenant)
	if err != nil {
		t.Fatalf("listing routes: %v", err)
	}
	for _, route := range routes {
		if route.PathPrefix == path {
			return route.ID
		}
	}
	t.Fatalf("route %q was not returned from Postgres", path)
	return 0
}

func assertPlan(t *testing.T, st *store.Store, tenant, path string, wantCandidates int, wantFallbackEnv string) {
	t.Helper()
	snap, err := st.LoadSnapshot(context.Background())
	if err != nil {
		t.Fatalf("loading snapshot: %v", err)
	}
	plan, ok := snap.PlanRoute(tenant, path+"request")
	if !ok {
		t.Fatalf("snapshot did not plan route %q", path)
	}
	if len(plan.Candidates) != wantCandidates {
		t.Fatalf("candidate count = %d, want %d", len(plan.Candidates), wantCandidates)
	}
	if got := plan.Primary().AuthEnv; got != "PRIMARY_KEY" {
		t.Fatalf("primary credential source = %q, want PRIMARY_KEY", got)
	}
	if wantCandidates == 2 {
		if got := plan.Candidates[1].AuthEnv; got != wantFallbackEnv {
			t.Fatalf("fallback credential source = %q, want %q", got, wantFallbackEnv)
		}
	}
}

func TestRoutePlanRoundTripsThroughPostgres(t *testing.T) {
	st := testStore(t)
	const tenant = "routeplan-roundtrip"
	const path = "/routeplan-roundtrip/"
	createRoutePlanTenant(t, st, tenant)

	spec := routePlanSpec(tenant, path, 1)
	spec.FallbackUpstream = "http://fallback.invalid"
	spec.FallbackAuthHeader = "x-fallback-key"
	spec.FallbackAuthEnv = "FALLBACK_KEY"
	if err := st.AddRoute(context.Background(), spec); err != nil {
		t.Fatalf("adding route with fallback: %v", err)
	}
	assertPlan(t, st, tenant, path, 2, "FALLBACK_KEY")

	routeID := routeIDForPath(t, st, tenant, path)
	if err := st.SetRouteFallback(context.Background(), routeID, store.FallbackSpec{
		Upstream: "http://replacement.invalid", AuthHeader: "authorization",
		AuthEnv: "REPLACEMENT_KEY", AuthPrefix: "Bearer ",
	}); err != nil {
		t.Fatalf("replacing fallback: %v", err)
	}
	assertPlan(t, st, tenant, path, 2, "REPLACEMENT_KEY")

	if err := st.SetRouteFallback(context.Background(), routeID, store.FallbackSpec{}); err != nil {
		t.Fatalf("clearing fallback: %v", err)
	}
	assertPlan(t, st, tenant, path, 1, "")
}

func TestPostgresStoreRefusesInvalidFallbackConfigurations(t *testing.T) {
	st := testStore(t)
	const tenant = "routeplan-refusals"
	createRoutePlanTenant(t, st, tenant)

	cases := []struct {
		name     string
		path     string
		retries  int
		fallback store.FallbackSpec
	}{
		{
			name: "fallback has no attempt to spend", path: "/no-retry/", retries: 0,
			fallback: store.FallbackSpec{Upstream: "http://fallback.invalid"},
		},
		{
			name: "fallback equals primary", path: "/same-upstream/", retries: 1,
			fallback: store.FallbackSpec{Upstream: "http://primary.invalid"},
		},
		{
			name: "credentials have no fallback upstream", path: "/credentials-only/", retries: 1,
			fallback: store.FallbackSpec{AuthHeader: "x-api-key", AuthEnv: "FALLBACK_KEY"},
		},
		{
			name: "fallback auth header has no env", path: "/missing-env/", retries: 1,
			fallback: store.FallbackSpec{Upstream: "http://fallback.invalid", AuthHeader: "x-api-key"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := routePlanSpec(tenant, tc.path, tc.retries)
			if err := st.AddRoute(context.Background(), spec); err != nil {
				t.Fatalf("adding baseline route: %v", err)
			}
			routeID := routeIDForPath(t, st, tenant, tc.path)
			if err := st.SetRouteFallback(context.Background(), routeID, tc.fallback); err == nil {
				t.Fatal("invalid fallback configuration reached Postgres without being refused")
			}

			var upstream, header, env, prefix string
			if err := st.Pool.QueryRow(context.Background(), `
				SELECT fallback_upstream_url, fallback_auth_header, fallback_auth_env,
				       fallback_auth_prefix
				FROM routes WHERE id = $1`, routeID,
			).Scan(&upstream, &header, &env, &prefix); err != nil {
				t.Fatalf("reading route after refusal: %v", err)
			}
			if upstream != "" || header != "" || env != "" || prefix != "" {
				t.Fatalf("refused fallback mutated the row: upstream=%q header=%q env=%q prefix=%q", upstream, header, env, prefix)
			}
			assertPlan(t, st, tenant, tc.path, 1, "")
		})
	}
}

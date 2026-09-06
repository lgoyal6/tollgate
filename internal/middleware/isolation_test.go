package middleware

// Object ownership on the data plane. A route belongs to exactly one tenant,
// and the tenant comes from the credential, so the only thing standing
// between one teammate's key and another team's upstream is that the router
// looks routes up per tenant. That is worth an explicit test: the failure
// mode is not an error, it is a request quietly succeeding against somebody
// else's upstream credential.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/store"
)

// twoTenants builds a snapshot where each tenant owns a private prefix and
// both own the same shared prefix pointed at different upstreams.
func twoTenants(t *testing.T) (snap *store.Snapshot, keyA, keyB string) {
	t.Helper()
	genA, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	genB, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	tenant := func(id string) *store.Tenant {
		return &store.Tenant{
			ID: id, Name: id, Enabled: true,
			RLAlgorithm: store.AlgoTokenBucket, RLRate: 1000, RLBurst: 1000,
		}
	}
	route := func(id int64, tenantID, prefix, upstream string) *store.Route {
		return &store.Route{
			ID: id, TenantID: tenantID, PathPrefix: prefix,
			Timeout: time.Second, Upstream: mustURL(t, upstream),
		}
	}
	snap = store.SnapshotForTest(
		[]*store.Tenant{tenant("alpha"), tenant("beta")},
		[]*store.Route{
			route(1, "alpha", "/alpha-only/", "http://alpha-upstream:9000"),
			route(2, "beta", "/beta-only/", "http://beta-upstream:9000"),
			route(3, "alpha", "/shared/", "http://alpha-upstream:9000"),
			route(4, "beta", "/shared/", "http://beta-upstream:9000"),
		},
		[]*store.APIKey{
			{ID: genA.ID, TenantID: "alpha", SecretHash: genA.SecretHash, Status: store.KeyActive},
			{ID: genB.ID, TenantID: "beta", SecretHash: genB.SecretHash, Status: store.KeyActive},
		},
	)
	return snap, genA.Plaintext, genB.Plaintext
}

// TestOneTenantsKeyCannotReachAnothersRoute is the isolation property.
func TestOneTenantsKeyCannotReachAnothersRoute(t *testing.T) {
	snap, keyA, keyB := twoTenants(t)
	snapshots := func() *store.Snapshot { return snap }
	m := observability.NewMetrics()

	// The terminal handler reports which upstream the router chose, which is
	// the fact a crossed route would show up in.
	var reached string
	sink := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = reqctx.InfoFrom(r.Context()).Upstream
		w.WriteHeader(http.StatusOK)
	})
	h := Chain(sink,
		Recover(testLogger),
		RequestID(),
		Metrics(m),
		Auth(snapshots, m, nil),
		Router(snapshots),
	)

	call := func(key, path string) (int, string) {
		reached = ""
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, reached
	}

	if code, up := call(keyA, "/alpha-only/thing"); code != http.StatusOK || up != "alpha-upstream:9000" {
		t.Fatalf("alpha on its own route: status %d upstream %q, want 200 alpha-upstream:9000", code, up)
	}
	if code, up := call(keyA, "/beta-only/thing"); code != http.StatusNotFound {
		t.Errorf("alpha's key reached beta's private route: status %d upstream %q, want 404", code, up)
	}
	if code, up := call(keyB, "/alpha-only/thing"); code != http.StatusNotFound {
		t.Errorf("beta's key reached alpha's private route: status %d upstream %q, want 404", code, up)
	}

	// The shared prefix is the interesting one: the same path resolves to a
	// different upstream per tenant, so the credential decides, not the URL.
	if code, up := call(keyA, "/shared/thing"); code != http.StatusOK || up != "alpha-upstream:9000" {
		t.Errorf("alpha on the shared prefix: status %d upstream %q, want alpha-upstream:9000", code, up)
	}
	if code, up := call(keyB, "/shared/thing"); code != http.StatusOK || up != "beta-upstream:9000" {
		t.Errorf("beta on the shared prefix: status %d upstream %q, want beta-upstream:9000", code, up)
	}

	// A path parameter cannot be used to escape the prefix either.
	for _, path := range []string{
		"/alpha-only/../beta-only/thing",
		"/alpha-only/%2e%2e/beta-only/thing",
	} {
		if code, up := call(keyB, path); code == http.StatusOK && up == "alpha-upstream:9000" {
			t.Errorf("beta's key reached alpha's upstream via %q", path)
		}
	}
}

// TestDisabledTenantLosesEveryKeyAtOnce is the kill switch. Disabling a tenant
// has to refuse its credentials without anyone revoking them one by one,
// because that is the only lever an operator has when a client runs away with
// the shared provider key.
func TestDisabledTenantLosesEveryKeyAtOnce(t *testing.T) {
	snap, keyA, _ := twoTenants(t)
	if _, err := auth.Verify(snap, keyA, time.Now()); err != nil {
		t.Fatalf("alpha's key does not authenticate to begin with: %v", err)
	}

	alpha, ok := snap.Tenant("alpha")
	if !ok {
		t.Fatal("alpha missing from the snapshot")
	}
	alpha.Enabled = false

	if _, err := auth.Verify(snap, keyA, time.Now()); err != auth.ErrTenantDisabled {
		t.Errorf("disabled tenant's key rejected as %v, want ErrTenantDisabled", err)
	}
}

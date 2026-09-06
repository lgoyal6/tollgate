package proxy

// The lifecycle of the credential the gateway holds on everyone's behalf.
//
// secret_test.go proves the shared provider key does not escape. This file
// covers the two moments the key changes underneath a running process: it is
// rotated, and it is revoked. Both have to work without a restart, because a
// gateway that has to be restarted to pick up a rotated key is a gateway
// nobody rotates, and both have to be visible, because the failure mode of a
// revoked shared key is a stream of 401s that look exactly like tenants
// sending bad requests.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lgoyal6/tollgate/internal/store"
)

// injecting makes a route carry the gateway's own credential upstream, the
// way a deployment wires up a shared provider key.
func withInjectedCredential(env string) func(*store.Route) {
	return func(r *store.Route) {
		r.UpstreamAuthHeader = "X-Api-Key"
		r.UpstreamAuthEnv = env
		r.RetryMax = 0
	}
}

// counterValues flattens one metric family into label-set -> value, so a test
// can assert on what an operator would actually see on a dashboard.
func counterValues(t *testing.T, p *Proxy, name string) map[string]float64 {
	t.Helper()
	families, err := p.metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	out := map[string]float64{}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			var labels []string
			for _, l := range m.GetLabel() {
				labels = append(labels, l.GetName()+"="+l.GetValue())
			}
			out[strings.Join(labels, ",")] = m.GetCounter().GetValue()
		}
	}
	return out
}

// TestARotatedProviderCredentialBindsWithoutARestart is the property that
// makes rotation possible at all: the credential is read at the moment the
// outbound request is built, not captured when the route was loaded. Cache it
// anywhere and rotating the provider key means restarting every replica.
func TestARotatedProviderCredentialBindsWithoutARestart(t *testing.T) {
	const envName = "TOLLGATE_TEST_ROTATING_CREDENTIAL"
	const before = "provider-key-generation-one"
	const after = "provider-key-generation-two"

	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-Api-Key"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	t.Setenv(envName, before)
	p, _, _ := recording(t, Options{})
	route := routeTo(t, upstream.URL, withInjectedCredential(envName))

	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/messages", nil)
		resp, _ := send(p, route, req)
		return resp.Code
	}
	if code := call(); code != http.StatusOK {
		t.Fatalf("first request: %d", code)
	}

	// The rotation. Same process, same *Proxy, same route, same connection
	// pool: nothing is rebuilt.
	t.Setenv(envName, after)
	if code := call(); code != http.StatusOK {
		t.Fatalf("request after rotation: %d", code)
	}

	if len(seen) != 2 {
		t.Fatalf("upstream saw %d requests, want 2", len(seen))
	}
	if seen[0] != before {
		t.Errorf("first request carried %q, want the pre-rotation credential", seen[0])
	}
	if seen[1] != after {
		t.Errorf("the request after rotation still carried %q; the credential is captured "+
			"somewhere instead of read per request, so rotating it needs a restart", seen[1])
	}
}

// TestARevokedProviderCredentialIsLoud is the defect this file was written
// for. When the provider revokes the shared key, every affected request comes
// back 401 or 403, and the gateway relays that verbatim. On its own signals
// that is indistinguishable from tenants sending bad requests, so nobody finds
// out until somebody reads a support ticket.
func TestARevokedProviderCredentialIsLoud(t *testing.T) {
	const envName = "TOLLGATE_TEST_REVOKED_CREDENTIAL"
	t.Setenv(envName, "provider-key-that-was-revoked")

	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(rejecting.Close)

	p, logs, _ := recording(t, Options{})
	route := routeTo(t, rejecting.URL, withInjectedCredential(envName))
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/messages", nil)
	resp, _ := send(p, route, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want the upstream's own 401 relayed", resp.Code)
	}

	// A counter an operator can alert on, separate from the tenant's own 4xx.
	got := counterValues(t, p, "tollgate_upstream_credential_failures_total")
	if len(got) == 0 {
		t.Fatal("the upstream refused a request carrying the gateway's own credential and " +
			"nothing counted it; a revoked shared key is a silent no-op")
	}
	var total float64
	for labels, v := range got {
		if !strings.Contains(labels, "reason=rejected") {
			t.Errorf("unexpected label set %q", labels)
		}
		total += v
	}
	if total != 1 {
		t.Errorf("counter = %v, want 1", total)
	}

	if !strings.Contains(logs.String(), "credential") {
		t.Errorf("nothing in the log says the gateway's own credential was refused:\n%s", logs)
	}
	// And the log must say it without saying what the credential is.
	if strings.Contains(logs.String(), "provider-key-that-was-revoked") {
		t.Errorf("the log line carries the credential itself:\n%s", logs)
	}
}

// TestATenantsOwn4xxIsNotCountedAsACredentialFailure is the other half: the
// counter is only useful if it does not fire for every 400 a caller earns.
func TestATenantsOwn4xxIsNotCountedAsACredentialFailure(t *testing.T) {
	const envName = "TOLLGATE_TEST_WORKING_CREDENTIAL"
	t.Setenv(envName, "provider-key-that-works")

	fussy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(fussy.Close)

	p, _, _ := recording(t, Options{})
	route := routeTo(t, fussy.URL, withInjectedCredential(envName))
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/messages", nil)
	if resp, _ := send(p, route, req); resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.Code)
	}
	if got := counterValues(t, p, "tollgate_upstream_credential_failures_total"); len(got) != 0 {
		t.Errorf("a caller's own 400 was counted as a credential failure: %v", got)
	}
}

// TestARouteWithNoCredentialInjectionIsNotCounted keeps the counter meaning
// what its name says. A 401 from an upstream this gateway does not
// authenticate to says nothing about the gateway's credentials.
func TestARouteWithNoCredentialInjectionIsNotCounted(t *testing.T) {
	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(rejecting.Close)

	p, _, _ := recording(t, Options{})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/messages", nil)
	if resp, _ := send(p, routeTo(t, rejecting.URL, nil), req); resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
	if got := counterValues(t, p, "tollgate_upstream_credential_failures_total"); len(got) != 0 {
		t.Errorf("a route that injects nothing was counted as a credential failure: %v", got)
	}
}

// TestAMissingProviderCredentialIsCountedToo closes the third case: the
// credential was never there. That already fails the request loudly, but it
// belonged in the same counter as the revoked one, because to an operator they
// are the same question - "can this gateway still authenticate upstream?"
func TestAMissingProviderCredentialIsCountedToo(t *testing.T) {
	const envName = "TOLLGATE_TEST_ABSENT_CREDENTIAL"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the upstream must not be reached with no credential to send")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	p, _, _ := recording(t, Options{})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/messages", nil)
	resp, _ := send(p, routeTo(t, upstream.URL, withInjectedCredential(envName)), req)
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.Code)
	}
	got := counterValues(t, p, "tollgate_upstream_credential_failures_total")
	if len(got) == 0 {
		t.Fatal("a route configured with a credential that is not set was not counted")
	}
	for labels := range got {
		if !strings.Contains(labels, "reason=missing") {
			t.Errorf("label set %q, want reason=missing", labels)
		}
	}
	// The client is told nothing about which variable, and nothing about why.
	if strings.Contains(resp.Body.String(), envName) {
		t.Errorf("the client response names the credential variable: %s", resp.Body)
	}
}

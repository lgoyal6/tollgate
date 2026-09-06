package admin

// Object ownership on the management surface.
//
// This API has one principal - whoever holds ADMIN_TOKEN - so "another
// tenant's identifier" cannot mean a privilege boundary here the way it does
// on the data plane, where the tenant comes from the credential and
// internal/middleware/crosstenant_test.go checks it. What it means here is the
// other half of the same property: an identifier that really exists must not
// address an object it does not name. A key id is not a tenant id, a tenant id
// is not a key id, and a route id is neither.
//
// Two things are asserted at every entry point that takes an identifier:
//
//   - nothing moves. The whole of tenants, routes and keys is captured before
//     and after each probe and compared; a write that lands anywhere fails the
//     test, including on the object the identifier really does name.
//   - the refusal for a real identifier of the wrong kind is byte-identical to
//     the refusal for one that was invented. Otherwise the management API
//     answers "which ids exist?" for anybody who gets one request through.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const ownPrefix = "own-"

type world struct {
	h       http.Handler
	tenantA string
	tenantB string
	keyA    string
	keyB    string
	routeA  string
	routeB  string
}

// twoTenantsWithObjects seeds two tenants, each with a key and a route, so
// every probe below has a real identifier of every kind to reach for.
func twoTenantsWithObjects(t *testing.T) world {
	t.Helper()
	st := testStore(t)
	sweep := func() {
		_, _ = st.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id LIKE $1`, ownPrefix+"%")
	}
	sweep()
	t.Cleanup(sweep)

	h := serve(t, st)
	w := world{h: h, tenantA: ownPrefix + "alpha", tenantB: ownPrefix + "beta"}
	for _, tenant := range []string{w.tenantA, w.tenantB} {
		if code, body := do(t, h, "POST", "/api/tenants",
			`{"id":"`+tenant+`","name":"`+tenant+`"}`); code != http.StatusCreated {
			t.Fatalf("seeding %s: %d %v", tenant, code, body)
		}
		code, body := do(t, h, "POST", "/api/tenants/"+tenant+"/keys", `{"scopes":["read"]}`)
		if code != http.StatusCreated {
			t.Fatalf("seeding key for %s: %d %v", tenant, code, body)
		}
		if code, body := do(t, h, "POST", "/api/tenants/"+tenant+"/routes",
			`{"path_prefix":"/`+tenant+`/","upstream":"http://upstream:9000"}`); code != http.StatusCreated {
			t.Fatalf("seeding route for %s: %d %v", tenant, code, body)
		}
		id, _ := body["key_id"].(string)
		if tenant == w.tenantA {
			w.keyA = id
		} else {
			w.keyB = id
		}
	}

	_, overview := do(t, h, "GET", "/api/overview", "")
	for _, raw := range overview["routes"].([]any) {
		r, _ := raw.(map[string]any)
		id := strconv.FormatInt(int64(r["id"].(float64)), 10)
		switch r["tenant_id"] {
		case w.tenantA:
			w.routeA = id
		case w.tenantB:
			w.routeB = id
		}
	}
	if w.keyA == "" || w.keyB == "" || w.routeA == "" || w.routeB == "" {
		t.Fatalf("seeding did not produce every object: %+v", w)
	}
	return w
}

// state is everything the management API can show, as bytes. Usage counters
// are dropped: they are per-replica traffic, not stored objects.
func (w world) state(t *testing.T) []byte {
	t.Helper()
	req := httptest.NewRequest("GET", MountPath+"/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview: %d %s", rec.Code, rec.Body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("overview is not JSON: %v", err)
	}
	delete(decoded, "usage")
	out, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encoding overview: %v", err)
	}
	return out
}

// raw drives one request and returns the exact bytes and status.
func (w world) raw(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	var req *http.Request
	if r == nil {
		req = httptest.NewRequest(method, MountPath+path, nil)
	} else {
		req = httptest.NewRequest(method, MountPath+path, r)
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// TestAnIdentifierOfTheWrongKindReachesNothing walks every entry point that
// takes an identifier and presents one belonging to a different kind of
// object.
func TestAnIdentifierOfTheWrongKindReachesNothing(t *testing.T) {
	w := twoTenantsWithObjects(t)

	// The invented identifiers are shaped like the real ones they stand in
	// for, so the comparison is about existence and not about format.
	const inventedText = ownPrefix + "does-not-exist"
	const inventedNumber = "2147483646"

	cases := []struct {
		name     string
		method   string
		real     string // a path built from an identifier that exists
		invented string // the same path built from one that does not
		body     string
	}{
		{
			name:     "update a tenant, addressed by a key id",
			method:   "PUT",
			real:     "/api/tenants/" + w.keyB,
			invented: "/api/tenants/" + inventedText,
			body:     `{"name":"moved"}`,
		},
		{
			name:     "issue a key, addressed by another key's id",
			method:   "POST",
			real:     "/api/tenants/" + w.keyB + "/keys",
			invented: "/api/tenants/" + inventedText + "/keys",
			body:     `{"scopes":["read"]}`,
		},
		{
			name:     "issue a key, addressed by a route id",
			method:   "POST",
			real:     "/api/tenants/" + w.routeB + "/keys",
			invented: "/api/tenants/" + inventedNumber + "/keys",
			body:     `{}`,
		},
		{
			name:     "add a route, addressed by a key id",
			method:   "POST",
			real:     "/api/tenants/" + w.keyB + "/routes",
			invented: "/api/tenants/" + inventedText + "/routes",
			body:     `{"path_prefix":"/x/","upstream":"http://elsewhere:9000"}`,
		},
		{
			name:     "rotate a key, addressed by a tenant id",
			method:   "POST",
			real:     "/api/keys/" + w.tenantB + "/rotate",
			invented: "/api/keys/" + inventedText + "/rotate",
			body:     `{"grace_seconds":60}`,
		},
		{
			name:     "revoke a key, addressed by a tenant id",
			method:   "DELETE",
			real:     "/api/keys/" + w.tenantB,
			invented: "/api/keys/" + inventedText,
			body:     ``,
		},
		{
			name:     "delete a route, addressed by a key id",
			method:   "DELETE",
			real:     "/api/routes/" + w.keyB,
			invented: "/api/routes/" + inventedText,
			body:     ``,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := w.state(t)

			realCode, realBody := w.raw(t, tc.method, tc.real, tc.body)
			if realCode < 400 {
				t.Fatalf("an identifier of the wrong kind was accepted: %d %s", realCode, realBody)
			}
			if after := w.state(t); !bytes.Equal(before, after) {
				t.Errorf("the request changed stored state despite being refused %d\nbefore: %s\nafter:  %s",
					realCode, before, after)
			}

			inventedCode, inventedBody := w.raw(t, tc.method, tc.invented, tc.body)
			if inventedCode != realCode || !bytes.Equal(realBody, inventedBody) {
				t.Errorf("an identifier that exists is distinguishable from one that does not:\n"+
					" real (%s):     %d %s\n invented (%s): %d %s",
					tc.real, realCode, strings.TrimSpace(string(realBody)),
					tc.invented, inventedCode, strings.TrimSpace(string(inventedBody)))
			}
			if after := w.state(t); !bytes.Equal(before, after) {
				t.Errorf("the invented-identifier request changed stored state\nbefore: %s\nafter:  %s", before, after)
			}
		})
	}
}

// TestTheBodyCannotRetargetAPathParameter is the write-side of ownership: the
// tenant an object is created under comes from the URL, and a body that names
// a different one must not be able to move it.
func TestTheBodyCannotRetargetAPathParameter(t *testing.T) {
	w := twoTenantsWithObjects(t)

	// The decoder rejects unknown fields, so a body trying to name a tenant is
	// refused outright rather than silently ignored. Both matter: silently
	// ignored is how a caller comes to believe it worked.
	for _, body := range []string{
		`{"scopes":["read"],"tenant":"` + w.tenantB + `"}`,
		`{"scopes":["read"],"tenant_id":"` + w.tenantB + `"}`,
	} {
		code, out := w.raw(t, "POST", "/api/tenants/"+w.tenantA+"/keys", body)
		if code != http.StatusBadRequest {
			t.Errorf("a body naming another tenant: %d %s, want 400", code, out)
		}
	}

	// And the legitimate call binds the key to the tenant in the URL.
	code, out := w.raw(t, "POST", "/api/tenants/"+w.tenantA+"/keys", `{"scopes":["read"]}`)
	if code != http.StatusCreated {
		t.Fatalf("issuing a key: %d %s", code, out)
	}
	var issued map[string]any
	if err := json.Unmarshal(out, &issued); err != nil {
		t.Fatalf("issued key is not JSON: %v", err)
	}
	if issued["tenant"] != w.tenantA {
		t.Errorf("key issued under %v, want %s", issued["tenant"], w.tenantA)
	}

	// A route created under one tenant must not appear under the other.
	if code, out := w.raw(t, "POST", "/api/tenants/"+w.tenantA+"/routes",
		`{"path_prefix":"/shared/","upstream":"http://a:9000"}`); code != http.StatusCreated {
		t.Fatalf("adding a route: %d %s", code, out)
	}
	_, overview := do(t, w.h, "GET", "/api/overview", "")
	for _, entry := range overview["routes"].([]any) {
		r, _ := entry.(map[string]any)
		if r["path_prefix"] == "/shared/" && r["tenant_id"] != w.tenantA {
			t.Errorf("the route landed under %v, want %s", r["tenant_id"], w.tenantA)
		}
	}
}

// TestDeletingATenantTakesItsOwnObjectsAndNobodyElses pins the blast radius of
// the one operation that reaches other tables.
func TestDeletingATenantTakesItsOwnObjectsAndNobodyElses(t *testing.T) {
	w := twoTenantsWithObjects(t)
	st := testStore(t)

	if _, err := st.Pool.Exec(context.Background(),
		`DELETE FROM tenants WHERE id = $1`, w.tenantA); err != nil {
		t.Fatalf("deleting %s: %v", w.tenantA, err)
	}

	_, overview := do(t, w.h, "GET", "/api/overview", "")
	var survivingRoutes, survivingKeys int
	for _, entry := range overview["routes"].([]any) {
		r, _ := entry.(map[string]any)
		switch r["tenant_id"] {
		case w.tenantA:
			t.Errorf("route %v outlived its tenant", r["id"])
		case w.tenantB:
			survivingRoutes++
		}
	}
	for _, entry := range overview["keys"].([]any) {
		k, _ := entry.(map[string]any)
		switch k["tenant_id"] {
		case w.tenantA:
			t.Errorf("key %v outlived its tenant", k["id"])
		case w.tenantB:
			survivingKeys++
		}
	}
	if survivingRoutes != 1 || survivingKeys != 1 {
		t.Errorf("the other tenant kept %d routes and %d keys, want 1 and 1",
			survivingRoutes, survivingKeys)
	}
}

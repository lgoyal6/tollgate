package admin

import (
	"net/http"
	"testing"
)

// These cases are the minimal reproductions Schemathesis shrank from its
// generated corpus. They keep the fixes in the ordinary Go suite, while the
// full generator remains available through scripts/schemathesis.sh.

func TestInvalidOptionalBodiesAndScopeItemsAreRejected(t *testing.T) {
	h, tenant, keyID := seedContract(t, "schema-null")
	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPut, "/api/tenants/" + tenant, `null`},
		{http.MethodPost, "/api/tenants/" + tenant + "/keys", `null`},
		{http.MethodPost, "/api/tenants/" + tenant + "/keys", "\t"},
		{http.MethodPost, "/api/tenants/" + tenant + "/keys", `{"scopes":[null]}`},
		{http.MethodPost, "/api/keys/" + keyID + "/rotate", `null`},
	}
	for _, tc := range cases {
		if code, body := do(t, h, tc.method, tc.path, tc.body); code != http.StatusBadRequest {
			t.Errorf("%s %s: %d %v, want 400", tc.method, tc.path, code, body)
		}
	}
}

func TestConflictsAndMissingReferencesHaveDistinctStatuses(t *testing.T) {
	h, tenant, _ := seedContract(t, "schema-status")
	if code, body := do(t, h, http.MethodPost, "/api/tenants",
		`{"id":"`+tenant+`"}`); code != http.StatusConflict {
		t.Fatalf("duplicate tenant: %d %v, want 409", code, body)
	}
	if code, body := do(t, h, http.MethodPost, "/api/tenants/missing/keys", `{}`); code != http.StatusNotFound {
		t.Errorf("key for missing tenant: %d %v, want 404", code, body)
	}
	if code, body := do(t, h, http.MethodPost, "/api/tenants/missing/routes",
		`{"path_prefix":"/x/","upstream":"http://upstream"}`); code != http.StatusNotFound {
		t.Errorf("route for missing tenant: %d %v, want 404", code, body)
	}
	if code, body := do(t, h, http.MethodPost, "/api/keys/missing/rotate", `{}`); code != http.StatusNotFound {
		t.Errorf("rotate missing key: %d %v, want 404", code, body)
	}

	route := `{"path_prefix":"/same/","upstream":"http://upstream"}`
	if code, body := do(t, h, http.MethodPost, "/api/tenants/"+tenant+"/routes", route); code != http.StatusCreated {
		t.Fatalf("first route: %d %v, want 201", code, body)
	}
	if code, body := do(t, h, http.MethodPost, "/api/tenants/"+tenant+"/routes", route); code != http.StatusConflict {
		t.Errorf("duplicate route: %d %v, want 409", code, body)
	}
}

func TestPersistedNULAndOverflowingDurationAreRejectedAtTheBoundary(t *testing.T) {
	h, tenant, keyID := seedContract(t, "schema-bounds")
	cases := []struct {
		path string
		body string
	}{
		{"/api/tenants", `{"id":"contract-nul","name":"bad\u0000name"}`},
		{"/api/tenants/" + tenant + "/routes", `{"path_prefix":"/x/","upstream":"http://upstream","auth_header":"X-Key\u0000","auth_env":"KEY"}`},
		{"/api/keys/" + keyID + "/rotate", `{"grace_seconds":9223372037}`},
	}
	for _, tc := range cases {
		if code, body := do(t, h, http.MethodPost, tc.path, tc.body); code != http.StatusBadRequest {
			t.Errorf("POST %s: %d %v, want 400", tc.path, code, body)
		}
	}
}

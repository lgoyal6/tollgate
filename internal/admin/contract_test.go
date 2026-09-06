package admin

// The management API's contract, checked against the handlers that actually
// answer rather than against a description of them. openapi.json is the
// contract; this file drives every operation in it with generated boundary
// inputs and asserts that the status code and the body shape that come back
// are ones the document declares.
//
// Everything destructive here is scoped to tenant ids prefixed "contract-"
// against the throwaway database named by TOLLGATE_TEST_POSTGRES, and is
// deleted again on cleanup.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// spec is the slice of OpenAPI this test needs. Decoding into a narrow struct
// rather than pulling in a validator library keeps the contract check itself
// dependency-free, and the parts left out (schemas, examples) are not what
// drifts.
type spec struct {
	OpenAPI string `json:"openapi"`
	Paths   map[string]map[string]struct {
		OperationID string `json:"operationId"`
		Summary     string `json:"summary"`
		// A pointer so "no security key" (inherit the document's requirement)
		// is distinguishable from "security: []" (deliberately public).
		Security  *[]map[string][]string     `json:"security"`
		Responses map[string]json.RawMessage `json:"responses"`
	} `json:"paths"`
}

// specPath maps a router pattern to the path the document names it by. The
// only difference is the console's {$} anchor, which is net/http syntax for
// "this path exactly" and not part of the URL.
func specPath(pattern string) string {
	return strings.TrimSuffix(pattern, "{$}")
}

// publicOperations are the ones the document deliberately exempts from the
// admin token, by declaring an empty security list.
func publicOperations(t *testing.T, s spec) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for path, methods := range s.Paths {
		for method, op := range methods {
			if op.Security != nil && len(*op.Security) == 0 {
				out[strings.ToUpper(method)+" "+path] = true
			}
		}
	}
	return out
}

func loadSpec(t *testing.T) spec {
	t.Helper()
	raw, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatalf("reading openapi.json: %v", err)
	}
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	if !strings.HasPrefix(s.OpenAPI, "3.") {
		t.Fatalf("openapi field = %q, want a 3.x document", s.OpenAPI)
	}
	return s
}

// specOperations flattens the document into the same METHOD /path form the
// handler table uses.
func specOperations(t *testing.T, s spec) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for path, methods := range s.Paths {
		for method, op := range methods {
			key := strings.ToUpper(method) + " " + path
			if len(op.Responses) == 0 {
				t.Errorf("%s declares no responses", key)
			}
			if op.OperationID == "" {
				t.Errorf("%s has no operationId", key)
			}
			codes := map[string]bool{}
			for code := range op.Responses {
				codes[code] = true
			}
			public := op.Security != nil && len(*op.Security) == 0
			if !public && !codes["401"] {
				t.Errorf("%s does not declare 401; every management endpoint is behind the admin token", key)
			}
			out[key] = codes
		}
	}
	return out
}

// TestDeclaredOperationsAllRequireTheToken re-derives the auth expectation
// from the document instead of from a hand-written list, so a new endpoint
// cannot be added to the spec and quietly left unauthenticated.
func TestDeclaredOperationsAllRequireTheToken(t *testing.T) {
	// A nil store: any handler reached without the token would panic, so an
	// auth hole fails loudly here rather than silently passing.
	h := serve(t, nil)
	doc := loadSpec(t)
	public := publicOperations(t, doc)
	for key := range specOperations(t, doc) {
		if public[key] {
			continue
		}
		method, path, _ := strings.Cut(key, " ")
		concrete := strings.NewReplacer("{id}", "contract-probe").Replace(path)
		req := httptest.NewRequest(method, MountPath+concrete, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: status = %d, want 401", key, rec.Code)
		}
	}
}

// seedContract seeds one tenant and one key, both scoped to a prefix this
// test owns and both deleted again on cleanup.
func seedContract(t *testing.T, name string) (h http.Handler, tenant, keyID string) {
	t.Helper()
	st := testStore(t)
	ctx := context.Background()
	tenant = "contract-" + name
	// The whole "contract-" prefix belongs to this file, and boundary inputs
	// deliberately create tenants under it, so the sweep is by prefix rather
	// than by the one id seeded here. Nothing outside the prefix is touched.
	_, _ = st.Pool.Exec(ctx, `DELETE FROM tenants WHERE id LIKE 'contract-%'`)
	t.Cleanup(func() {
		_, _ = st.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id LIKE 'contract-%'`)
	})

	h = serve(t, st)
	if code, body := do(t, h, "POST", "/api/tenants",
		`{"id":"`+tenant+`","name":"Contract"}`); code != http.StatusCreated {
		t.Fatalf("seeding tenant: %d %v", code, body)
	}
	code, body := do(t, h, "POST", "/api/tenants/"+tenant+"/keys", `{"scopes":["read"]}`)
	if code != http.StatusCreated {
		t.Fatalf("seeding key: %d %v", code, body)
	}
	keyID, _ = body["key_id"].(string)
	return h, tenant, keyID
}

// TestBoundaryInputsStayInsideTheContract fires the inputs a generator would:
// nothing, null, truncated JSON, unknown fields, wrong content types, integer
// extremes and oversized bodies. The assertion is not that any particular one
// is rejected - some are legitimately accepted - but that every answer is a
// status the document declares, carrying the body shape it declares, and
// never a panic or a 5xx.
func TestBoundaryInputsStayInsideTheContract(t *testing.T) {
	h, tenant, keyID := seedContract(t, "boundary")
	declared := specOperations(t, loadSpec(t))

	huge := `{"id":"contract-huge","name":"` + strings.Repeat("x", 70<<10) + `"}`
	deep := `{"id":` + strings.Repeat("[", 500) + strings.Repeat("]", 500) + `}`

	cases := []struct {
		name        string
		method      string
		specPath    string
		requestPath string
		body        string
		contentType string
	}{
		{"empty body", "POST", "/api/tenants", "/api/tenants", "", ""},
		{"json null", "POST", "/api/tenants", "/api/tenants", `null`, "application/json"},
		{"truncated json", "POST", "/api/tenants", "/api/tenants", `{"id":`, "application/json"},
		{"unknown field", "POST", "/api/tenants", "/api/tenants", `{"id":"contract-unknown","surprise":1}`, "application/json"},
		{"wrong content type", "POST", "/api/tenants", "/api/tenants", `{"id":"contract-ct"}`, "text/plain"},
		{"array where object expected", "POST", "/api/tenants", "/api/tenants", `[{"id":"contract-arr"}]`, "application/json"},
		{"empty id", "POST", "/api/tenants", "/api/tenants", `{"id":""}`, "application/json"},
		{"negative rate", "POST", "/api/tenants", "/api/tenants", `{"id":"contract-neg","rate":-1}`, "application/json"},
		{"int64 max window", "POST", "/api/tenants", "/api/tenants", `{"id":"contract-max","window_ms":9223372036854775807}`, "application/json"},
		{"float where int expected", "POST", "/api/tenants", "/api/tenants", `{"id":"contract-float","burst":1.5}`, "application/json"},
		{"body over the 64KiB cap", "POST", "/api/tenants", "/api/tenants", huge, "application/json"},
		{"deeply nested value", "POST", "/api/tenants", "/api/tenants", deep, "application/json"},

		{"update unknown tenant", "PUT", "/api/tenants/{id}", "/api/tenants/contract-nosuch", `{"name":"x"}`, "application/json"},
		{"update with unknown field", "PUT", "/api/tenants/{id}", "/api/tenants/" + tenant, `{"name":"x","surprise":1}`, "application/json"},

		{"issue key for unknown tenant", "POST", "/api/tenants/{id}/keys", "/api/tenants/contract-nosuch/keys", `{}`, "application/json"},
		{"issue key with empty body", "POST", "/api/tenants/{id}/keys", "/api/tenants/" + tenant + "/keys", "", ""},
		{"issue key with non-string scope", "POST", "/api/tenants/{id}/keys", "/api/tenants/" + tenant + "/keys", `{"scopes":[7]}`, "application/json"},

		{"route without upstream", "POST", "/api/tenants/{id}/routes", "/api/tenants/" + tenant + "/routes", `{"path_prefix":"/x/"}`, "application/json"},
		{"route with relative prefix", "POST", "/api/tenants/{id}/routes", "/api/tenants/" + tenant + "/routes", `{"path_prefix":"x","upstream":"http://u:9000"}`, "application/json"},
		{"route with retries out of range", "POST", "/api/tenants/{id}/routes", "/api/tenants/" + tenant + "/routes", `{"path_prefix":"/x/","upstream":"http://u:9000","retry_max":99}`, "application/json"},
		{"route with a header but no env", "POST", "/api/tenants/{id}/routes", "/api/tenants/" + tenant + "/routes", `{"path_prefix":"/x/","upstream":"http://u:9000","auth_header":"X-Api-Key"}`, "application/json"},
		{"route with negative timeout", "POST", "/api/tenants/{id}/routes", "/api/tenants/" + tenant + "/routes", `{"path_prefix":"/x/","upstream":"http://u:9000","timeout_ms":-1}`, "application/json"},

		{"rotate unknown key", "POST", "/api/keys/{id}/rotate", "/api/keys/contract-nosuch/rotate", `{}`, "application/json"},
		{"rotate with negative grace", "POST", "/api/keys/{id}/rotate", "/api/keys/" + keyID + "/rotate", `{"grace_seconds":-5}`, "application/json"},

		{"revoke unknown key", "DELETE", "/api/keys/{id}", "/api/keys/contract-nosuch", "", ""},

		{"delete non-integer route", "DELETE", "/api/routes/{id}", "/api/routes/not-a-number", "", ""},
		{"delete route id past int64", "DELETE", "/api/routes/{id}", "/api/routes/99999999999999999999", "", ""},
		{"delete unknown route", "DELETE", "/api/routes/{id}", "/api/routes/2147483647", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.method + " " + tc.specPath
			codes, ok := declared[key]
			if !ok {
				t.Fatalf("%s is not in openapi.json; the case list and the spec disagree", key)
			}

			var body *strings.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			var req *http.Request
			if body == nil {
				req = httptest.NewRequest(tc.method, MountPath+tc.requestPath, nil)
			} else {
				req = httptest.NewRequest(tc.method, MountPath+tc.requestPath, body)
			}
			req.Header.Set("Authorization", "Bearer "+testToken)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			t.Logf("%s -> %d %s", key, rec.Code, strings.TrimSpace(rec.Body.String()))

			if rec.Code >= 500 {
				t.Fatalf("status = %d, which is the gateway blaming itself for a caller's input. body: %s", rec.Code, rec.Body)
			}
			if !codes[fmt.Sprint(rec.Code)] {
				t.Errorf("status = %d, which %s does not declare (declared: %v). body: %s",
					rec.Code, key, sortedCodes(codes), rec.Body)
			}

			var decoded map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
				t.Fatalf("response is not a JSON object: %s", rec.Body)
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			switch {
			case rec.Code >= 400:
				if _, ok := decoded["error"].(string); !ok {
					t.Errorf("error response has no string `error` field: %s", rec.Body)
				}
			case strings.HasSuffix(tc.requestPath, "/keys"), strings.HasSuffix(tc.requestPath, "/rotate"):
				for _, field := range []string{"key_id", "key", "tenant", "note"} {
					if _, ok := decoded[field]; !ok {
						t.Errorf("issued-key response is missing %q: %s", field, rec.Body)
					}
				}
			default:
				if _, ok := decoded["status"].(string); !ok {
					t.Errorf("success response has no string `status` field: %s", rec.Body)
				}
			}
		})
	}
}

// TestOverviewHasNoPagination pins a contract fact a client would otherwise
// have to discover the hard way. The document declares no pagination
// parameters, and the handler has none: limit and offset are ignored rather
// than honoured, so a client that assumed a page size would silently believe
// it had seen everything after one call.
func TestOverviewHasNoPagination(t *testing.T) {
	h, _, _ := seedContract(t, "pagination")

	plain, first := do(t, h, "GET", "/api/overview", "")
	if plain != http.StatusOK {
		t.Fatalf("overview: %d", plain)
	}
	paged, second := do(t, h, "GET", "/api/overview?limit=1&offset=0&page=1&cursor=zzz", "")
	if paged != http.StatusOK {
		t.Fatalf("overview with pagination-shaped query: %d", paged)
	}
	countIn := func(body map[string]any, field string) int {
		list, _ := body[field].([]any)
		return len(list)
	}
	for _, field := range []string{"tenants", "routes", "keys"} {
		if countIn(first, field) != countIn(second, field) {
			t.Errorf("%s: %d rows without a query, %d with limit=1; the endpoint paginates without saying so",
				field, countIn(first, field), countIn(second, field))
		}
	}
	if countIn(first, "tenants") == 0 {
		t.Error("overview returned no tenants; the seed did not land and this test proved nothing")
	}
}

// TestKeyOwnershipSurvivesRotation is the object-ownership property of the
// management API. A key belongs to exactly one tenant, and rotation must not
// be a way to move it: the replacement has to inherit the original's tenant
// and scopes, whatever the caller sends.
func TestKeyOwnershipSurvivesRotation(t *testing.T) {
	h, tenant, keyID := seedContract(t, "ownership")

	other := "contract-ownership-other"
	if code, body := do(t, h, "POST", "/api/tenants",
		`{"id":"`+other+`","name":"Other"}`); code != http.StatusCreated {
		t.Fatalf("seeding second tenant: %d %v", code, body)
	}
	code, body := do(t, h, "POST", "/api/keys/"+keyID+"/rotate", `{"grace_seconds":60}`)
	if code != http.StatusCreated {
		t.Fatalf("rotate: %d %v", code, body)
	}
	if got := body["tenant"]; got != tenant {
		t.Fatalf("replacement key belongs to %v, want %s", got, tenant)
	}
	newID, _ := body["key_id"].(string)

	_, overview := do(t, h, "GET", "/api/overview", "")
	keys, _ := overview["keys"].([]any)
	var found bool
	for _, raw := range keys {
		k, _ := raw.(map[string]any)
		if k["id"] != newID {
			continue
		}
		found = true
		if k["tenant_id"] != tenant {
			t.Errorf("replacement key tenant_id = %v, want %s", k["tenant_id"], tenant)
		}
		scopes, _ := k["scopes"].([]any)
		if len(scopes) != 1 || scopes[0] != "read" {
			t.Errorf("replacement key scopes = %v, want [read]", scopes)
		}
		if _, leaked := k["secret_hash"]; leaked {
			t.Error("the management API serialises secret_hash")
		}
		if _, leaked := k["key"]; leaked {
			t.Error("the management API serialises the key plaintext in a listing")
		}
	}
	if !found {
		t.Fatalf("replacement key %s is not in the overview", newID)
	}

	// Rotating an already-rotated key must not work: it is in grace, not
	// active, so a second rotation would mint a key nobody asked for.
	if code, body := do(t, h, "POST", "/api/keys/"+keyID+"/rotate", `{}`); code != http.StatusBadRequest {
		t.Errorf("rotating a key already in grace: %d %v, want 400", code, body)
	}
}

// TestListingsNeverCarrySecrets is the one response-shape rule that is a
// security property rather than a convenience: the only place a plaintext key
// may appear is the 201 that issues it.
func TestListingsNeverCarrySecrets(t *testing.T) {
	h, _, _ := seedContract(t, "secrets")
	code, _ := do(t, h, "GET", "/api/overview", "")
	if code != http.StatusOK {
		t.Fatalf("overview: %d", code)
	}
	req := httptest.NewRequest("GET", MountPath+"/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	raw := rec.Body.String()
	for _, forbidden := range []string{"secret_hash", "secretHash", "tg_k", testToken} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("overview response contains %q", forbidden)
		}
	}
}

func sortedCodes(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

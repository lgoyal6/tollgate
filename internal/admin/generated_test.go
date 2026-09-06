package admin

// Generated boundary inputs for the whole management surface.
//
// contract_test.go drives a hand-written list of interesting cases. This file
// drives a product instead: every operation the router registers, crossed with
// a corpus of request bodies and a corpus of path-parameter values. The point
// of generating rather than listing is that the case list cannot fall behind
// the API - add an endpoint to operations() and it is exercised here on the
// next run, with no edit to this file.
//
// Four things are asserted about every single answer, and none of them is
// "the input was rejected", because plenty of these inputs are legitimately
// accepted:
//
//  1. the status code is one openapi.json declares for that operation;
//  2. the body is a JSON object, whatever the status;
//  3. a 4xx or 5xx carries a string `error` field;
//  4. that field says nothing that only means something inside the gateway -
//     no table or constraint name, no driver prose, no host or path.
//
// Everything created here lives under the "gen-" tenant prefix and is deleted
// on cleanup. Path parameters are hostile on purpose but never create rows:
// only the `id` in a POST /api/tenants body does, and every one of those is
// prefixed.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const genPrefix = "gen-"

// internalTells are substrings that only mean something inside the gateway:
// the driver's own prose, the schema's names, Go package internals, and the
// coordinates of the machine it runs on. None of them belongs in a message
// sent to a client of a management API.
var internalTells = []string{
	"SQLSTATE", "constraint", "pgx", "postgres", "no rows in result set",
	"strconv.", "json.", "api_keys", "spend_entries", "schema_migrations",
	"relation ", "column ", "closed pool", "dial tcp", "127.0.0.1", "5432",
	"/var/", "/Users/", "goroutine", ".go:",
}

func internalDetailIn(msg string) []string {
	low := strings.ToLower(msg)
	var hit []string
	for _, tell := range internalTells {
		if strings.Contains(low, strings.ToLower(tell)) {
			hit = append(hit, tell)
		}
	}
	return hit
}

// bodyCorpus is the request-body half of the product. Names are only for test
// output; nothing branches on them.
func bodyCorpus() []struct{ name, body, contentType string } {
	long := strings.Repeat("x", 4096)
	overCap := `{"id":"` + genPrefix + `over","name":"` + strings.Repeat("x", 70<<10) + `"}`
	deep := `{"id":` + strings.Repeat("[", 400) + strings.Repeat("]", 400) + `}`
	return []struct{ name, body, contentType string }{
		{"absent", "", ""},
		{"empty string", "", "application/json"},
		{"empty object", `{}`, "application/json"},
		{"json null", `null`, "application/json"},
		{"json array", `[]`, "application/json"},
		{"json true", `true`, "application/json"},
		{"json number", `0`, "application/json"},
		{"json string", `"nope"`, "application/json"},
		{"truncated", `{"id":`, "application/json"},
		{"trailing garbage", `{"id":"` + genPrefix + `t"} }}`, "application/json"},
		{"unknown field", `{"id":"` + genPrefix + `u","surprise":1}`, "application/json"},
		{"duplicate keys", `{"id":"` + genPrefix + `d","id":"` + genPrefix + `d2"}`, "application/json"},
		{"wrong content type", `{"id":"` + genPrefix + `ct"}`, "text/plain"},
		{"no content type", `{"id":"` + genPrefix + `nct"}`, ""},
		{"empty id", `{"id":""}`, "application/json"},
		{"id of 4KiB", `{"id":"` + genPrefix + long + `"}`, "application/json"},
		{"id with a NUL", "{\"id\":\"" + genPrefix + "\\u0000nul\"}", "application/json"},
		{"id with newlines", `{"id":"` + genPrefix + `a\nb\rc"}`, "application/json"},
		{"id with unicode", `{"id":"` + genPrefix + `\u00e9\u4e2d\ud83d\ude00"}`, "application/json"},
		{"id shaped like SQL", `{"id":"` + genPrefix + `'; DROP TABLE tenants; --"}`, "application/json"},
		{"id shaped like a path", `{"id":"` + genPrefix + `../../etc/passwd"}`, "application/json"},
		{"id shaped like a mongo operator", `{"id":{"$ne":null}}`, "application/json"},
		{"negative numbers", `{"id":"` + genPrefix + `neg","rate":-1,"burst":-1,"limit":-1,"window_ms":-1,"timeout_ms":-1,"retry_max":-1,"grace_seconds":-1}`, "application/json"},
		{"int64 extremes", `{"id":"` + genPrefix + `max","burst":9223372036854775807,"limit":-9223372036854775808,"window_ms":9223372036854775807,"timeout_ms":9223372036854775807,"grace_seconds":9223372036854775807,"retry_max":2147483647}`, "application/json"},
		{"past int64", `{"id":"` + genPrefix + `past","burst":99999999999999999999}`, "application/json"},
		{"floats where integers go", `{"id":"` + genPrefix + `flt","burst":1.5,"window_ms":2.5,"grace_seconds":0.5,"retry_max":1.5}`, "application/json"},
		{"exponent notation", `{"id":"` + genPrefix + `exp","rate":1e308,"burst":1e3}`, "application/json"},
		{"nulls everywhere", `{"id":null,"name":null,"enabled":null,"algorithm":null,"scopes":null,"path_prefix":null,"upstream":null}`, "application/json"},
		{"unknown algorithm", `{"id":"` + genPrefix + `algo","algorithm":"leaky_bucket"}`, "application/json"},
		{"scopes of the wrong type", `{"scopes":[7,{},null]}`, "application/json"},
		{"route with a credential in the body", `{"path_prefix":"/x/","upstream":"http://u:9000","auth_header":"X-Api-Key","auth_env":"NOT_SET_ANYWHERE"}`, "application/json"},
		{"route to a non-URL", `{"path_prefix":"/x/","upstream":"://"}`, "application/json"},
		{"route to a file scheme", `{"path_prefix":"/x/","upstream":"file:///etc/passwd"}`, "application/json"},
		{"body over the 64KiB cap", overCap, "application/json"},
		{"deeply nested", deep, "application/json"},
	}
}

// pathCorpus is the path-parameter half. The values that look like they could
// address a real row are the seeded ones; the rest cannot match anything.
func pathCorpus(seeded map[string]string) []struct{ name, id string } {
	return []struct{ name, id string }{
		{"a tenant that exists", seeded["tenant"]},
		{"a key that exists", seeded["key"]},
		{"a route that exists", seeded["route"]},
		{"absent", ""},
		{"one character", "a"},
		{"4KiB", strings.Repeat("z", 4096)},
		{"zero", "0"},
		{"negative", "-1"},
		{"past int64", "9223372036854775808"},
		{"traversal", "..%2f..%2fetc%2fpasswd"},
		{"encoded slash", "a%2Fb"},
		{"unicode", "%C3%A9%E4%B8%AD"},
		{"shaped like SQL", "%27%3B%20DROP%20TABLE%20api_keys%3B%20--"},
		{"shaped like a header", "a%0d%0aX-Injected:%201"},
	}
}

// seedGenerated makes one tenant, one key and one route, so the corpus has
// identifiers that really do address a row.
func seedGenerated(t *testing.T) (http.Handler, map[string]string) {
	t.Helper()
	st := testStore(t)
	ctx := context.Background()
	sweep := func() {
		_, _ = st.Pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id LIKE $1`, genPrefix+"%")
	}
	sweep()
	t.Cleanup(sweep)
	_ = ctx

	h := serve(t, st)
	tenant := genPrefix + "seed"
	if code, body := do(t, h, "POST", "/api/tenants",
		`{"id":"`+tenant+`","name":"Generated"}`); code != http.StatusCreated {
		t.Fatalf("seeding tenant: %d %v", code, body)
	}
	code, body := do(t, h, "POST", "/api/tenants/"+tenant+"/keys", `{"scopes":["read"]}`)
	if code != http.StatusCreated {
		t.Fatalf("seeding key: %d %v", code, body)
	}
	keyID, _ := body["key_id"].(string)

	if code, body := do(t, h, "POST", "/api/tenants/"+tenant+"/routes",
		`{"path_prefix":"/gen/","upstream":"http://upstream:9000"}`); code != http.StatusCreated {
		t.Fatalf("seeding route: %d %v", code, body)
	}
	_, overview := do(t, h, "GET", "/api/overview", "")
	routeID := ""
	for _, raw := range overview["routes"].([]any) {
		r, _ := raw.(map[string]any)
		if r["tenant_id"] == tenant {
			routeID = strconv.FormatInt(int64(r["id"].(float64)), 10)
		}
	}
	if routeID == "" {
		t.Fatal("seeded route is not in the overview")
	}
	return h, map[string]string{"tenant": tenant, "key": keyID, "route": routeID}
}

// TestGeneratedInputsStayInsideTheContract is the product run.
func TestGeneratedInputsStayInsideTheContract(t *testing.T) {
	h, seeded := seedGenerated(t)
	s, err := New(nil, nil, testToken, quietLogger(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	declared := specOperations(t, loadSpec(t))
	bodies := bodyCorpus()
	ids := pathCorpus(seeded)

	var requests int
	for _, op := range s.operations() {
		if op.raw != nil {
			continue // the console takes no input; it is covered in surface_test.go
		}
		key := op.Method + " " + specPath(op.Path)
		codes, ok := declared[key]
		if !ok {
			t.Fatalf("%s is served but not declared; the drift check should have caught this", key)
		}
		idCases := ids
		if !strings.Contains(op.Path, "{id}") {
			idCases = ids[:1] // the path has no parameter; run the corpus once
		}
		for _, id := range idCases {
			concrete := strings.ReplaceAll(op.Path, "{id}", id.id)
			for _, b := range bodies {
				requests++
				name := fmt.Sprintf("%s/%s/%s", key, id.name, b.name)

				var req *http.Request
				if b.body == "" && b.contentType == "" {
					req = httptest.NewRequest(op.Method, MountPath+concrete, nil)
				} else {
					req = httptest.NewRequest(op.Method, MountPath+concrete, strings.NewReader(b.body))
				}
				req.Header.Set("Authorization", "Bearer "+testToken)
				if b.contentType != "" {
					req.Header.Set("Content-Type", b.contentType)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				// An id that is empty, or that carries a raw slash, produces
				// a URL that is no longer an instance of this operation's
				// path at all, so the surface's own catch-all answers and its
				// two codes are legitimate too.
				expected := codes
				if id.id == "" || strings.Contains(id.id, "/") {
					expected = map[string]bool{"404": true, "405": true}
					for c := range codes {
						expected[c] = true
					}
				}
				if !expected[strconv.Itoa(rec.Code)] {
					t.Errorf("%s: status %d, which openapi.json does not declare for it (declared: %v); body: %s",
						name, rec.Code, sortedCodes(expected), strings.TrimSpace(rec.Body.String()))
				}
				if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
					t.Errorf("%s: Content-Type %q, want application/json", name, ct)
				}
				var decoded map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
					t.Errorf("%s: response is not a JSON object: %s", name, rec.Body)
					continue
				}
				if rec.Code < 400 {
					continue
				}
				msg, ok := decoded["error"].(string)
				if !ok {
					t.Errorf("%s: %d with no string `error` field: %s", name, rec.Code, rec.Body)
					continue
				}
				if tells := internalDetailIn(msg); len(tells) > 0 {
					t.Errorf("%s: the error message tells the caller %v: %q", name, tells, msg)
				}
			}
		}
	}
	t.Logf("%d generated requests across %d operations", requests, len(s.operations())-1)
}

// TestGeneratedInputsNeverLeakThroughTheUnmatchedHandler runs the same path
// corpus at endpoints that do not exist, because the catch-all is code too and
// it answers before any token check.
func TestGeneratedInputsNeverLeakThroughTheUnmatchedHandler(t *testing.T) {
	h := serve(t, nil)
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		for _, id := range pathCorpus(map[string]string{}) {
			for _, shape := range []string{"/api/%s", "/%s", "/api/tenants/%s/nope", "/api/keys/%s/nope"} {
				path := fmt.Sprintf(shape, id.id)
				if path == "/" {
					continue // the mount root is the console, not an unknown path
				}
				req := httptest.NewRequest(method, MountPath+path, strings.NewReader(`{}`))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				switch rec.Code {
				case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusUnauthorized:
				default:
					t.Errorf("%s %s: status %d, want 404, 405 or 401", method, path, rec.Code)
				}
				if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
					t.Errorf("%s %s: Content-Type %q, want application/json", method, path, ct)
				}
				var decoded map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
					t.Errorf("%s %s: response is not a JSON object: %s", method, path, rec.Body)
					continue
				}
				msg, _ := decoded["error"].(string)
				if msg == "" {
					t.Errorf("%s %s: no `error` field: %s", method, path, rec.Body)
				}
				// The reply must not echo the path back: that is how a 404
				// page becomes reflected content.
				if strings.Contains(msg, id.id) && id.id != "" {
					t.Errorf("%s %s: the refusal echoes the caller's own path back: %q", method, path, msg)
				}
			}
		}
	}
}

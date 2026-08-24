package admin

// Unit tests here cover the part that must hold with no database at all: the
// management surface is absent unless a token is configured, and once it
// exists nothing behind it answers without that token. Full CRUD is exercised
// against a real Postgres below, skipped unless TOLLGATE_TEST_POSTGRES is set
// (same convention as the Redis limiter tests).

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lgoyal6/tollgate/internal/store"
)

const testToken = "test-admin-token-0123456789"

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewDisabledWithoutToken(t *testing.T) {
	s, err := New(nil, nil, "", quietLogger())
	if err != nil {
		t.Fatalf("New with empty token: %v", err)
	}
	if s != nil {
		t.Fatal("empty ADMIN_TOKEN must yield no management server, got one")
	}
}

func TestNewRejectsShortToken(t *testing.T) {
	s, err := New(nil, nil, "short", quietLogger())
	if err == nil {
		t.Fatal("expected a short token to be rejected")
	}
	if s != nil {
		t.Fatal("no server should be returned alongside an error")
	}
}

// serve builds the handler as the gateway mounts it, at MountPath.
func serve(t *testing.T, st *store.Store) http.Handler {
	t.Helper()
	s, err := New(st, nil, testToken, quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(MountPath+"/", s.Handler())
	return mux
}

// TestEveryAPIRouteRequiresTheToken is the security property of this package:
// no management endpoint answers without the bearer token, so mounting the
// console on the public tenant listener does not expose key issuance.
func TestEveryAPIRouteRequiresTheToken(t *testing.T) {
	// A nil store is deliberate: if any of these reached its handler it would
	// panic, so the test fails loudly rather than silently passing.
	h := serve(t, nil)

	cases := []struct{ method, path string }{
		{"GET", "/api/overview"},
		{"POST", "/api/tenants"},
		{"PUT", "/api/tenants/alice"},
		{"POST", "/api/tenants/alice/keys"},
		{"POST", "/api/tenants/alice/routes"},
		{"POST", "/api/keys/k123/rotate"},
		{"DELETE", "/api/keys/k123"},
		{"DELETE", "/api/routes/1"},
	}
	headers := []struct {
		name  string
		value string
	}{
		{"absent", ""},
		{"wrong token", "Bearer not-the-token-at-all-nope"},
		{"right token, wrong scheme", "Basic " + testToken},
		{"token without scheme", testToken},
		{"empty bearer", "Bearer "},
		{"token with trailing junk", "Bearer " + testToken + "x"},
	}

	for _, c := range cases {
		for _, hd := range headers {
			t.Run(c.method+c.path+"/"+hd.name, func(t *testing.T) {
				req := httptest.NewRequest(c.method, MountPath+c.path, strings.NewReader("{}"))
				if hd.value != "" {
					req.Header.Set("Authorization", hd.value)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("got %d, want 401 (%s %s with %s)", rec.Code, c.method, c.path, hd.name)
				}
				if body := rec.Body.String(); strings.Contains(body, testToken) {
					t.Fatal("error body echoed the admin token back")
				}
			})
		}
	}
}

// TestConsoleServesWithoutToken documents the split: the page itself is a
// static shell with no data in it, so it loads unauthenticated and then asks
// the operator for the token. Every byte of actual config comes from the API,
// which does not.
func TestConsoleServesWithoutToken(t *testing.T) {
	h := serve(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", MountPath+"/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("console returned %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "tollgate") {
		t.Fatal("console body does not look like the console")
	}
	if strings.Contains(body, testToken) {
		t.Fatal("console leaked the admin token into the page")
	}
	// The page needs to know where its own API lives.
	if !strings.Contains(body, MountPath) {
		t.Fatalf("console does not carry its mount path %q", MountPath)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

// TestConsoleStartsLocked pins a defect the first version shipped with: a
// duplicated class attribute meant the header actions rendered before the
// operator had authenticated, so the page looked unlocked when it was not.
func TestConsoleStartsLocked(t *testing.T) {
	h := serve(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", MountPath+"/", nil))
	body := rec.Body.String()

	for _, id := range []string{"hdr-actions", "app"} {
		// The element must carry the hide class in the same tag as its id.
		i := strings.Index(body, `id="`+id+`"`)
		if i < 0 {
			t.Fatalf("console has no element with id %q", id)
		}
		start := strings.LastIndex(body[:i], "<")
		end := i + strings.Index(body[i:], ">")
		tag := body[start:end]
		if !strings.Contains(tag, "hide") {
			t.Fatalf("%q renders visible before unlock: %s", id, tag)
		}
	}
	// A tag with two class attributes silently drops the second one.
	if strings.Contains(body, `class="row" id="hdr-actions" class=`) {
		t.Fatal("duplicate class attribute on hdr-actions")
	}
	// The favicon is inlined so the browser does not request /favicon.ico
	// from the tenant listener, which answers 401.
	if !strings.Contains(body, `rel="icon"`) {
		t.Fatal("console has no inline favicon; the browser will 401 on /favicon.ico")
	}
}

func TestUnknownAdminPathIs404(t *testing.T) {
	h := serve(t, nil)
	for _, p := range []string{MountPath + "/nope", MountPath + "/api/nope"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d, want 404", p, rec.Code)
		}
	}
}

// --- integration: the whole management flow against a real Postgres ---

func testStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("TOLLGATE_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("TOLLGATE_TEST_POSTGRES not set; skipping management API integration tests")
	}
	st, err := store.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connecting to test postgres: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func do(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, MountPath+path, r)
	req.Header.Set("Authorization", "Bearer "+testToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: response is not JSON: %s", method, path, rec.Body.String())
		}
	}
	return rec.Code, out
}

func TestManagementFlow(t *testing.T) {
	st := testStore(t)
	h := serve(t, st)
	ctx := context.Background()

	tenant := "admtest"
	_, _ = st.Pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenant)
	t.Cleanup(func() {
		_, _ = st.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenant)
	})

	code, _ := do(t, h, "POST", "/api/tenants",
		`{"id":"`+tenant+`","name":"Admin Test","algorithm":"sliding_window","limit":5,"window_ms":60000}`)
	if code != http.StatusCreated {
		t.Fatalf("create tenant: got %d, want 201", code)
	}

	// Issue a key: the plaintext comes back exactly once.
	code, issued := do(t, h, "POST", "/api/tenants/"+tenant+"/keys", `{"scopes":["read"]}`)
	if code != http.StatusCreated {
		t.Fatalf("issue key: got %d, want 201", code)
	}
	plaintext, _ := issued["key"].(string)
	keyID, _ := issued["key_id"].(string)
	if plaintext == "" || keyID == "" {
		t.Fatalf("issue key returned no key material: %v", issued)
	}
	if !strings.Contains(plaintext, keyID) {
		t.Fatalf("plaintext %q does not carry its key id %q", plaintext, keyID)
	}

	// The secret is never readable again, from any endpoint.
	code, ov := do(t, h, "GET", "/api/overview", "")
	if code != http.StatusOK {
		t.Fatalf("overview: got %d, want 200", code)
	}
	raw, err := json.Marshal(ov)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), plaintext) {
		t.Fatal("overview echoed a key secret back; only hashes may be stored or served")
	}

	// A route that names an upstream credential stores the env var's name,
	// never a value.
	code, _ = do(t, h, "POST", "/api/tenants/"+tenant+"/routes",
		`{"path_prefix":"/admtest/","upstream":"http://127.0.0.1:9000","strip_prefix":true,`+
			`"auth_header":"x-api-key","auth_env":"ADMTEST_UPSTREAM_KEY"}`)
	if code != http.StatusCreated {
		t.Fatalf("add route: got %d, want 201", code)
	}
	routes, err := st.ListRoutes(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	if routes[0].CredentialFrom != "ADMTEST_UPSTREAM_KEY" || !routes[0].CredentialSet {
		t.Fatalf("route did not record its credential source: %+v", routes[0])
	}

	// Rotate: old key survives in a grace window, replacement is new.
	code, rotated := do(t, h, "POST", "/api/keys/"+keyID+"/rotate", `{"grace_seconds":60}`)
	if code != http.StatusCreated {
		t.Fatalf("rotate: got %d, want 201", code)
	}
	newID, _ := rotated["key_id"].(string)
	if newID == "" || newID == keyID {
		t.Fatalf("rotate returned no fresh key id: %v", rotated)
	}
	keys, err := st.ListKeys(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]store.KeyStatus{}
	for _, k := range keys {
		states[k.ID] = k.Status
	}
	if states[keyID] != store.KeyGrace {
		t.Fatalf("rotated key is %q, want grace", states[keyID])
	}
	if states[newID] != store.KeyActive {
		t.Fatalf("replacement key is %q, want active", states[newID])
	}
	// Rotating the same key twice must fail: it is no longer active.
	if code, _ := do(t, h, "POST", "/api/keys/"+keyID+"/rotate", `{}`); code == http.StatusCreated {
		t.Fatal("rotating an already-rotated key succeeded; it should not")
	}

	// Revoke is immediate and idempotency-safe: the second call 404s.
	if code, _ := do(t, h, "DELETE", "/api/keys/"+newID, ""); code != http.StatusOK {
		t.Fatalf("revoke: got %d, want 200", code)
	}
	if code, _ := do(t, h, "DELETE", "/api/keys/"+newID, ""); code != http.StatusNotFound {
		t.Fatalf("second revoke: got %d, want 404", code)
	}

	// The kill switch: disabling a tenant is a policy update, not a delete.
	code, _ = do(t, h, "PUT", "/api/tenants/"+tenant,
		`{"name":"Admin Test","enabled":false,"algorithm":"sliding_window","limit":5,"window_ms":60000,"rate":1,"burst":5}`)
	if code != http.StatusOK {
		t.Fatalf("disable tenant: got %d, want 200", code)
	}
	tenants, err := st.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tn := range tenants {
		if tn.ID == tenant {
			found = true
			if tn.Enabled {
				t.Fatal("tenant still enabled after the kill switch")
			}
		}
	}
	if !found {
		t.Fatal("tenant vanished from the overview after being disabled")
	}

	// Updating a tenant that does not exist is a 404, not a silent no-op.
	if code, _ := do(t, h, "PUT", "/api/tenants/nope-not-here",
		`{"name":"x","algorithm":"token_bucket","rate":1,"burst":1,"limit":1,"window_ms":1000}`); code != http.StatusNotFound {
		t.Fatalf("update missing tenant: got %d, want 404", code)
	}
}

func TestRejectsBadInput(t *testing.T) {
	st := testStore(t)
	h := serve(t, st)

	bad := []struct {
		name, method, path, body string
	}{
		{"no id", "POST", "/api/tenants", `{"name":"x"}`},
		{"unknown field", "POST", "/api/tenants", `{"id":"x","nope":1}`},
		{"bad algorithm", "POST", "/api/tenants", `{"id":"x","algorithm":"magic"}`},
		{"negative limit", "POST", "/api/tenants", `{"id":"x","limit":-5}`},
		{"malformed json", "POST", "/api/tenants", `{`},
		{"route id not a number", "DELETE", "/api/routes/abc", ""},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			code, body := do(t, h, c.method, c.path, c.body)
			if code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400 (body %v)", code, body)
			}
			if body["error"] == nil {
				t.Fatal("400 response carried no error message")
			}
		})
	}
}

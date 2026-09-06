package admin

// The management API's published surface, checked against the router rather
// than against a description of the router.
//
// contract_test.go compares openapi.json with the operation table. That is
// only a contract check if the table is the whole router: a handler wired
// straight onto the mux is invisible to it, and an undocumented endpoint that
// answers 200 without a token is exactly the thing a contract is supposed to
// make impossible. So the first test here reads the source of every
// registration this package makes and requires all but the documented
// catch-all to come from the table.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// catchAll is the one pattern that is allowed to be registered as a literal:
// it is not an endpoint, it is what answers when no endpoint matched.
const catchAll = "/"

// TestEveryRouteRegistrationComesFromTheOperationTable parses this package's
// own source and fails on any pattern registered with a string literal other
// than the catch-all. Anything else has to go through operations(), which is
// what the openapi.json comparison reads.
func TestEveryRouteRegistrationComesFromTheOperationTable(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}
	var literals []string
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			literals = append(literals, name+": "+pattern+" (line "+
				strconv.Itoa(fset.Position(lit.Pos()).Line)+")")
			return true
		})
	}
	for _, got := range literals {
		_, pattern, _ := strings.Cut(got, ": ")
		pattern, _, _ = strings.Cut(pattern, " (line")
		if pattern == catchAll {
			continue
		}
		t.Errorf("%s is registered on the router as a literal, so it never passes "+
			"through operations() and openapi.json is not checked against it", got)
	}
}

// TestSpecDeclaresEveryRegisteredOperation is the bidirectional drift check
// over the whole router, console included, rather than over the JSON API
// alone.
func TestSpecDeclaresEveryRegisteredOperation(t *testing.T) {
	s, err := New(nil, nil, testToken, quietLogger(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	declared := specOperations(t, loadSpec(t))
	registered := map[string]bool{}
	for _, op := range s.operations() {
		registered[op.Method+" "+specPath(op.Path)] = true
	}
	for key := range registered {
		if _, ok := declared[key]; !ok {
			t.Errorf("%s is served but not in openapi.json", key)
		}
	}
	for key := range declared {
		if !registered[key] {
			t.Errorf("openapi.json declares %s, which nothing serves", key)
		}
	}
}

// TestUnknownPathAnswersTheDocumentedErrorEnvelope covers what net/http's own
// mux would otherwise answer: a text/plain body with no `error` field, which
// is a response shape this API's contract does not have.
func TestUnknownPathAnswersTheDocumentedErrorEnvelope(t *testing.T) {
	h := serve(t, nil) // nil store: nothing here may reach a handler

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/tenants"}, // real prefix, no such endpoint for GET
		{"GET", "/api/nope"},    // nothing like it at all
		{"POST", "/api/nope"},
		{"GET", "/api/keys/k1"}, // /api/keys/{id} exists, but only for DELETE
		{"DELETE", "/api/tenants"},
		{"PATCH", "/api/tenants/x"},
		{"OPTIONS", "/api/overview"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, MountPath+tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 404 or 405", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json; body: %s",
					ct, strings.TrimSpace(rec.Body.String()))
			}
			if !strings.Contains(rec.Body.String(), `"error"`) {
				t.Errorf("body has no `error` field: %s", strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

// TestWrongMethodAnswersAllowDerivedFromTheSpec is the other half of the
// bidirectional check, expressed at runtime: for every path the document
// declares, the Allow header the gateway sends back must name exactly the
// methods the document declares for that path. A method added to one side
// only shows up here.
func TestWrongMethodAnswersAllowDerivedFromTheSpec(t *testing.T) {
	h := serve(t, nil)
	byPath := map[string]map[string]bool{}
	for key := range specOperations(t, loadSpec(t)) {
		method, path, _ := strings.Cut(key, " ")
		if byPath[path] == nil {
			byPath[path] = map[string]bool{}
		}
		byPath[path][method] = true
	}

	for path, methods := range byPath {
		// Pick a method the path does not serve.
		var unused string
		for _, candidate := range []string{"PATCH", "PUT", "POST", "DELETE"} {
			if !methods[candidate] {
				unused = candidate
				break
			}
		}
		if unused == "" {
			continue
		}
		concrete := strings.NewReplacer("{id}", "surface-probe").Replace(path)
		req := httptest.NewRequest(unused, MountPath+concrete, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status = %d, want 405", unused, path, rec.Code)
			continue
		}
		want := make([]string, 0, len(methods))
		for m := range methods {
			want = append(want, m)
		}
		sort.Strings(want)
		if got := rec.Header().Get("Allow"); got != strings.Join(want, ", ") {
			t.Errorf("%s %s: Allow = %q, want %q", unused, path, got, strings.Join(want, ", "))
		}
	}
}

// TestTheCatchAllIsNotAnAuthenticationBypass pins the thing that would make
// the catch-all worse than net/http's default: it answers before any token
// check, so it must never be reachable for a path an operation serves.
func TestTheCatchAllIsNotAnAuthenticationBypass(t *testing.T) {
	s, err := New(nil, nil, testToken, quietLogger(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := serve(t, nil)
	for _, op := range s.operations() {
		if op.raw != nil {
			continue // the console is public by design
		}
		concrete := strings.NewReplacer("{id}", "surface-probe").Replace(op.Path)
		req := httptest.NewRequest(op.Method, MountPath+concrete, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: status = %d, want 401; the catch-all answered "+
				"for a path an operation serves", op.Method, op.Path, rec.Code)
		}
	}
}

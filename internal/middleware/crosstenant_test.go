package middleware

// Cross-tenant object access, at every point on the data plane where a caller
// gets to name something.
//
// isolation_test.go proves the router does not hand one tenant another's
// route. This file asks the harder question: when a tenant presents an
// identifier that belongs to somebody else, is the refusal distinguishable
// from the refusal for an identifier that was simply made up? If it is, the
// gateway is an oracle - a caller can enumerate which tenants, keys and route
// prefixes exist by diffing the replies - and the answers here are compared
// byte for byte, with the request id pinned so that the only thing that could
// differ is the part the gateway chose.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/store"
)

// pinnedRequestID makes two refusals comparable byte for byte: it is the one
// field in the error envelope that is generated per request.
const pinnedRequestID = "cross-tenant-probe"

// reply is everything a caller can observe about one refusal.
type reply struct {
	status  int
	headers string
	body    []byte
}

func (r reply) String() string {
	return strings.TrimSpace(string(r.body)) + " | " + r.headers
}

// crossTenantFixture builds two tenants with private and shared prefixes, and
// a chain that records whether anything ever reached the far side.
func crossTenantFixture(t *testing.T) (call func(credential, path string) reply, forwarded *atomic.Int64, keyA, keyB, idA, idB string) {
	t.Helper()
	snap, keyA, keyB := twoTenants(t)
	idA, idB = keyIDOf(keyA), keyIDOf(keyB)

	var reached atomic.Int64
	sink := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	h := Chain(sink,
		Recover(testLogger),
		RequestID(),
		Metrics(observability.NewMetrics()),
		Auth(func() *store.Snapshot { return snap }, observability.NewMetrics(), nil),
		Router(func() *store.Snapshot { return snap }),
	)

	call = func(credential, path string) reply {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"model":"m"}`))
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set("X-Request-Id", pinnedRequestID)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		names := make([]string, 0, len(rec.Header()))
		for k := range rec.Header() {
			names = append(names, k+": "+strings.Join(rec.Header()[k], ","))
		}
		sort.Strings(names)
		return reply{status: rec.Code, headers: strings.Join(names, "; "), body: rec.Body.Bytes()}
	}
	return call, &reached, keyA, keyB, idA, idB
}

// keyIDOf splits tg_<id>_<secret>. The id is not a secret - it is in every
// log line and every metric label - which is exactly why a caller can put
// somebody else's in a credential and see what comes back.
func keyIDOf(credential string) string {
	rest := strings.TrimPrefix(credential, "tg_")
	id, _, _ := strings.Cut(rest, "_")
	return id
}

// TestAnothersRouteRefusesExactlyLikeARouteThatDoesNotExist is the object
// entry point a tenant can address directly: the path prefix.
func TestAnothersRouteRefusesExactlyLikeARouteThatDoesNotExist(t *testing.T) {
	call, forwarded, keyA, _, _, _ := crossTenantFixture(t)

	// Baseline: alpha's own route works, so a 404 below means isolation and
	// not a chain that refuses everything.
	if got := call(keyA, "/alpha-only/thing"); got.status != http.StatusOK {
		t.Fatalf("alpha on its own route: %d %s", got.status, got)
	}
	before := forwarded.Load()

	real := call(keyA, "/beta-only/thing")          // beta's route, which exists
	invented := call(keyA, "/no-such-prefix/thing") // a prefix nobody owns

	if real.status != http.StatusNotFound {
		t.Errorf("alpha addressing beta's route: %d, want 404", real.status)
	}
	if !bytes.Equal(real.body, invented.body) || real.status != invented.status || real.headers != invented.headers {
		t.Errorf("a route that belongs to somebody else is distinguishable from one that does not exist:\n"+
			" real:     %d %s\n invented: %d %s", real.status, real, invented.status, invented)
	}
	if got := forwarded.Load(); got != before {
		t.Errorf("%d requests reached the far side of the chain while probing another tenant's route", got-before)
	}
}

// TestAnothersKeyIDRefusesExactlyLikeAKeyIDThatDoesNotExist covers the other
// identifier a caller controls: the key id inside the credential itself. A
// tollgate key is tg_<id>_<secret>, so a caller can name any key id it likes
// and pair it with its own secret.
func TestAnothersKeyIDRefusesExactlyLikeAKeyIDThatDoesNotExist(t *testing.T) {
	call, forwarded, keyA, _, _, idB := crossTenantFixture(t)

	secretOf := func(credential string) string {
		_, rest, _ := strings.Cut(credential, "_")
		_, secret, _ := strings.Cut(rest, "_")
		return secret
	}
	// Alpha's own secret, presented under beta's key id.
	borrowed := "tg_" + idB + "_" + secretOf(keyA)
	invented := "tg_kdeadbeefdead_" + secretOf(keyA)

	before := forwarded.Load()
	got, want := call(borrowed, "/beta-only/thing"), call(invented, "/beta-only/thing")

	if got.status != http.StatusUnauthorized {
		t.Errorf("another tenant's key id with our own secret: %d, want 401", got.status)
	}
	if !bytes.Equal(got.body, want.body) || got.status != want.status || got.headers != want.headers {
		t.Errorf("a key id that exists is distinguishable from one that does not:\n"+
			" real:     %d %s\n invented: %d %s", got.status, got, want.status, want)
	}
	if n := forwarded.Load() - before; n != 0 {
		t.Errorf("%d requests reached the far side while probing another tenant's key id", n)
	}
}

// TestEveryAuthenticationFailureIsTheSameReply is the general form: whatever
// went wrong with a credential, the caller is told the same thing. Otherwise
// the difference between "revoked", "expired" and "never existed" is a
// readable signal about somebody else's account.
func TestEveryAuthenticationFailureIsTheSameReply(t *testing.T) {
	snap, keyA, _ := twoTenants(t)
	idA := keyIDOf(keyA)

	var reached atomic.Int64
	sink := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	m := observability.NewMetrics()
	h := Chain(sink, Recover(testLogger), RequestID(), Auth(func() *store.Snapshot { return snap }, m, nil), Router(func() *store.Snapshot { return snap }))

	call := func(credential string) reply {
		req := httptest.NewRequest(http.MethodPost, "/alpha-only/thing", nil)
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set("X-Request-Id", pinnedRequestID)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		names := make([]string, 0, len(rec.Header()))
		for k := range rec.Header() {
			names = append(names, k+": "+strings.Join(rec.Header()[k], ","))
		}
		sort.Strings(names)
		return reply{status: rec.Code, headers: strings.Join(names, "; "), body: rec.Body.Bytes()}
	}

	// Baseline first: the credential works before anything is done to it.
	if got := call(keyA); got.status != http.StatusOK {
		t.Fatalf("alpha's key does not work to begin with: %d %s", got.status, got)
	}

	_, secret, _ := strings.Cut(strings.TrimPrefix(keyA, "tg_"), "_")
	unknown := call("tg_kdeadbeefdead_" + secret)

	cases := map[string]string{
		"wrong secret for a real key id": "tg_" + idA + "_" + strings.Repeat("A", len(secret)),
		"not a tollgate key at all":      "nonsense",
		"empty id":                       "tg__" + secret,
	}
	for name, credential := range cases {
		got := call(credential)
		if !bytes.Equal(got.body, unknown.body) || got.status != unknown.status || got.headers != unknown.headers {
			t.Errorf("%s is distinguishable from an unknown key:\n got:     %d %s\n unknown: %d %s",
				name, got.status, got, unknown.status, unknown)
		}
	}

	// Revoked, grace-expired and tenant-disabled are reached by mutating the
	// snapshot rather than by crafting a credential.
	key, ok := snap.Key(idA)
	if !ok {
		t.Fatalf("alpha's key %s is not in the snapshot", idA)
	}
	original := *key

	key.Status = store.KeyRevoked
	if got := call(keyA); !bytes.Equal(got.body, unknown.body) || got.status != unknown.status {
		t.Errorf("a revoked key is distinguishable from an unknown one:\n got: %d %s\n unknown: %d %s",
			got.status, got, unknown.status, unknown)
	}

	past := time.Now().Add(-time.Hour)
	key.Status = store.KeyGrace
	key.GraceUntil = &past
	if got := call(keyA); !bytes.Equal(got.body, unknown.body) || got.status != unknown.status {
		t.Errorf("a key whose grace window has closed is distinguishable from an unknown one:\n got: %d %s",
			got.status, got)
	}

	*key = original
	alpha, _ := snap.Tenant("alpha")
	alpha.Enabled = false
	if got := call(keyA); !bytes.Equal(got.body, unknown.body) || got.status != unknown.status {
		t.Errorf("a disabled tenant is distinguishable from an unknown key:\n got: %d %s", got.status, got)
	}

	if n := reached.Load(); n != 1 {
		t.Errorf("%d requests reached the far side of the chain; only the baseline should have", n)
	}
}

// TestAuthenticationFailuresStillSeparateInTheMetrics is the other side of the
// same coin, and the reason the opacity above is safe to keep: an operator has
// to be able to tell a revoked key from an unknown one, so the distinction
// lives in a counter nobody outside the deployment can read.
func TestAuthenticationFailuresStillSeparateInTheMetrics(t *testing.T) {
	for _, err := range []error{
		auth.ErrUnknownKey, auth.ErrBadSecret, auth.ErrRevoked,
		auth.ErrGraceExpired, auth.ErrTenantDisabled, auth.ErrMalformed,
	} {
		if reason := authFailureReason(err); reason == "other" {
			t.Errorf("%v is counted as %q, so an operator cannot tell it apart", err, reason)
		}
	}
}

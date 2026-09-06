package admin

// Key lifecycle timing. Issuing, rotating and revoking a key are writes to
// Postgres, but what a teammate can actually spend is decided from the
// in-process config snapshot, so the question these tests answer is not "did
// the row change" - the CRUD test above covers that - it is "when does the
// change bind". A revocation that returns 200 while the revoked credential
// still works is the difference between an offboarding and a security
// incident.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/store"
)

// liveGateway is the pair a real replica runs: a management handler writing to
// Postgres, and the watcher-backed snapshot the request path authenticates
// against. Nothing here reads the database per request, which is exactly why
// the timing is worth a test.
type liveGateway struct {
	admin   http.Handler
	watcher *store.Watcher
	store   *store.Store
}

func liveFixture(t *testing.T, tenant string) *liveGateway {
	t.Helper()
	st := testStore(t)
	ctx := context.Background()

	_, _ = st.Pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenant)
	t.Cleanup(func() {
		_, _ = st.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenant)
	})

	// Poll and debounce at their production defaults. A test that shortened
	// them would be measuring a gateway nobody deploys.
	w := store.NewWatcher(st, quietLogger(), 30*time.Second, 200*time.Millisecond)
	s, err := New(st, nil, testToken, quietLogger(), w)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &liveGateway{admin: MountOn(s.Handler(), http.NotFoundHandler()), watcher: w, store: st}
}

// verify authenticates a credential exactly as the Auth middleware does:
// against whatever snapshot this replica is currently serving.
func (g *liveGateway) verify(t *testing.T, credential string) error {
	t.Helper()
	snap := g.watcher.Snapshot()
	if snap == nil {
		t.Fatal("watcher has no snapshot; the gateway would be answering 503")
	}
	_, err := auth.Verify(snap, credential, time.Now())
	return err
}

func (g *liveGateway) reload(t *testing.T) {
	t.Helper()
	if err := g.watcher.Load(context.Background()); err != nil {
		t.Fatalf("loading snapshot: %v", err)
	}
}

func issueKey(t *testing.T, g *liveGateway, tenant string) (id, plaintext string) {
	t.Helper()
	code, body := do(t, g.admin, "POST", "/api/tenants/"+tenant+"/keys", `{"scopes":["read"]}`)
	if code != http.StatusCreated {
		t.Fatalf("issue key: got %d, want 201: %v", code, body)
	}
	id, _ = body["key_id"].(string)
	plaintext, _ = body["key"].(string)
	if id == "" || plaintext == "" {
		t.Fatalf("issue key returned no credential: %v", body)
	}
	return id, plaintext
}

// TestRevocationBindsOnTheNextRequest is the offboarding property. The moment
// the management API answers 200 to a revoke, the credential must be dead on
// this replica - not dead once the watcher's debounce elapses, and not dead
// once the 30 second poll comes round.
func TestRevocationBindsOnTheNextRequest(t *testing.T) {
	const tenant = "lifecycle-revoke"
	g := liveFixture(t, tenant)

	code, body := do(t, g.admin, "POST", "/api/tenants",
		`{"id":"`+tenant+`","name":"Lifecycle Revoke"}`)
	if code != http.StatusCreated {
		t.Fatalf("create tenant: got %d, want 201: %v", code, body)
	}
	keyID, credential := issueKey(t, g, tenant)

	// Baseline: the key works. Without this the test could pass because the
	// key never worked in the first place.
	g.reload(t)
	if err := g.verify(t, credential); err != nil {
		t.Fatalf("freshly issued key does not authenticate: %v", err)
	}

	code, body = do(t, g.admin, "DELETE", "/api/keys/"+keyID, "")
	if code != http.StatusOK {
		t.Fatalf("revoke: got %d, want 200: %v", code, body)
	}

	// No reload here on purpose: this is the next request arriving at the
	// same process that just answered the revoke.
	if err := g.verify(t, credential); err == nil {
		t.Fatal("revoked credential still authenticates on the replica that performed the revocation; the 200 was a promise this gateway had not kept")
	}
}

// TestRotationBindsOnTheNextRequest is the other half. Rotation has to be
// non-disruptive in both directions at once: the replacement must work
// immediately, or the teammate who just copied it out of the console gets a
// 401, and the old one must keep working until its grace window closes, or
// rotation is just revocation with extra steps.
func TestRotationBindsOnTheNextRequest(t *testing.T) {
	const tenant = "lifecycle-rotate"
	g := liveFixture(t, tenant)

	code, body := do(t, g.admin, "POST", "/api/tenants",
		`{"id":"`+tenant+`","name":"Lifecycle Rotate"}`)
	if code != http.StatusCreated {
		t.Fatalf("create tenant: got %d, want 201: %v", code, body)
	}
	oldID, oldCredential := issueKey(t, g, tenant)

	g.reload(t)
	if err := g.verify(t, oldCredential); err != nil {
		t.Fatalf("freshly issued key does not authenticate: %v", err)
	}

	code, body = do(t, g.admin, "POST", "/api/keys/"+oldID+"/rotate", `{"grace_seconds":3600}`)
	if code != http.StatusCreated {
		t.Fatalf("rotate: got %d, want 201: %v", code, body)
	}
	newCredential, _ := body["key"].(string)
	if newCredential == "" {
		t.Fatalf("rotate returned no replacement credential: %v", body)
	}

	if err := g.verify(t, newCredential); err != nil {
		t.Fatalf("replacement credential does not authenticate on the replica that minted it: %v", err)
	}
	if err := g.verify(t, oldCredential); err != nil {
		t.Fatalf("rotated key stopped working inside its grace window: %v", err)
	}
}

// TestGraceWindowExpiryIsCheckedPerRequest pins the part of the state machine
// that no reload can carry: a key in grace is refused once grace_until has
// passed, and it is the request's clock that decides, not the snapshot's age.
// Without this a key could sit in a snapshot loaded before expiry and keep
// authenticating until something unrelated triggered a reload.
func TestGraceWindowExpiryIsCheckedPerRequest(t *testing.T) {
	const tenant = "lifecycle-grace"
	g := liveFixture(t, tenant)

	code, body := do(t, g.admin, "POST", "/api/tenants",
		`{"id":"`+tenant+`","name":"Lifecycle Grace"}`)
	if code != http.StatusCreated {
		t.Fatalf("create tenant: got %d, want 201: %v", code, body)
	}
	oldID, oldCredential := issueKey(t, g, tenant)

	code, body = do(t, g.admin, "POST", "/api/keys/"+oldID+"/rotate", `{"grace_seconds":2}`)
	if code != http.StatusCreated {
		t.Fatalf("rotate: got %d, want 201: %v", code, body)
	}
	if err := g.verify(t, oldCredential); err != nil {
		t.Fatalf("rotated key refused inside its grace window: %v", err)
	}

	// Deliberately no reload: the snapshot still holds the grace key, and the
	// refusal has to come from comparing the request's clock to grace_until.
	snap := g.watcher.Snapshot()
	if _, err := auth.Verify(snap, oldCredential, time.Now().Add(5*time.Second)); err == nil {
		t.Fatal("key still authenticates after its grace window closed")
	} else if err != auth.ErrGraceExpired {
		t.Fatalf("expired grace key rejected as %v, want ErrGraceExpired; the metric would attribute it to the wrong cause", err)
	}
}

// TestRevokedKeyLeavesTheSnapshot documents which failure a revoked key
// actually produces. LoadSnapshot filters `status <> 'revoked'`, so the key is
// simply absent and auth reports it as unknown rather than revoked. That is
// safe - unknown is a refusal - but it means the tollgate_auth_failures_total
// reason label never carries "revoked" in production, and an operator
// alerting on continued use of a revoked credential has to watch
// "unknown_key" instead.
func TestRevokedKeyLeavesTheSnapshot(t *testing.T) {
	const tenant = "lifecycle-absent"
	g := liveFixture(t, tenant)

	code, body := do(t, g.admin, "POST", "/api/tenants",
		`{"id":"`+tenant+`","name":"Lifecycle Absent"}`)
	if code != http.StatusCreated {
		t.Fatalf("create tenant: got %d, want 201: %v", code, body)
	}
	keyID, credential := issueKey(t, g, tenant)

	if code, body := do(t, g.admin, "DELETE", "/api/keys/"+keyID, ""); code != http.StatusOK {
		t.Fatalf("revoke: got %d, want 200: %v", code, body)
	}
	g.reload(t)

	if _, ok := g.watcher.Snapshot().Key(keyID); ok {
		t.Error("revoked key is still present in the snapshot")
	}
	if err := g.verify(t, credential); err != auth.ErrUnknownKey {
		t.Errorf("revoked key rejected as %v, want ErrUnknownKey; update the comment above and the alerting note if this changes", err)
	}
}

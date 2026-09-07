package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/store"
)

func TestCurrentAuthorizationRechecksAfterSnapshotAuthentication(t *testing.T) {
	generated, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	snap := store.SnapshotForTest(
		[]*store.Tenant{{ID: "acme", Enabled: true}}, nil,
		[]*store.APIKey{{ID: generated.ID, TenantID: "acme", SecretHash: generated.SecretHash, Status: store.KeyActive}},
	)
	state := store.AccessAllowed
	hits := 0
	checker := func(context.Context, string, string, time.Time) (store.AccessState, error) {
		return state, nil
	}
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }),
		RequestID(), Auth(func() *store.Snapshot { return snap }, observability.NewMetrics(), nil),
		CurrentAuthorization(checker, observability.NewMetrics()))

	request := func() int {
		req := httptest.NewRequest(http.MethodGet, "/v1/chat", nil)
		req.Header.Set("Authorization", "Bearer "+generated.Plaintext)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := request(); got != http.StatusOK || hits != 1 {
		t.Fatalf("baseline = status %d, hits %d; want 200, 1", got, hits)
	}

	// The local snapshot is deliberately unchanged. This models a second
	// replica that has not processed LISTEN/NOTIFY yet.
	state = store.AccessRevoked
	if got := request(); got != http.StatusUnauthorized {
		t.Fatalf("next protected action after revocation = %d, want 401", got)
	}
	if hits != 1 {
		t.Fatalf("revoked request reached protected action; hits = %d", hits)
	}
}

func TestCurrentAuthorizationFailsClosedWithinBound(t *testing.T) {
	generated, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	snap := store.SnapshotForTest(
		[]*store.Tenant{{ID: "acme", Enabled: true}}, nil,
		[]*store.APIKey{{ID: generated.ID, TenantID: "acme", SecretHash: generated.SecretHash, Status: store.KeyActive}},
	)
	checker := func(ctx context.Context, _, _ string, _ time.Time) (store.AccessState, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	hits := 0
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }),
		RequestID(), Auth(func() *store.Snapshot { return snap }, observability.NewMetrics(), nil),
		CurrentAuthorization(checker, observability.NewMetrics()))
	req := httptest.NewRequest(http.MethodGet, "/v1/chat", nil)
	req.Header.Set("Authorization", "Bearer "+generated.Plaintext)
	rec := httptest.NewRecorder()
	started := time.Now()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if hits != 0 {
		t.Fatal("protected action ran while current authorization was unavailable")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("authorization check took %s, want a bounded refusal", elapsed)
	}
}

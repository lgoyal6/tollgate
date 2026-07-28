package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/store"
)

func TestGenerateAndParseRoundTrip(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(gen.Plaintext, "tg_") {
		t.Fatalf("plaintext %q missing tg_ prefix", gen.Plaintext)
	}
	id, secret, err := Parse(gen.Plaintext)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if id != gen.ID {
		t.Errorf("parsed id %q, want %q", id, gen.ID)
	}
	if string(HashSecret(secret)) != string(gen.SecretHash) {
		t.Error("hash of parsed secret does not match stored hash")
	}
}

// Regression: base64url secrets can legitimately contain underscores; Parse
// must treat everything after the second separator as the secret.
func TestParseSecretWithUnderscores(t *testing.T) {
	id, secret, err := Parse("tg_k123_se_cr_et")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if id != "k123" || secret != "se_cr_et" {
		t.Errorf("Parse = (%q, %q), want (k123, se_cr_et)", id, secret)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"no separators", "tgabcdef"},
		{"wrong prefix", "sk_k123_secret"},
		{"missing secret", "tg_k123_"},
		{"missing id", "tg__secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := Parse(tt.raw); !errors.Is(err, ErrMalformed) {
				t.Errorf("Parse(%q) err = %v, want ErrMalformed", tt.raw, err)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	makeSnap := func(status store.KeyStatus, graceUntil *time.Time, tenantEnabled bool) *store.Snapshot {
		return store.SnapshotForTest(
			[]*store.Tenant{{ID: "acme", Name: "Acme", Enabled: tenantEnabled}},
			nil,
			[]*store.APIKey{{
				ID: gen.ID, TenantID: "acme", SecretHash: gen.SecretHash,
				Scopes: []string{"read"}, Status: status, GraceUntil: graceUntil,
			}},
		)
	}

	tests := []struct {
		name       string
		raw        string
		snap       *store.Snapshot
		wantErr    error
		wantOK     bool
		wantGrace  bool
	}{
		{
			name: "active key accepted",
			raw:  gen.Plaintext, snap: makeSnap(store.KeyActive, nil, true),
			wantOK: true,
		},
		{
			name: "unknown key id",
			raw:  "tg_knope_" + strings.Repeat("x", 43), snap: makeSnap(store.KeyActive, nil, true),
			wantErr: ErrUnknownKey,
		},
		{
			name: "wrong secret",
			raw:  "tg_" + gen.ID + "_wrongsecret", snap: makeSnap(store.KeyActive, nil, true),
			wantErr: ErrBadSecret,
		},
		{
			name: "revoked key",
			raw:  gen.Plaintext, snap: makeSnap(store.KeyRevoked, nil, true),
			wantErr: ErrRevoked,
		},
		{
			name: "grace window still open",
			raw:  gen.Plaintext, snap: makeSnap(store.KeyGrace, &future, true),
			wantOK: true, wantGrace: true,
		},
		{
			name: "grace window expired",
			raw:  gen.Plaintext, snap: makeSnap(store.KeyGrace, &past, true),
			wantErr: ErrGraceExpired,
		},
		{
			name: "grace status without deadline",
			raw:  gen.Plaintext, snap: makeSnap(store.KeyGrace, nil, true),
			wantErr: ErrGraceExpired,
		},
		{
			name: "tenant disabled",
			raw:  gen.Plaintext, snap: makeSnap(store.KeyActive, nil, false),
			wantErr: ErrTenantDisabled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, err := Verify(tt.snap, tt.raw, now)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Verify err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !tt.wantOK {
				t.Fatal("expected failure, got success")
			}
			if verdict.Tenant.ID != "acme" {
				t.Errorf("tenant = %q, want acme", verdict.Tenant.ID)
			}
			if verdict.Deprecated != tt.wantGrace {
				t.Errorf("Deprecated = %v, want %v", verdict.Deprecated, tt.wantGrace)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	key := &store.APIKey{Scopes: []string{"read", "metrics"}}
	tests := []struct {
		name     string
		required string
		want     bool
	}{
		{"empty requirement always passes", "", true},
		{"present scope", "read", true},
		{"absent scope", "write", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasScope(key, tt.required); got != tt.want {
				t.Errorf("HasScope(%q) = %v, want %v", tt.required, got, tt.want)
			}
		})
	}
}

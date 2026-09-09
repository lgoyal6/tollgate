package secops

import (
	"strconv"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/reqctx"
)

func replayRecorder(t *testing.T, now time.Time) (*Recorder, *collect) {
	t.Helper()
	sink := &collect{}
	return NewRecorder(Options{Sinks: []Sink{sink}, Now: fixedClock(now), ReplayCapacity: 4}), sink
}

func TestTokenReplayFiresOnlyForASecondPeer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	expiry := now.Add(5 * time.Minute)

	tests := []struct {
		name       string
		presents   []string // peer identities, in order
		wantEvents int
	}{
		{"one presentation is not a replay", []string{"cert:a"}, 0},
		{"the same peer twice is a refresh, not a replay", []string{"cert:a", "cert:a"}, 0},
		{"a second peer is a replay", []string{"cert:a", "cert:b"}, 1},
		{"a third peer is another replay", []string{"cert:a", "cert:b", "cert:c"}, 2},
		{"an address peer is tracked like a certificate peer", []string{"ip:10.0.0.1", "ip:10.0.0.2"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, sink := replayRecorder(t, now)
			ctx, _ := tracedContext(t, &reqctx.Info{RequestID: "r", TenantID: "acme"})
			for _, peer := range tt.presents {
				rec.NoteTokenUse(ctx, "jti:t1", peer, expiry, false)
			}
			if len(sink.events) != tt.wantEvents {
				t.Fatalf("emitted %d token_replay events, want %d", len(sink.events), tt.wantEvents)
			}
			for _, e := range sink.events {
				if e.Type != EventTokenReplay || e.Control != ControlTokenReplayFilter {
					t.Errorf("unexpected event %+v", e)
				}
				// The detector must never claim it did anything about it.
				if e.Outcome != OutcomeAllowed {
					t.Errorf("outcome = %q, want %q: the filter refuses nothing", e.Outcome, OutcomeAllowed)
				}
				if e.Evidence["first_seen_peer"] != tt.presents[0] {
					t.Errorf("first_seen_peer = %q, want the original peer %q",
						e.Evidence["first_seen_peer"], tt.presents[0])
				}
			}
		})
	}
}

// A token id past its own expiry is a fresh sighting, not a replay: the
// filter tracks a credential's lifetime, and a reissued token that happened
// to reuse a jti is not evidence of theft.
func TestAnExpiredSightingIsNotAReplay(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	f := NewReplayFilter(8)
	expiry := start.Add(time.Minute)

	if s := f.note("jti:t1", "cert:a", expiry, start); s.replayed {
		t.Fatal("first sighting reported as a replay")
	}
	if s := f.note("jti:t1", "cert:b", expiry, start.Add(2*time.Minute)); s.replayed {
		t.Fatal("a presentation after the token expired must not be a replay")
	}
}

func TestTheReplayFilterStaysBounded(t *testing.T) {
	f := NewReplayFilter(4)
	now := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 100; i++ {
		f.note("jti:t"+strconv.Itoa(i), "cert:a", now.Add(time.Hour), now)
	}
	if got := f.Len(); got != 4 {
		t.Fatalf("filter holds %d entries, want the capacity 4", got)
	}
}

func TestTokenIDPrefersTheJTIAndNeverStoresTheToken(t *testing.T) {
	raw := "header.payload.signature"
	if got := TokenID("abc", raw); got != "jti:abc" {
		t.Errorf("TokenID with a jti = %q, want %q", got, "jti:abc")
	}
	hashed := TokenID("", raw)
	if hashed == raw || len(hashed) < 8 {
		t.Errorf("TokenID without a jti = %q, want a hash of the token", hashed)
	}
	if TokenID("", raw) != hashed {
		t.Error("TokenID without a jti is not stable")
	}
}

func TestPeerIdentityDistinguishesProofFromHint(t *testing.T) {
	tests := []struct {
		thumbprint, host, want string
	}{
		{"AAAA", "10.0.0.1", "cert:AAAA"},
		{"", "10.0.0.1", "ip:10.0.0.1"},
		{"", "", "unknown"},
	}
	for _, tt := range tests {
		if got := PeerIdentity(tt.thumbprint, tt.host); got != tt.want {
			t.Errorf("PeerIdentity(%q, %q) = %q, want %q", tt.thumbprint, tt.host, got, tt.want)
		}
	}
}

// The thresholds in this test are the frozen ones from secops/manifest.json.
func TestSpendAnomalyNeedsRateAndSpendAndARotatedKey(t *testing.T) {
	frozen := SpendThresholds{
		Window:            5 * time.Second,
		MinRequests:       10,
		MinSpendMicros:    2_000_000,
		RequireRotatedKey: true,
	}
	tests := []struct {
		name       string
		requests   int
		perRequest int64
		rotated    bool
		wantEvents int
	}{
		{"the malicious leg: enough requests and enough money", 20, 510_000, true, 1},
		{"the benign leg: same requests, ordinary spend", 20, 2_100, true, 0},
		{"expensive but rare", 4, 5_000_000, true, 0},
		{"fast and cheap", 40, 1_000, true, 0},
		{"an active key spending the same way is not this scenario", 20, 510_000, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &collect{}
			now := time.Unix(1_700_000_000, 0).UTC()
			rec := NewRecorder(Options{Sinks: []Sink{sink}, Now: func() time.Time { return now }, Spend: frozen})
			ctx, _ := tracedContext(t, &reqctx.Info{RequestID: "r", TenantID: "spend-co", KeyID: "kold"})
			for i := 0; i < tt.requests; i++ {
				rec.NoteSpend(ctx, tt.perRequest, tt.rotated)
			}
			if len(sink.events) != tt.wantEvents {
				t.Fatalf("emitted %d provider_anomaly events, want %d", len(sink.events), tt.wantEvents)
			}
			for _, e := range sink.events {
				if e.Type != EventProviderAnomaly || e.Control != ControlSpendAnomaly {
					t.Errorf("unexpected event %+v", e)
				}
				if e.Outcome != OutcomeAllowed {
					t.Errorf("outcome = %q: the detector refuses nothing", e.Outcome)
				}
			}
		})
	}
}

// Requests spread wider than the window are not a spike, however many there
// are: this is what stops a steady well-behaved tenant from being reported
// once its lifetime spend passes the floor.
func TestSpendOutsideTheWindowDoesNotAccumulate(t *testing.T) {
	sink := &collect{}
	now := time.Unix(1_700_000_000, 0).UTC()
	rec := NewRecorder(Options{
		Sinks: []Sink{sink},
		Now:   func() time.Time { return now },
		Spend: SpendThresholds{Window: 5 * time.Second, MinRequests: 10, MinSpendMicros: 2_000_000, RequireRotatedKey: true},
	})
	ctx, _ := tracedContext(t, &reqctx.Info{RequestID: "r", TenantID: "spend-co", KeyID: "kold"})
	for i := 0; i < 40; i++ {
		rec.NoteSpend(ctx, 510_000, true)
		now = now.Add(2 * time.Second) // 2s apart: at most 3 land in any 5s window
	}
	if len(sink.events) != 0 {
		t.Fatalf("emitted %d events for traffic spread past the window, want 0", len(sink.events))
	}
}

// A detector with no thresholds must be off rather than permissive.
func TestZeroSpendThresholdsDisableTheDetector(t *testing.T) {
	if (SpendThresholds{}).Enabled() {
		t.Fatal("a zero SpendThresholds reports itself enabled")
	}
	sink := &collect{}
	rec := NewRecorder(Options{Sinks: []Sink{sink}})
	ctx, _ := tracedContext(t, &reqctx.Info{RequestID: "r", TenantID: "spend-co"})
	for i := 0; i < 100; i++ {
		rec.NoteSpend(ctx, 10_000_000, true)
	}
	if len(sink.events) != 0 {
		t.Fatalf("emitted %d events with no thresholds configured, want 0", len(sink.events))
	}
}

func TestSpendAnomalyFiresOncePerWindow(t *testing.T) {
	sink := &collect{}
	now := time.Unix(1_700_000_000, 0).UTC()
	rec := NewRecorder(Options{
		Sinks: []Sink{sink},
		Now:   func() time.Time { return now },
		Spend: SpendThresholds{Window: 5 * time.Second, MinRequests: 10, MinSpendMicros: 2_000_000, RequireRotatedKey: true},
	})
	ctx, _ := tracedContext(t, &reqctx.Info{RequestID: "r", TenantID: "spend-co", KeyID: "kold"})
	for i := 0; i < 30; i++ {
		rec.NoteSpend(ctx, 510_000, true)
	}
	if len(sink.events) != 1 {
		t.Fatalf("emitted %d events for one sustained window, want 1", len(sink.events))
	}
	now = now.Add(6 * time.Second)
	for i := 0; i < 10; i++ {
		rec.NoteSpend(ctx, 510_000, true)
	}
	if len(sink.events) != 2 {
		t.Fatalf("emitted %d events across two windows, want 2", len(sink.events))
	}
}

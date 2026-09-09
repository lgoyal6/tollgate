package secops

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// frozenManifest loads the committed manifest, so these tests are against the
// rules the evaluation actually runs under rather than against a fixture that
// can drift from them.
func frozenManifest(t *testing.T) *Manifest {
	t.Helper()
	m, err := LoadManifest(filepath.Join("..", "..", "secops", "manifest.json"))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	return m
}

func TestTheFrozenManifestIsLoadableAndComplete(t *testing.T) {
	m := frozenManifest(t)
	if len(m.Scenarios) != 7 {
		t.Fatalf("manifest lists %d scenarios, want 7", len(m.Scenarios))
	}
	if got := len(m.MaliciousScenarios()); got != 6 {
		t.Fatalf("manifest lists %d malicious scenarios, want 6", got)
	}
	for _, key := range []string{
		"stolen_token_replay", "cert_binding_mismatch", "provider_key_anomaly",
		"ssrf_metadata_attempt", "auth_rate_burst", "upstream_timeout_cascade",
		"benign_matched_traffic",
	} {
		if _, ok := m.Scenario(key); !ok {
			t.Errorf("manifest has no scenario %q", key)
		}
	}
	if m.Success.BenignAlerts != 0 || !m.Success.LinkageComplete || !m.Success.Deterministic || !m.Success.FaultCaught {
		t.Errorf("success thresholds are not the frozen ones: %+v", m.Success)
	}
	if len(m.Determinism.Normalization.EvidenceKeys) == 0 {
		t.Error("the manifest names no evidence keys to normalize, so determinism could never hold")
	}
	benign, _ := m.Scenario("benign_matched_traffic")
	if benign.Rule.ExpectedIncidents == nil || *benign.Rule.ExpectedIncidents != 0 {
		t.Error("the benign scenario does not require zero incidents")
	}
}

func TestAManifestWithoutARuleIsRefused(t *testing.T) {
	tests := []struct {
		name string
		m    Manifest
	}{
		{"no version", Manifest{Scenarios: []Scenario{{Key: "x", Malicious: false}}}},
		{"no scenarios", Manifest{Version: 1}},
		{"a malicious scenario matching nothing", Manifest{Version: 1, Scenarios: []Scenario{
			{Key: "x", Malicious: true, Rule: Rule{GroupBy: "tenant", MinEvents: 1}, FailedControl: "c", RecoveryAction: "r"},
		}}},
		{"a malicious scenario with no recovery action", Manifest{Version: 1, Scenarios: []Scenario{
			{Key: "x", Malicious: true, FailedControl: "c", Rule: Rule{
				GroupBy: "tenant", MinEvents: 1, MatchEventTypes: []EventType{EventRateBurst}}},
		}}},
		{"a duplicated scenario key", Manifest{Version: 1, Scenarios: []Scenario{{Key: "x"}, {Key: "x"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.m.validate(); err == nil {
				t.Fatal("validate accepted a manifest that could not produce a result")
			}
		})
	}
}

// linked builds an event that satisfies the linkage requirement, so a test
// asserting a rule is not accidentally asserting linkage as well.
func linked(id int64, at time.Time, typ EventType, tenant string, outcome Outcome, evidence map[string]string) Event {
	return Event{
		ID: id, At: at, Type: typ, TenantID: tenant, TraceID: "trace-" + tenant,
		SpanID: "span", RequestID: "req", Route: "/api/", Control: "some_control",
		Outcome: outcome, Evidence: evidence,
	}
}

func TestCorrelateAppliesTheFrozenRules(t *testing.T) {
	m := frozenManifest(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	upstream := map[string]string{"upstream_host": "127.0.0.1:9001"}

	tests := []struct {
		name         string
		events       []Event
		wantScenario string
		wantDelayMS  int64
		wantTenants  int
	}{
		{
			name: "one token replay is an incident",
			events: []Event{
				linked(1, base, EventTokenReplay, "replay-co", OutcomeAllowed, nil),
			},
			wantScenario: "stolen_token_replay",
		},
		{
			name: "one certificate mismatch is an incident",
			events: []Event{
				linked(1, base, EventCertMismatch, "bind-co", OutcomeRejected, nil),
			},
			wantScenario: "cert_binding_mismatch",
		},
		{
			name: "one refused metadata upstream is an incident",
			events: []Event{
				linked(1, base, EventSSRFRejected, "meta-co", OutcomeRejected, nil),
			},
			wantScenario: "ssrf_metadata_attempt",
		},
		{
			name: "grace-key use plus a spend spike is an incident, timed from the first key use",
			events: append(
				keyRotationRun(1, base, 12, "spend-co"),
				linked(13, base.Add(900*time.Millisecond), EventProviderAnomaly, "spend-co", OutcomeAllowed, nil),
			),
			wantScenario: "provider_key_anomaly",
			wantDelayMS:  900,
		},
		{
			name:         "ten refusals inside the window is a burst",
			events:       burstRun(1, base, 10, "burst-co", 40*time.Millisecond),
			wantScenario: "auth_rate_burst",
			wantDelayMS:  360,
		},
		{
			name: "three timeouts then a fallback is a cascade, across every tenant on that upstream",
			events: []Event{
				linked(1, base, EventUpstreamTimeoutCascade, "cascade-a", OutcomeTimedOut, upstream),
				linked(2, base.Add(50*time.Millisecond), EventUpstreamTimeoutCascade, "cascade-a", OutcomeTimedOut, upstream),
				linked(3, base.Add(100*time.Millisecond), EventUpstreamTimeoutCascade, "cascade-b", OutcomeTimedOut, upstream),
				linked(4, base.Add(250*time.Millisecond), EventUpstreamTimeoutCascade, "cascade-b", OutcomeFellBack, upstream),
			},
			wantScenario: "upstream_timeout_cascade",
			wantDelayMS:  250,
			wantTenants:  2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Correlate(tt.events, m)
			if len(got) != 1 {
				t.Fatalf("correlated %d incidents, want 1: %+v", len(got), got)
			}
			inc := got[0]
			if inc.Scenario != tt.wantScenario {
				t.Fatalf("scenario = %q, want %q", inc.Scenario, tt.wantScenario)
			}
			if inc.DetectionDelayMS != tt.wantDelayMS {
				t.Errorf("detection_delay_ms = %d, want %d", inc.DetectionDelayMS, tt.wantDelayMS)
			}
			wantTenants := tt.wantTenants
			if wantTenants == 0 {
				wantTenants = 1
			}
			if inc.AffectedTenantCount != wantTenants {
				t.Errorf("affected_tenant_count = %d, want %d", inc.AffectedTenantCount, wantTenants)
			}
			if !inc.LinkageComplete {
				t.Errorf("linkage incomplete on fully linked events: missing %v", inc.MissingLinkage)
			}
			sc, _ := m.Scenario(tt.wantScenario)
			if inc.FailedControl != sc.FailedControl || inc.RecoveryAction != sc.RecoveryAction {
				t.Errorf("incident does not carry the manifest's control and action: %+v", inc)
			}
			if len(inc.EvidenceEventIDs) != len(tt.events) {
				t.Errorf("evidence links %d events, want all %d", len(inc.EvidenceEventIDs), len(tt.events))
			}
		})
	}
}

func keyRotationRun(startID int64, base time.Time, n int, tenant string) []Event {
	var out []Event
	for i := 0; i < n; i++ {
		out = append(out, linked(startID+int64(i), base.Add(time.Duration(i)*20*time.Millisecond),
			EventKeyRotation, tenant, OutcomeAllowed, nil))
	}
	return out
}

func burstRun(startID int64, base time.Time, n int, tenant string, gap time.Duration) []Event {
	var out []Event
	for i := 0; i < n; i++ {
		out = append(out, linked(startID+int64(i), base.Add(time.Duration(i)*gap),
			EventAuthRejected, tenant, OutcomeRejected, nil))
	}
	return out
}

// Below the threshold there is no incident. This is the half of a detection
// rule that decides whether the benign replay is quiet, and it is the half
// that never gets tested.
func TestCorrelateStaysSilentBelowTheThresholds(t *testing.T) {
	m := frozenManifest(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	upstream := map[string]string{"upstream_host": "127.0.0.1:9001"}

	tests := []struct {
		name   string
		events []Event
	}{
		{"nine refusals is not a burst", burstRun(1, base, 9, "burst-co", 40*time.Millisecond)},
		{"ten refusals spread past the window is not a burst",
			burstRun(1, base, 10, "burst-co", 2*time.Second)},
		{"grace-key use with no spend spike is not an anomaly",
			keyRotationRun(1, base, 40, "spend-co")},
		{"timeouts with no fallback is not this cascade", []Event{
			linked(1, base, EventUpstreamTimeoutCascade, "cascade-a", OutcomeTimedOut, upstream),
			linked(2, base.Add(time.Millisecond), EventUpstreamTimeoutCascade, "cascade-a", OutcomeTimedOut, upstream),
			linked(3, base.Add(2*time.Millisecond), EventUpstreamTimeoutCascade, "cascade-a", OutcomeTimedOut, upstream),
		}},
		{"a fallback with no timeouts before it is not a cascade", []Event{
			linked(1, base, EventUpstreamTimeoutCascade, "cascade-a", OutcomeFellBack, upstream),
		}},
		{"nothing at all", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Correlate(tt.events, m); len(got) != 0 {
				t.Fatalf("correlated %d incidents below the threshold: %+v", len(got), got)
			}
		})
	}
}

// The linkage check has to be able to fail, or the evaluation's headline
// number is decoration. This is the same edge the planted build tag breaks.
func TestAnEventWithNoTraceMakesTheIncidentIncomplete(t *testing.T) {
	m := frozenManifest(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	e := linked(1, base, EventCertMismatch, "bind-co", OutcomeRejected, nil)
	e.TraceID = ""

	got := Correlate([]Event{e}, m)
	if len(got) != 1 {
		t.Fatalf("correlated %d incidents, want 1", len(got))
	}
	if got[0].LinkageComplete {
		t.Fatal("an incident whose only evidence has no trace id reported complete linkage")
	}
	if !reflect.DeepEqual(got[0].MissingLinkage, []string{"trace_id"}) {
		t.Errorf("missing_linkage = %v, want [trace_id]", got[0].MissingLinkage)
	}
}

// Correlation must not depend on the order events are handed over, or two
// runs of the same replay could disagree.
func TestCorrelateIsOrderIndependent(t *testing.T) {
	m := frozenManifest(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	events := burstRun(1, base, 12, "burst-co", 30*time.Millisecond)
	forward := Correlate(events, m)

	reversed := make([]Event, len(events))
	for i, e := range events {
		reversed[len(events)-1-i] = e
	}
	if got := Correlate(reversed, m); !reflect.DeepEqual(got, forward) {
		t.Fatalf("correlation depends on input order:\n%+v\n%+v", forward, got)
	}
}

// The gateway cannot read the manifest at runtime, so the thresholds it
// enforces are written twice. This is the test that stops the two copies
// drifting: a number changed in one place and not the other fails here
// rather than in a report nobody re-derives.
func TestTheCodeAndTheManifestAgree(t *testing.T) {
	m := frozenManifest(t)

	fromManifest, err := m.SpendThresholdsFromManifest()
	if err != nil {
		t.Fatalf("SpendThresholdsFromManifest: %v", err)
	}
	if got := FrozenSpendThresholds(); got != fromManifest {
		t.Errorf("the spend thresholds in code are %+v, the manifest says %+v", got, fromManifest)
	}

	capacity, err := m.ReplayCapacityFromManifest()
	if err != nil {
		t.Fatalf("ReplayCapacityFromManifest: %v", err)
	}
	if capacity != defaultReplayCapacity {
		t.Errorf("the replay filter capacity in code is %d, the manifest says %d", defaultReplayCapacity, capacity)
	}
}

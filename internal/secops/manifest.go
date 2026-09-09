package secops

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Manifest is secops/manifest.json: the evaluation design, frozen and
// committed before any detection code existed.
//
// The correlator reads its rules from here rather than carrying them in Go
// constants, so there is exactly one copy of every threshold and it is the
// one in version control. A rule that only lives in code can be adjusted in
// the same commit that reports the result it produces, and then the result
// means nothing.
type Manifest struct {
	Version          int              `json:"manifest_version"`
	Name             string           `json:"name"`
	FrozenAt         string           `json:"frozen_at"`
	EvidenceBoundary EvidenceBoundary `json:"evidence_boundary"`
	Linkage          LinkageSpec      `json:"linkage"`
	Determinism      Determinism      `json:"determinism"`
	Success          Success          `json:"success_thresholds"`
	Scenarios        []Scenario       `json:"scenarios"`
}

type EvidenceBoundary struct {
	RunsOn     string   `json:"runs_on"`
	Traffic    string   `json:"traffic"`
	NotClaimed []string `json:"not_claimed"`
}

type LinkageSpec struct {
	RequiredFields []string `json:"required_fields_on_every_evidence_event"`
}

type Determinism struct {
	Definition    string        `json:"definition"`
	Normalization Normalization `json:"normalization"`
	Requirement   string        `json:"requirement"`
}

type Normalization struct {
	EvidenceKeys []string `json:"normalized_evidence_keys"`
}

type Success struct {
	Malicious       string `json:"malicious_scenarios_detected"`
	BenignAlerts    int    `json:"benign_alerts"`
	LinkageComplete bool   `json:"linkage_complete_on_every_incident"`
	Deterministic   bool   `json:"normalized_replay_deterministic"`
	FaultCaught     bool   `json:"planted_negative_control_caught"`
}

// Scenario is one row of the evaluation.
type Scenario struct {
	Key             string   `json:"key"`
	Ordinal         int      `json:"ordinal"`
	Title           string   `json:"title"`
	Malicious       bool     `json:"malicious"`
	ExpectedTypes   []string `json:"expected_event_types"`
	Rule            Rule     `json:"rule"`
	FailedControl   string   `json:"failed_control"`
	RecoveryAction  string   `json:"recovery_action"`
	RequiredFields  []string `json:"required_linkage_fields"`
	ExpectedOutcome string   `json:"expected_outcome"`
	// DetectorThresholds is the scenario's own detector configuration, kept
	// untyped because each detector's block is a different shape and the
	// manifest is a published document rather than a Go struct.
	DetectorThresholds map[string]any `json:"detector_thresholds"`
}

// Rule is the frozen detection rule for one scenario.
type Rule struct {
	// GroupBy is what makes two events part of the same incident: "tenant",
	// "upstream" or "route".
	GroupBy string `json:"group_by"`
	// MatchEventTypes is which events belong to this scenario at all.
	MatchEventTypes []EventType `json:"match_event_types"`
	// MinEvents is how many matching events the group needs.
	MinEvents int `json:"min_events"`
	// WindowMS bounds how far apart those events may be. Zero means no
	// window: the count alone decides.
	WindowMS int64 `json:"window_ms"`
	// RequireEventType, when set, is the event that satisfies the rule. Used
	// where a scenario has supporting events plus one that is the finding.
	RequireEventType EventType `json:"require_event_type"`
	// RequireOutcome, when set, is an outcome that must appear in the group,
	// and the event carrying it is what satisfies the rule.
	RequireOutcome Outcome `json:"require_outcome"`
	// MinEventsWithOutcome is a floor on one outcome before RequireOutcome
	// counts, so "it fell back" is only a cascade if something timed out
	// first.
	MinEventsWithOutcome *OutcomeCount `json:"min_events_with_outcome"`
	// ExpectedIncidents is set only on the benign scenario, where the whole
	// rule is that there are none.
	ExpectedIncidents *int `json:"expected_incidents"`
}

type OutcomeCount struct {
	Outcome Outcome `json:"outcome"`
	Count   int     `json:"count"`
}

// Window is WindowMS as a duration.
func (r Rule) Window() time.Duration { return time.Duration(r.WindowMS) * time.Millisecond }

// LoadManifest reads and validates the frozen manifest.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secops: reading manifest: %w", err)
	}
	// Unknown fields are tolerated on purpose: the manifest also carries the
	// prose an operator reads - why each control was chosen, what the
	// evaluation does not claim - and a new note in it must not stop the
	// harness. What must not be tolerated is a MISSING rule, which validate
	// below refuses.
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("secops: parsing manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// validate refuses a manifest that could not produce a meaningful result.
func (m *Manifest) validate() error {
	if m.Version == 0 {
		return fmt.Errorf("secops: manifest has no manifest_version")
	}
	if len(m.Scenarios) == 0 {
		return fmt.Errorf("secops: manifest lists no scenarios")
	}
	seen := make(map[string]bool, len(m.Scenarios))
	for _, s := range m.Scenarios {
		if s.Key == "" {
			return fmt.Errorf("secops: a scenario has no key")
		}
		if seen[s.Key] {
			return fmt.Errorf("secops: scenario %q is listed twice", s.Key)
		}
		seen[s.Key] = true
		if !s.Malicious {
			continue
		}
		if len(s.Rule.MatchEventTypes) == 0 {
			return fmt.Errorf("secops: scenario %q matches no event types", s.Key)
		}
		if s.Rule.MinEvents < 1 {
			return fmt.Errorf("secops: scenario %q has min_events %d", s.Key, s.Rule.MinEvents)
		}
		if s.Rule.GroupBy == "" {
			return fmt.Errorf("secops: scenario %q has no group_by", s.Key)
		}
		if s.FailedControl == "" || s.RecoveryAction == "" {
			return fmt.Errorf("secops: scenario %q has no failed_control or recovery_action", s.Key)
		}
	}
	return nil
}

// Scenario finds one scenario by key.
func (m *Manifest) Scenario(key string) (Scenario, bool) {
	for _, s := range m.Scenarios {
		if s.Key == key {
			return s, true
		}
	}
	return Scenario{}, false
}

// MaliciousScenarios is the set the detection rate is measured over.
func (m *Manifest) MaliciousScenarios() []Scenario {
	var out []Scenario
	for _, s := range m.Scenarios {
		if s.Malicious {
			out = append(out, s)
		}
	}
	return out
}

// FrozenSpendThresholds is the provider spend anomaly rule, in code.
//
// It is duplicated from secops/manifest.json on purpose: the gateway must not
// read a repository file at runtime to decide what an anomaly is. The
// duplication is held honest by TestTheCodeAndTheManifestAgree, which fails
// if the two ever differ, so there is no version of this where the shipped
// numbers and the published ones drift apart quietly.
func FrozenSpendThresholds() SpendThresholds {
	return SpendThresholds{
		Window:            5 * time.Second,
		MinRequests:       10,
		MinSpendMicros:    2_000_000,
		RequireRotatedKey: true,
	}
}

// SpendThresholdsFromManifest reads the same rule out of the manifest, so a
// test can compare the two.
func (m *Manifest) SpendThresholdsFromManifest() (SpendThresholds, error) {
	sc, ok := m.Scenario("provider_key_anomaly")
	if !ok {
		return SpendThresholds{}, fmt.Errorf("secops: manifest has no provider_key_anomaly scenario")
	}
	var out SpendThresholds
	ms, err := numberFrom(sc.DetectorThresholds, "window_ms")
	if err != nil {
		return out, err
	}
	out.Window = time.Duration(ms) * time.Millisecond
	requests, err := numberFrom(sc.DetectorThresholds, "min_requests_in_window")
	if err != nil {
		return out, err
	}
	out.MinRequests = int(requests)
	micros, err := numberFrom(sc.DetectorThresholds, "min_spend_micros_in_window")
	if err != nil {
		return out, err
	}
	out.MinSpendMicros = micros
	rotated, ok := sc.DetectorThresholds["requires_rotated_or_grace_key"].(bool)
	if !ok {
		return out, fmt.Errorf("secops: manifest provider_key_anomaly has no requires_rotated_or_grace_key")
	}
	out.RequireRotatedKey = rotated
	return out, nil
}

// ReplayCapacityFromManifest is the token replay filter's frozen bound.
func (m *Manifest) ReplayCapacityFromManifest() (int, error) {
	sc, ok := m.Scenario("stolen_token_replay")
	if !ok {
		return 0, fmt.Errorf("secops: manifest has no stolen_token_replay scenario")
	}
	n, err := numberFrom(sc.DetectorThresholds, "replay_filter_capacity")
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// numberFrom reads one JSON number out of a threshold block.
func numberFrom(block map[string]any, key string) (int64, error) {
	raw, ok := block[key]
	if !ok {
		return 0, fmt.Errorf("secops: manifest threshold %q is missing", key)
	}
	f, ok := raw.(float64)
	if !ok {
		return 0, fmt.Errorf("secops: manifest threshold %q is %T, want a number", key, raw)
	}
	return int64(f), nil
}

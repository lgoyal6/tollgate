package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lgoyal6/tollgate/internal/secops"
)

// Report is results/security-ops-eval.json.
//
// Everything a reader needs to disbelieve it: which manifest produced it and
// its hash, what the harness actually sent, what was detected and what was
// not, and the boundary the whole thing sits inside.
type Report struct {
	GeneratedBy       string           `json:"generated_by"`
	Manifest          ManifestRef      `json:"manifest"`
	EvidenceBoundary  BoundaryRef      `json:"evidence_boundary"`
	Harness           HarnessRef       `json:"harness"`
	Scenarios         []ScenarioResult `json:"scenarios"`
	BenignReplay      BenignResult     `json:"benign_replay"`
	Determinism       DeterminismRef   `json:"determinism"`
	TimelineIntegrity TimelineRef      `json:"timeline_integrity"`
	DetectionDelay    DelaySummary     `json:"detection_delay_ms"`
	Thresholds        []ThresholdCheck `json:"frozen_thresholds"`
	PlantedFault      PlantedFaultRef  `json:"planted_negative_control"`
	Pass              bool             `json:"pass"`
}

type ManifestRef struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Version  int    `json:"manifest_version"`
	FrozenAt string `json:"frozen_at"`
}

type BoundaryRef struct {
	RunsOn     string   `json:"runs_on"`
	Traffic    string   `json:"traffic"`
	NotClaimed []string `json:"not_claimed"`
}

type HarnessRef struct {
	Chain             string `json:"middleware_chain"`
	ChainOmission     string `json:"middleware_omitted"`
	BreakerMinSamples int    `json:"breaker_min_requests"`
	BreakerCooldownMS int64  `json:"breaker_cooldown_ms"`
	BurstPolicy       string `json:"burst_tenant_policy"`
	Tracing           string `json:"tracing"`
	Storage           string `json:"storage"`
}

// ScenarioResult is one row of the evaluation.
type ScenarioResult struct {
	Key                 string            `json:"scenario"`
	Ordinal             int               `json:"ordinal"`
	Title               string            `json:"title"`
	Detected            bool              `json:"detected"`
	DetectionDelayMS    int64             `json:"detection_delay_ms"`
	AffectedTenants     []string          `json:"affected_tenants"`
	AffectedTenantCount int               `json:"affected_tenant_count"`
	FailedControl       string            `json:"failed_control"`
	ControlOutcome      string            `json:"control_outcome"`
	ControlHeld         bool              `json:"control_held"`
	RecoveryAction      string            `json:"recovery_action"`
	EvidenceEventIDs    []int64           `json:"evidence_event_ids"`
	EvidenceTraceIDs    []string          `json:"evidence_trace_ids"`
	LinkageComplete     bool              `json:"linkage_complete"`
	MissingLinkage      []string          `json:"missing_linkage,omitempty"`
	EventsObserved      int               `json:"events_observed"`
	RequestsSent        int               `json:"requests_sent"`
	ResponseStatuses    []int             `json:"response_statuses"`
	Notes               []string          `json:"notes"`
	Incidents           []secops.Incident `json:"incidents"`
}

type BenignResult struct {
	Alerts            int               `json:"alerts"`
	Incidents         []secops.Incident `json:"incidents"`
	RequestsSent      int               `json:"requests_sent"`
	EventsObserved    int               `json:"events_observed"`
	MatchedOnRequests bool              `json:"request_count_matches_malicious"`
	PerScenario       []BenignLeg       `json:"per_scenario"`
}

type BenignLeg struct {
	Scenario       string   `json:"scenario"`
	RequestsSent   int      `json:"requests_sent"`
	EventsObserved int      `json:"events_observed"`
	Alerts         int      `json:"alerts"`
	Notes          []string `json:"notes"`
}

type DeterminismRef struct {
	Runs       int    `json:"runs"`
	Identical  bool   `json:"normalized_timelines_identical"`
	DigestSHA  string `json:"normalized_digest_sha256"`
	Difference string `json:"first_difference,omitempty"`
}

type TimelineRef struct {
	Path           string `json:"path"`
	EventsRecorded int    `json:"events_recorded"`
	EventsRebuilt  int    `json:"events_rebuilt_from_log"`
	RebuildMatches bool   `json:"rebuild_matches_memory"`
}

type DelaySummary struct {
	Median int64  `json:"median_across_malicious_scenarios"`
	Max    int64  `json:"max_across_malicious_scenarios"`
	Note   string `json:"note"`
}

type ThresholdCheck struct {
	Name     string `json:"threshold"`
	Required string `json:"required"`
	Observed string `json:"observed"`
	Pass     bool   `json:"pass"`
}

type PlantedFaultRef struct {
	Active bool   `json:"active_in_this_build"`
	Note   string `json:"note"`
}

// evaluation is everything a report is built from.
type evaluation struct {
	Manifest     *secops.Manifest
	ManifestPath string
	TimelinePath string
	Passes       []pass
	InMemory     []secops.Event
	Rebuilt      []secops.Event
}

func evaluate(in evaluation) (*Report, bool) {
	m := in.Manifest
	malicious := findPass(in.Passes, "malicious", 1)
	benign := findPass(in.Passes, "benign", 1)

	report := &Report{
		GeneratedBy: "cmd/tollgate-secops-replay",
		Manifest: ManifestRef{
			Path:     in.ManifestPath,
			SHA256:   fileSHA256(in.ManifestPath),
			Version:  m.Version,
			FrozenAt: m.FrozenAt,
		},
		EvidenceBoundary: BoundaryRef{
			RunsOn:     m.EvidenceBoundary.RunsOn,
			Traffic:    m.EvidenceBoundary.Traffic,
			NotClaimed: m.EvidenceBoundary.NotClaimed,
		},
		Harness: HarnessRef{
			Chain: "Recover, secops.Observe, RequestID, Metrics, Tracing, Auth, Router, " +
				"RequestSize, RateLimit, Concurrency, Budget, proxy",
			ChainOmission:     "CurrentAuthorization: it is a targeted Postgres query and these commands run with no database",
			BreakerMinSamples: harnessBreakerConfig().MinRequests,
			BreakerCooldownMS: harnessBreakerConfig().Cooldown.Milliseconds(),
			BurstPolicy:       "sliding window log, 6 requests per 250ms, identical in both legs",
			Tracing:           "OpenTelemetry SDK tracer with no exporter: real span contexts, nothing leaves the process",
			Storage:           "in-memory config snapshot, in-memory rate limiter, in-memory budget ledger, httptest upstreams",
		},
		PlantedFault: PlantedFaultRef{
			Active: secops.PlantedFaultActive,
			Note: "true only in a build carrying -tags secops_planted_fault, which strips the trace id " +
				"from cert_mismatch events so the linkage check can be shown to be able to fail",
		},
	}

	maliciousIncidents := secops.Correlate(malicious.Events, m)
	benignIncidents := secops.Correlate(benign.Events, m)

	var delays []int64
	for _, sc := range m.MaliciousScenarios() {
		leg := findLeg(malicious, sc.Key)
		row := ScenarioResult{
			Key: sc.Key, Ordinal: sc.Ordinal, Title: sc.Title,
			FailedControl:    sc.FailedControl,
			RecoveryAction:   sc.RecoveryAction,
			RequestsSent:     leg.Requests,
			ResponseStatuses: leg.Statuses,
			Notes:            leg.Notes,
			EventsObserved:   len(leg.Events),
			LinkageComplete:  true,
		}
		row.Incidents = incidentsWithin(maliciousIncidents, sc.Key, leg.FirstEventID, leg.LastEventID)
		if len(row.Incidents) > 0 {
			primary := row.Incidents[0]
			row.Detected = true
			row.DetectionDelayMS = primary.DetectionDelayMS
			row.AffectedTenants = primary.AffectedTenants
			row.AffectedTenantCount = primary.AffectedTenantCount
			row.ControlOutcome = primary.ControlOutcome
			row.ControlHeld = primary.ControlOutcome == string(secops.OutcomeRejected)
			row.EvidenceEventIDs = primary.EvidenceEventIDs
			row.EvidenceTraceIDs = primary.EvidenceTraceIDs
			for _, inc := range row.Incidents {
				if !inc.LinkageComplete {
					row.LinkageComplete = false
					row.MissingLinkage = appendUnique(row.MissingLinkage, inc.MissingLinkage...)
				}
			}
			delays = append(delays, primary.DetectionDelayMS)
		} else {
			row.LinkageComplete = false
			row.MissingLinkage = append(row.MissingLinkage, "no incident: nothing to link")
		}
		report.Scenarios = append(report.Scenarios, row)
	}

	report.BenignReplay = benignResult(benign, benignIncidents)
	report.BenignReplay.MatchedOnRequests = totalRequests(benign) == totalRequests(malicious)

	report.Determinism = determinism(in.Passes, m)
	report.TimelineIntegrity = TimelineRef{
		Path:           in.TimelinePath,
		EventsRecorded: len(in.InMemory),
		EventsRebuilt:  len(in.Rebuilt),
		RebuildMatches: sameTimeline(in.InMemory, in.Rebuilt),
	}
	report.DetectionDelay = DelaySummary{
		Median: median(delays),
		Max:    maxOf(delays),
		Note: "milliseconds from the first event of an incident to the event that satisfied its rule, " +
			"inside a script that controls its own timing. It is not a measurement of how fast anybody " +
			"would notice: there is no alerting path and no human here. Scenarios whose rule is satisfied " +
			"by their own first event are 0 ms by construction, which the manifest says up front.",
	}
	report.Thresholds = checkThresholds(report, m)
	report.Pass = true
	for _, t := range report.Thresholds {
		if !t.Pass {
			report.Pass = false
		}
	}
	return report, report.Pass
}

func benignResult(p pass, incidents []secops.Incident) BenignResult {
	out := BenignResult{Alerts: len(incidents), Incidents: incidents}
	for _, leg := range p.Legs {
		out.RequestsSent += leg.Requests
		out.EventsObserved += len(leg.Events)
		out.PerScenario = append(out.PerScenario, BenignLeg{
			Scenario:       leg.Scenario,
			RequestsSent:   leg.Requests,
			EventsObserved: len(leg.Events),
			Alerts:         len(incidentsWithin(incidents, "", leg.FirstEventID, leg.LastEventID)),
			Notes:          leg.Notes,
		})
	}
	if out.Incidents == nil {
		out.Incidents = []secops.Incident{}
	}
	return out
}

// determinism normalizes both runs leg by leg and compares them byte for
// byte.
func determinism(passes []pass, m *secops.Manifest) DeterminismRef {
	keys := m.Determinism.Normalization.EvidenceKeys
	digests := make([]string, 0, 2)
	for run := 1; run <= 2; run++ {
		var legsOut []secops.NormalizedLeg
		for _, name := range []string{"malicious", "benign"} {
			p := findPass(passes, name, run)
			for _, leg := range p.Legs {
				lines, err := secops.Normalize(leg.Events, keys)
				if err != nil {
					return DeterminismRef{Runs: 2, Identical: false, Difference: err.Error()}
				}
				legsOut = append(legsOut, secops.NormalizedLeg{
					Scenario: name + "/" + leg.Scenario,
					Lines:    lines,
				})
			}
		}
		digests = append(digests, secops.NormalizedDigest(legsOut))
	}
	out := DeterminismRef{Runs: 2, Identical: digests[0] == digests[1]}
	sum := sha256.Sum256([]byte(digests[0]))
	out.DigestSHA = hex.EncodeToString(sum[:])
	if !out.Identical {
		out.Difference = firstDifference(digests[0], digests[1])
	}
	return out
}

func firstDifference(a, b string) string {
	linesA, linesB := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(linesA) && i < len(linesB); i++ {
		if linesA[i] != linesB[i] {
			return fmt.Sprintf("line %d:\n  run 1: %s\n  run 2: %s", i+1, linesA[i], linesB[i])
		}
	}
	return fmt.Sprintf("run 1 has %d lines, run 2 has %d", len(linesA), len(linesB))
}

func checkThresholds(r *Report, m *secops.Manifest) []ThresholdCheck {
	detected := 0
	linkageComplete := true
	for _, s := range r.Scenarios {
		if s.Detected {
			detected++
		}
		if !s.LinkageComplete {
			linkageComplete = false
		}
	}
	total := len(m.MaliciousScenarios())
	return []ThresholdCheck{
		{
			Name:     "malicious scenarios detected",
			Required: m.Success.Malicious,
			Observed: fmt.Sprintf("%d of %d", detected, total),
			Pass:     detected == total,
		},
		{
			Name:     "alerts on the matched benign replay",
			Required: fmt.Sprintf("%d", m.Success.BenignAlerts),
			Observed: fmt.Sprintf("%d", r.BenignReplay.Alerts),
			Pass:     r.BenignReplay.Alerts == m.Success.BenignAlerts,
		},
		{
			Name:     "tenant, trace, control and outcome on every incident",
			Required: "complete",
			Observed: passFail(linkageComplete, "complete", "incomplete"),
			Pass:     linkageComplete,
		},
		{
			Name:     "normalized replay identical across two runs",
			Required: "identical",
			Observed: passFail(r.Determinism.Identical, "identical", "different"),
			Pass:     r.Determinism.Identical,
		},
		{
			Name:     "the timeline rebuilt from its own log matches what was recorded",
			Required: "matches",
			Observed: passFail(r.TimelineIntegrity.RebuildMatches, "matches", "differs"),
			Pass:     r.TimelineIntegrity.RebuildMatches,
		},
		{
			Name:     "the benign replay sent the same number of requests as the attack",
			Required: "equal",
			Observed: passFail(r.BenignReplay.MatchedOnRequests, "equal", "different"),
			Pass:     r.BenignReplay.MatchedOnRequests,
		},
	}
}

func passFail(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func findPass(passes []pass, name string, run int) pass {
	for _, p := range passes {
		if p.Name == name && p.Run == run {
			return p
		}
	}
	return pass{Name: name, Run: run}
}

func findLeg(p pass, scenario string) legRecord {
	for _, leg := range p.Legs {
		if leg.Scenario == scenario {
			return leg
		}
	}
	return legRecord{legOutcome: legOutcome{Scenario: scenario}}
}

// incidentsWithin keeps the incidents whose first event came from one leg, so
// a scenario is credited with what it actually caused rather than with
// anything that happens to share its event types.
func incidentsWithin(incidents []secops.Incident, scenario string, firstID, lastID int64) []secops.Incident {
	out := []secops.Incident{}
	for _, inc := range incidents {
		if scenario != "" && inc.Scenario != scenario {
			continue
		}
		if inc.FirstEventID < firstID || inc.FirstEventID > lastID {
			continue
		}
		out = append(out, inc)
	}
	return out
}

func totalRequests(p pass) int {
	total := 0
	for _, leg := range p.Legs {
		total += leg.Requests
	}
	return total
}

func sameTimeline(a, b []secops.Event) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Type != b[i].Type || a[i].TenantID != b[i].TenantID ||
			a[i].TraceID != b[i].TraceID || a[i].Control != b[i].Control || a[i].Outcome != b[i].Outcome {
			return false
		}
		if !a[i].At.Equal(b[i].At) {
			return false
		}
	}
	return true
}

func median(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func maxOf(values []int64) int64 {
	var out int64
	for _, v := range values {
		if v > out {
			out = v
		}
	}
	return out
}

func appendUnique(dst []string, values ...string) []string {
	for _, v := range values {
		found := false
		for _, existing := range dst {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}

func fileSHA256(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// writeArtifacts writes the evaluation and the human-readable summary. The
// timeline is already on disk: it was written as the events happened, which
// is the only way an append-only log means anything.
func writeArtifacts(dir string, r *Report) error {
	blob, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("replay: encoding the evaluation: %w", err)
	}
	blob = append(blob, '\n')
	if err := os.WriteFile(filepath.Join(dir, "security-ops-eval.json"), blob, 0o644); err != nil {
		return fmt.Errorf("replay: writing the evaluation: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "security-ops-report.md"), []byte(renderMarkdown(r)), 0o644); err != nil {
		return fmt.Errorf("replay: writing the report: %w", err)
	}
	return nil
}

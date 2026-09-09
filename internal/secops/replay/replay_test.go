package replay

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/lgoyal6/tollgate/internal/secops"
)

const manifestPath = "../../../secops/manifest.json"

// Every malicious scenario in the manifest has to have a leg that produces
// it, and every leg has to correspond to a scenario. Without this, adding a
// scenario to the manifest and forgetting the leg would show up as an
// undetected scenario, and deleting a leg would show up as a passing run with
// one fewer row.
func TestEveryMaliciousScenarioHasALeg(t *testing.T) {
	m, err := secops.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	fx, err := newFixtures()
	if err != nil {
		t.Fatalf("newFixtures: %v", err)
	}
	defer fx.close()
	h, err := newHarness(fx, secops.NewRecorder(secops.Options{}))
	if err != nil {
		t.Fatalf("newHarness: %v", err)
	}

	inManifest := map[string]bool{}
	for _, sc := range m.MaliciousScenarios() {
		inManifest[sc.Key] = true
	}
	inHarness := map[string]bool{}
	for _, leg := range legs() {
		// The benign pass is the cheap one to probe with: it sends the same
		// requests without the attack, so this stays fast.
		out, err := leg(h, false)
		if err != nil {
			t.Fatalf("leg %s: %v", out.Scenario, err)
		}
		if out.Scenario == "" {
			t.Fatal("a leg reported no scenario key")
		}
		if out.Requests == 0 {
			t.Errorf("leg %s sent no requests", out.Scenario)
		}
		if len(out.Notes) == 0 {
			t.Errorf("leg %s says nothing about what it sent", out.Scenario)
		}
		inHarness[out.Scenario] = true
	}
	for key := range inManifest {
		if !inHarness[key] {
			t.Errorf("the manifest has scenario %q and the harness has no leg for it", key)
		}
	}
	for key := range inHarness {
		if !inManifest[key] {
			t.Errorf("the harness has a leg for %q and the manifest does not list it", key)
		}
	}
}

// The whole evaluation, end to end. It is the slowest test in the repository
// and it earns that: it is the one that fails if the detection layer stops
// detecting, if the benign replay starts alerting, if the timeline stops
// matching its own log, or if the replay stops being deterministic.
func TestTheReplayPassesItsFrozenThresholds(t *testing.T) {
	out := t.TempDir()
	report, ok, err := Run(Options{ManifestPath: manifestPath, OutDir: out, Progress: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ok {
		for _, threshold := range report.Thresholds {
			if !threshold.Pass {
				t.Errorf("threshold %q: required %s, observed %s",
					threshold.Name, threshold.Required, threshold.Observed)
			}
		}
		t.Fatal("the replay did not pass its frozen thresholds")
	}

	for _, s := range report.Scenarios {
		if !s.Detected {
			t.Errorf("scenario %s was not detected", s.Key)
		}
		if !s.LinkageComplete {
			t.Errorf("scenario %s has incomplete linkage: %v", s.Key, s.MissingLinkage)
		}
		if s.RecoveryAction == "" || s.FailedControl == "" {
			t.Errorf("scenario %s has no recovery action or failed control", s.Key)
		}
	}
	if report.BenignReplay.Alerts != 0 {
		t.Errorf("the benign replay raised %d alerts", report.BenignReplay.Alerts)
	}
	if report.BenignReplay.EventsObserved == 0 {
		t.Error("the benign replay produced no events at all, so it is not exercising the rules that must decline to fire")
	}
	if !report.Determinism.Identical {
		t.Errorf("the normalized replay differs between runs: %s", report.Determinism.Difference)
	}
	if secops.PlantedFaultActive {
		t.Error("this build carries the planted fault and still passed")
	}

	// The cascade is the one scenario whose evidence spans tenants, because
	// the breaker it observes is shared by every tenant on that upstream. If
	// that stops being true the scenario still passes and quietly stops
	// showing the thing it exists to show.
	cascade, ok := scenarioNamed(report, "upstream_timeout_cascade")
	if !ok {
		t.Fatal("the report has no upstream_timeout_cascade scenario")
	}
	if cascade.AffectedTenantCount < 2 {
		t.Errorf("the cascade affected %d tenant(s), want the shared breaker to show both",
			cascade.AffectedTenantCount)
	}
	if cascade.ControlOutcome != string(secops.OutcomeFellBack) {
		t.Errorf("the cascade's detection outcome is %q, want the fallback that ended it",
			cascade.ControlOutcome)
	}

	// The replay scenario has to end in "allowed", or the harness has stopped
	// telling the truth about what an unbound token costs.
	replayed, ok := scenarioNamed(report, "stolen_token_replay")
	if !ok {
		t.Fatal("the report has no stolen_token_replay scenario")
	}
	if replayed.ControlHeld {
		t.Error("the stolen token was refused, so this scenario is no longer showing that an unbound token is not")
	}

	for _, name := range []string{
		"security-ops-timeline.jsonl", "security-ops-eval.json", "security-ops-report.md",
	} {
		if _, err := readFile(filepath.Join(out, name)); err != nil {
			t.Errorf("artifact %s: %v", name, err)
		}
	}
}

func scenarioNamed(r *Report, key string) (ScenarioResult, bool) {
	for _, s := range r.Scenarios {
		if s.Key == key {
			return s, true
		}
	}
	return ScenarioResult{}, false
}

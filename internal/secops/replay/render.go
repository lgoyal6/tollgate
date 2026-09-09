package replay

import (
	"fmt"
	"strings"
)

// renderMarkdown is results/security-ops-report.md: the same facts as the
// JSON, for somebody who is not going to parse it.
//
// The boundary goes at the top rather than in a footnote. A page of detection
// results with the caveats at the bottom is a page that gets quoted without
// them.
func renderMarkdown(r *Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# tollgate security operations: detection evaluation\n\n")
	if r.Pass {
		fmt.Fprintf(&b, "**Every frozen threshold held.**\n\n")
	} else {
		fmt.Fprintf(&b, "**FAILED: at least one frozen threshold did not hold. See the table at the end.**\n\n")
	}
	if r.PlantedFault.Active {
		fmt.Fprintf(&b, "> This run was built with `-tags secops_planted_fault`. It is the negative control, "+
			"not a result: one correlation edge is deliberately broken.\n\n")
	}

	fmt.Fprintf(&b, "## What this is, and what it is not\n\n")
	fmt.Fprintf(&b, "- Runs on: %s\n", r.EvidenceBoundary.RunsOn)
	fmt.Fprintf(&b, "- Traffic: %s\n", r.EvidenceBoundary.Traffic)
	for _, line := range r.EvidenceBoundary.NotClaimed {
		fmt.Fprintf(&b, "- %s\n", line)
	}
	fmt.Fprintf(&b, "\nImplemented: the events, the trace linkage, the append-only timeline, the correlator, "+
		"the three detectors and the one allow-list control. Measured: the table below, on the single host above.\n\n")

	fmt.Fprintf(&b, "## Detection\n\n")
	fmt.Fprintf(&b, "| # | scenario | detected | delay ms | tenants | failed control | control held | recovery action | linkage |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|---|\n")
	for _, s := range r.Scenarios {
		fmt.Fprintf(&b, "| %d | %s | %s | %d | %d | `%s` | %s | %s | %s |\n",
			s.Ordinal, s.Key, yesNo(s.Detected), s.DetectionDelayMS, s.AffectedTenantCount,
			s.FailedControl, heldText(s), s.RecoveryAction, yesNo(s.LinkageComplete))
	}
	fmt.Fprintf(&b, "\nMedian detection delay across the malicious scenarios: **%d ms**. Maximum: **%d ms**.\n\n",
		r.DetectionDelay.Median, r.DetectionDelay.Max)
	fmt.Fprintf(&b, "%s\n\n", r.DetectionDelay.Note)

	fmt.Fprintf(&b, "## What each scenario sent\n\n")
	for _, s := range r.Scenarios {
		fmt.Fprintf(&b, "### %d. %s\n\n%s\n\n", s.Ordinal, s.Key, s.Title)
		for _, note := range s.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		fmt.Fprintf(&b, "- %d requests, %d security events, %d incident(s)\n",
			s.RequestsSent, s.EventsObserved, len(s.Incidents))
		if s.Detected {
			fmt.Fprintf(&b, "- outcome recorded by the control that decided: `%s`\n", s.ControlOutcome)
			fmt.Fprintf(&b, "- affected tenants: %s\n", strings.Join(s.AffectedTenants, ", "))
			fmt.Fprintf(&b, "- evidence: %d events across %d trace(s)\n",
				len(s.EvidenceEventIDs), len(s.EvidenceTraceIDs))
		} else {
			fmt.Fprintf(&b, "- **not detected**\n")
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## The matched benign replay\n\n")
	fmt.Fprintf(&b, "%d requests, %d security events, **%d alerts**. Request count matches the attack replay: %s.\n\n",
		r.BenignReplay.RequestsSent, r.BenignReplay.EventsObserved, r.BenignReplay.Alerts,
		yesNo(r.BenignReplay.MatchedOnRequests))
	fmt.Fprintf(&b, "| scenario | requests | events | alerts | what \"without the attack\" means here |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|\n")
	for _, leg := range r.BenignReplay.PerScenario {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %s |\n",
			leg.Scenario, leg.RequestsSent, leg.EventsObserved, leg.Alerts, lastNote(leg.Notes))
	}
	fmt.Fprintf(&b, "\nEvents without alerts are the point: a rotated key in ordinary use still records "+
		"key_rotation, and the rule declines to call it an incident.\n\n")

	fmt.Fprintf(&b, "## Determinism and integrity\n\n")
	fmt.Fprintf(&b, "- The replay ran %d times. Normalized timelines identical: **%s**.\n",
		r.Determinism.Runs, yesNo(r.Determinism.Identical))
	if r.Determinism.Difference != "" {
		fmt.Fprintf(&b, "- First difference:\n\n```\n%s\n```\n", r.Determinism.Difference)
	}
	fmt.Fprintf(&b, "- Normalized digest sha256: `%s`\n", r.Determinism.DigestSHA)
	fmt.Fprintf(&b, "- Timeline: %d events recorded, %d rebuilt from `%s`, match: **%s**.\n\n",
		r.TimelineIntegrity.EventsRecorded, r.TimelineIntegrity.EventsRebuilt,
		r.TimelineIntegrity.Path, yesNo(r.TimelineIntegrity.RebuildMatches))

	fmt.Fprintf(&b, "## How the harness was configured\n\n")
	fmt.Fprintf(&b, "- Chain: %s\n", r.Harness.Chain)
	fmt.Fprintf(&b, "- Omitted: %s\n", r.Harness.ChainOmission)
	fmt.Fprintf(&b, "- Breaker: opens at %d samples, cooldown %d ms (the shipped breaker at harness scale, so a scripted cascade takes under a second)\n",
		r.Harness.BreakerMinSamples, r.Harness.BreakerCooldownMS)
	fmt.Fprintf(&b, "- Burst tenant policy: %s\n", r.Harness.BurstPolicy)
	fmt.Fprintf(&b, "- Tracing: %s\n", r.Harness.Tracing)
	fmt.Fprintf(&b, "- Storage: %s\n\n", r.Harness.Storage)

	fmt.Fprintf(&b, "## Frozen thresholds\n\n")
	fmt.Fprintf(&b, "From `%s`, sha256 `%s`, frozen %s.\n\n",
		r.Manifest.Path, r.Manifest.SHA256, r.Manifest.FrozenAt)
	fmt.Fprintf(&b, "| threshold | required | observed | pass |\n|---|---|---|---|\n")
	for _, t := range r.Thresholds {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", t.Name, t.Required, t.Observed, yesNo(t.Pass))
	}
	fmt.Fprintf(&b, "\nThe negative control is not in this table because it is a separate build: "+
		"`scripts/run-security-ops-eval.sh` runs the harness again with `-tags secops_planted_fault` "+
		"and requires that run to FAIL.\n")
	return b.String()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// heldText says whether the control refused the request, which is a different
// question from whether the activity was detected.
func heldText(s ScenarioResult) string {
	if !s.Detected {
		return "unknown"
	}
	if s.ControlHeld {
		return "yes, refused"
	}
	return "no, allowed"
}

func lastNote(notes []string) string {
	if len(notes) == 0 {
		return ""
	}
	return notes[len(notes)-1]
}

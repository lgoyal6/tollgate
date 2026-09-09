// Command tollgate-secops-replay runs the scripted attack replay behind
// scripts/run-security-ops-eval.sh and writes the three result artifacts.
//
// It exits 0 only when every threshold frozen in secops/manifest.json held,
// which is what makes it usable as a check rather than as a report generator.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lgoyal6/tollgate/internal/secops"
	"github.com/lgoyal6/tollgate/internal/secops/replay"
)

func main() {
	manifest := flag.String("manifest", "secops/manifest.json", "path to the frozen evaluation manifest")
	out := flag.String("out", "results", "directory to write the timeline, evaluation and report into")
	quiet := flag.Bool("quiet", false, "suppress progress lines")
	flag.Parse()

	progress := os.Stdout
	if *quiet {
		progress = nil
	}

	report, ok, err := replay.Run(replay.Options{
		ManifestPath: *manifest,
		OutDir:       *out,
		Progress:     progress,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "secops replay could not run: %v\n", err)
		os.Exit(2)
	}

	summarize(report, *out)
	if !ok {
		fmt.Fprintln(os.Stderr, "\nsecops replay FAILED: at least one frozen threshold did not hold")
		os.Exit(1)
	}
	if secops.PlantedFaultActive {
		// Reaching here with the fault compiled in means the negative control
		// did not catch it, which invalidates every passing run of the normal
		// build: the check it is meant to prove cannot fail.
		fmt.Fprintln(os.Stderr, "\nsecops replay PASSED with the planted fault active, "+
			"which means the linkage check cannot fail and no passing run means anything")
		os.Exit(1)
	}
	fmt.Println("\nsecops replay passed every frozen threshold")
}

func summarize(r *replay.Report, out string) {
	fmt.Printf("\nplanted fault active in this build: %v\n", r.PlantedFault.Active)
	fmt.Printf("\n%-28s %-9s %-9s %-8s %s\n", "scenario", "detected", "delay ms", "tenants", "linkage")
	for _, s := range r.Scenarios {
		fmt.Printf("%-28s %-9v %-9d %-8d %v\n",
			s.Key, s.Detected, s.DetectionDelayMS, s.AffectedTenantCount, s.LinkageComplete)
	}
	fmt.Printf("\nbenign replay: %d requests, %d events, %d alerts\n",
		r.BenignReplay.RequestsSent, r.BenignReplay.EventsObserved, r.BenignReplay.Alerts)
	fmt.Printf("determinism over %d runs: identical=%v\n", r.Determinism.Runs, r.Determinism.Identical)
	if r.Determinism.Difference != "" {
		fmt.Printf("first difference:\n%s\n", r.Determinism.Difference)
	}
	fmt.Printf("timeline: %d events recorded, %d rebuilt from the log, match=%v\n",
		r.TimelineIntegrity.EventsRecorded, r.TimelineIntegrity.EventsRebuilt, r.TimelineIntegrity.RebuildMatches)
	fmt.Printf("\ndetection delay across malicious scenarios: median %d ms, max %d ms\n",
		r.DetectionDelay.Median, r.DetectionDelay.Max)
	fmt.Printf("\n%-62s %-12s %-12s %s\n", "frozen threshold", "required", "observed", "pass")
	for _, t := range r.Thresholds {
		fmt.Printf("%-62s %-12s %-12s %v\n", t.Name, t.Required, t.Observed, t.Pass)
	}
	fmt.Printf("\nartifacts in %s: security-ops-timeline.jsonl, security-ops-eval.json, security-ops-report.md\n", out)
}

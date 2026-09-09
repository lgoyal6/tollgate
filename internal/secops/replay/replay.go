package replay

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/lgoyal6/tollgate/internal/secops"
)

// Options configures one run of the harness.
type Options struct {
	// ManifestPath is the frozen design. Everything the harness measures
	// itself against is read from here.
	ManifestPath string
	// OutDir receives the three artifacts.
	OutDir string
	// Progress receives one line per step. Nil discards them.
	Progress io.Writer
}

// pass is one half of a run: the attack, or the matched benign traffic.
type pass struct {
	Name   string         `json:"pass"`
	Run    int            `json:"run"`
	Legs   []legRecord    `json:"legs"`
	Events []secops.Event `json:"-"`
}

// legRecord is one scenario leg with the slice of the timeline it produced.
type legRecord struct {
	legOutcome
	FirstEventID int64          `json:"first_event_id"`
	LastEventID  int64          `json:"last_event_id"`
	Events       []secops.Event `json:"-"`
}

// Run executes the whole evaluation: the attack replay and its matched
// benign counterpart, twice, then correlates, checks the frozen thresholds
// and writes the artifacts.
//
// Returns the report and whether every threshold held. An error means the
// harness could not run at all, which is a different thing from a failed
// evaluation and is reported differently.
func Run(opts Options) (*Report, bool, error) {
	manifest, err := secops.LoadManifest(opts.ManifestPath)
	if err != nil {
		return nil, false, err
	}
	spend, err := manifest.SpendThresholdsFromManifest()
	if err != nil {
		return nil, false, err
	}
	capacity, err := manifest.ReplayCapacityFromManifest()
	if err != nil {
		return nil, false, err
	}

	// A real tracer provider with no exporter: span contexts are genuine, so
	// the trace linkage in the events is the real thing, and nothing leaves
	// the process. An evaluation that needed a collector to run would not be
	// runnable by whoever reads this.
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer func() {
		otel.SetTracerProvider(previous)
		_ = tp.Shutdown(context.Background())
	}()

	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return nil, false, fmt.Errorf("replay: creating %s: %w", opts.OutDir, err)
	}
	timelinePath := filepath.Join(opts.OutDir, "security-ops-timeline.jsonl")
	// The timeline only ever appends, so a previous run's artifact is
	// removed before this one starts rather than truncated through the
	// Timeline type, which has no way to do that and should not have one.
	if err := os.Remove(timelinePath); err != nil && !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("replay: clearing %s: %w", timelinePath, err)
	}
	timeline, err := secops.NewTimeline(timelinePath)
	if err != nil {
		return nil, false, err
	}

	fx, err := newFixtures()
	if err != nil {
		return nil, false, err
	}
	defer fx.close()

	var counter atomic.Int64
	var passes []pass
	for run := 1; run <= 2; run++ {
		for _, malicious := range []bool{true, false} {
			name := "benign"
			if malicious {
				name = "malicious"
			}
			progressf(opts.Progress, "run %d: %s replay", run, name)
			p, err := runPass(fx, timeline, &counter, spend, capacity, run, malicious)
			if err != nil {
				return nil, false, err
			}
			passes = append(passes, p)
		}
	}
	if err := timeline.Close(); err != nil {
		return nil, false, fmt.Errorf("replay: the timeline did not write cleanly: %w", err)
	}

	// The timeline is supposed to BE the record, so it is read back and
	// compared instead of trusted. A harness that reported from memory while
	// the artifact said something else would be reporting on nothing.
	progressf(opts.Progress, "rebuilding the timeline from %s", timelinePath)
	rebuilt, err := rebuildFrom(timelinePath)
	if err != nil {
		return nil, false, err
	}

	report, ok := evaluate(evaluation{
		Manifest:     manifest,
		ManifestPath: opts.ManifestPath,
		TimelinePath: timelinePath,
		Passes:       passes,
		InMemory:     timeline.Events(),
		Rebuilt:      rebuilt,
	})
	if err := writeArtifacts(opts.OutDir, report); err != nil {
		return nil, false, err
	}
	return report, ok, nil
}

// runPass drives every leg once with a fresh chain and a fresh recorder.
func runPass(fx *fixtures, timeline *secops.Timeline, counter *atomic.Int64,
	spend secops.SpendThresholds, capacity, run int, malicious bool) (pass, error) {

	collected := &collector{}
	rec := secops.NewRecorder(secops.Options{
		Sinks:          []secops.Sink{timeline, collected},
		Counter:        counter,
		ReplayCapacity: capacity,
		Spend:          spend,
	})
	h, err := newHarness(fx, rec)
	if err != nil {
		return pass{}, err
	}

	p := pass{Name: "malicious", Run: run}
	if !malicious {
		p.Name = "benign"
	}
	for _, leg := range legs() {
		before := counter.Load()
		outcome, err := leg(h, malicious)
		if err != nil {
			return pass{}, fmt.Errorf("replay: %s leg %s: %w", p.Name, outcome.Scenario, err)
		}
		after := counter.Load()
		p.Legs = append(p.Legs, legRecord{
			legOutcome:   outcome,
			FirstEventID: before + 1,
			LastEventID:  after,
			Events:       collected.between(before, after),
		})
	}
	p.Events = collected.all()
	return p, nil
}

// collector keeps a pass's events so they can be sliced per leg without
// re-reading the file.
type collector struct {
	events []secops.Event
}

func (c *collector) Record(e secops.Event) { c.events = append(c.events, e) }

func (c *collector) all() []secops.Event { return append([]secops.Event(nil), c.events...) }

func (c *collector) between(afterID, throughID int64) []secops.Event {
	var out []secops.Event
	for _, e := range c.events {
		if e.ID > afterID && e.ID <= throughID {
			out = append(out, e)
		}
	}
	return out
}

func rebuildFrom(path string) ([]secops.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("replay: reopening the timeline: %w", err)
	}
	defer f.Close()
	return secops.Rebuild(f)
}

func progressf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format+"\n", args...)
}

// readFile is here so the tests can assert an artifact exists and is not
// empty without importing os for one call.
func readFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("replay: %s is empty", path)
	}
	return raw, nil
}

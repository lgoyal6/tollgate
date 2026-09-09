package secops

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTheTimelineIsAppendOnlyAndRebuildsFromItsOwnLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timeline.jsonl")

	first, err := NewTimeline(path)
	if err != nil {
		t.Fatalf("NewTimeline: %v", err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	first.Record(Event{
		ID: 1, At: at, Type: EventAuthRejected, TenantID: "acme", TraceID: "t1", SpanID: "s1",
		Control: ControlAPIKeyVerification, Outcome: OutcomeRejected,
		Evidence: map[string]string{"reason": "unknown_key"},
	})
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A second timeline over the same path appends. Nothing in this type can
	// shorten or rewrite the file, which is the property that makes it
	// evidence rather than a scratch buffer.
	second, err := NewTimeline(path)
	if err != nil {
		t.Fatalf("NewTimeline (reopen): %v", err)
	}
	second.Record(Event{
		ID: 2, At: at.Add(time.Second), Type: EventRateBurst, TenantID: "acme", TraceID: "t2", SpanID: "s2",
		Control: ControlRateLimit, Outcome: OutcomeRejected,
	})
	if err := second.Close(); err != nil {
		t.Fatalf("Close (reopen): %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	rebuilt, err := Rebuild(f)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if len(rebuilt) != 2 {
		t.Fatalf("rebuilt %d events, want both writes to survive (2)", len(rebuilt))
	}
	if rebuilt[0].ID != 1 || rebuilt[1].ID != 2 {
		t.Errorf("rebuilt out of order: %d then %d", rebuilt[0].ID, rebuilt[1].ID)
	}
	if rebuilt[0].Evidence["reason"] != "unknown_key" {
		t.Errorf("evidence did not survive the round trip: %+v", rebuilt[0].Evidence)
	}
	if !rebuilt[0].At.Equal(at) {
		t.Errorf("timestamp = %v, want %v", rebuilt[0].At, at)
	}
	if !rebuilt[0].LinkageComplete() {
		t.Errorf("a rebuilt event lost its linkage: %+v", rebuilt[0])
	}
}

// The append-only claim is about the type's surface, so it is asserted
// against the type's surface: no method here may update or delete.
func TestTheTimelineHasNoMutationPath(t *testing.T) {
	forbidden := []string{"update", "delete", "truncate", "remove", "set", "replace", "rewrite"}
	typ := reflect.TypeOf(&Timeline{})
	for i := 0; i < typ.NumMethod(); i++ {
		name := strings.ToLower(typ.Method(i).Name)
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Errorf("Timeline has a %s method: an append-only log cannot have one", typ.Method(i).Name)
			}
		}
	}
}

func TestAnInMemoryTimelineNeedsNoFile(t *testing.T) {
	tl, err := NewTimeline("")
	if err != nil {
		t.Fatalf("NewTimeline(\"\"): %v", err)
	}
	tl.Record(Event{ID: 1, Type: EventRateBurst})
	if tl.Len() != 1 {
		t.Fatalf("Len = %d, want 1", tl.Len())
	}
	if err := tl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestRebuildRefusesACorruptLine(t *testing.T) {
	if _, err := Rebuild(strings.NewReader("{\"event_id\":1}\nnot json\n")); err == nil {
		t.Fatal("Rebuild accepted a corrupt line; a timeline that silently drops a line is worse than one that fails")
	}
}

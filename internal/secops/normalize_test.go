package secops

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// twoRuns is the same logical event from two different runs: different ids,
// different clock, different certificate thumbprint, different ephemeral
// upstream port. Everything a determinism check must see past.
func twoRuns() (Event, Event) {
	a := Event{
		ID: 7, At: time.Unix(1_700_000_000, 0).UTC(), Type: EventTokenReplay,
		RequestID: "aaaaaaaaaaaa", TraceID: "0af7651916cd43dd8448eb211c80319c", SpanID: "b7ad6b7169203331",
		TenantID: "replay-co", KeyID: "oidc:user-1", Route: "/api/", Control: ControlTokenReplayFilter,
		Outcome: OutcomeAllowed,
		Evidence: map[string]string{
			"token_id": "jti:stolen-1", "peer": "cert:AAAA", "first_seen_peer": "cert:BBBB",
			"upstream_host": "127.0.0.1:51001", "refused": "false",
		},
	}
	b := a
	b.ID = 99
	b.At = time.Unix(1_800_000_500, 123).UTC()
	b.RequestID = "bbbbbbbbbbbb"
	b.TraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	b.SpanID = "00f067aa0ba902b7"
	b.Evidence = map[string]string{
		"token_id": "jti:stolen-1", "peer": "cert:CCCC", "first_seen_peer": "cert:DDDD",
		"upstream_host": "127.0.0.1:62222", "refused": "false",
	}
	return a, b
}

func TestNormalizeSeesPastEverythingThatVariesPerRun(t *testing.T) {
	m := frozenManifest(t)
	keys := m.Determinism.Normalization.EvidenceKeys
	a, b := twoRuns()

	linesA, err := Normalize([]Event{a}, keys)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	linesB, err := Normalize([]Event{b}, keys)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !reflect.DeepEqual(linesA, linesB) {
		t.Fatalf("the same event from two runs normalized differently:\n%s\n%s", linesA[0], linesB[0])
	}
	// And it must not have normalized away the evidence that is the finding.
	if !strings.Contains(linesA[0], "jti:stolen-1") {
		t.Errorf("normalization removed the token id, which is the evidence: %s", linesA[0])
	}
	if !strings.Contains(linesA[0], string(EventTokenReplay)) {
		t.Errorf("normalization removed the event type: %s", linesA[0])
	}
}

// The one thing normalization must NOT hide is whether an event carried its
// trace linkage, because that is exactly what the planted negative control
// takes away.
func TestNormalizeStillShowsAMissingTrace(t *testing.T) {
	m := frozenManifest(t)
	keys := m.Determinism.Normalization.EvidenceKeys
	a, _ := twoRuns()
	broken := a
	broken.TraceID = ""

	whole, err := Normalize([]Event{a}, keys)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	lost, err := Normalize([]Event{broken}, keys)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if whole[0] == lost[0] {
		t.Fatal("an event that lost its trace id normalized identically to one that kept it")
	}
	if !strings.Contains(lost[0], `"has_trace_id":false`) {
		t.Errorf("the normalized form does not report the missing trace: %s", lost[0])
	}
}

// A different sequence of events must normalize differently, or "byte
// identical" would mean nothing.
func TestNormalizeDistinguishesDifferentSequences(t *testing.T) {
	m := frozenManifest(t)
	keys := m.Determinism.Normalization.EvidenceKeys
	a, _ := twoRuns()
	other := a
	other.Type = EventCertMismatch
	other.Outcome = OutcomeRejected

	one, _ := Normalize([]Event{a, other}, keys)
	two, _ := Normalize([]Event{other, a}, keys)
	if reflect.DeepEqual(one, two) {
		t.Fatal("two different event orders normalized identically")
	}
}

// normalizedEvent is what the determinism comparison actually looks at, so a
// field added to Event has to be added there too or it silently stops being
// compared. The compiler will not say so; this will.
func TestTheNormalizedFormCoversEveryEventField(t *testing.T) {
	// Fields of Event that normalization deliberately drops or folds, with
	// the reason. Anything not listed here must appear in normalizedEvent.
	folded := map[string]string{
		"ID":        "folded into ordinal: it comes from a process-wide sequence",
		"At":        "folded into ordinal: it comes from a real clock",
		"RequestID": "random per request",
		"TraceID":   "random per request, replaced by has_trace_id",
		"SpanID":    "random per request, replaced by has_span_id",
	}
	normalized := map[string]bool{}
	nt := reflect.TypeOf(normalizedEvent{})
	for i := 0; i < nt.NumField(); i++ {
		normalized[nt.Field(i).Name] = true
	}
	et := reflect.TypeOf(Event{})
	for i := 0; i < et.NumField(); i++ {
		name := et.Field(i).Name
		if _, ok := folded[name]; ok {
			continue
		}
		if !normalized[name] {
			t.Errorf("Event.%s is not in the determinism comparison: add it to normalizedEvent, or to the folded list with a reason", name)
		}
	}
}

func TestNormalizedDigestLabelsEachLeg(t *testing.T) {
	digest := NormalizedDigest([]NormalizedLeg{
		{Scenario: "one", Lines: []string{"{}"}},
		{Scenario: "two", Lines: []string{"{}", "{}"}},
	})
	want := "# one 1\n{}\n# two 2\n{}\n{}\n"
	if digest != want {
		t.Fatalf("digest = %q, want %q", digest, want)
	}
}

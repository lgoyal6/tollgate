package secops

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// Timeline is the incident log: an append-only JSONL file and the same events
// in memory, in the order they were recorded.
//
// Append-only is the property, not the implementation detail. The file is
// opened O_APPEND and this type has no update path and no delete path, on
// purpose: an incident record that can be edited after the fact is not
// evidence of anything. Correcting a mistake means appending a later event
// that says so.
//
// What that does not claim: this is a file on one host, not a tamper-evident
// store. Anything that can write to the filesystem can rewrite it. The
// guarantee is that nothing in this process will.
type Timeline struct {
	mu     sync.Mutex
	events []Event
	file   *os.File
	enc    *json.Encoder
	// writeErr keeps the first write failure. Record cannot return an error
	// - it is on the request path, behind the Sink interface - so the failure
	// surfaces from Close, where somebody is in a position to fail the run.
	writeErr error
}

// NewTimeline opens path for appending. A nil path keeps the timeline in
// memory only, which is what a test wants.
func NewTimeline(path string) (*Timeline, error) {
	t := &Timeline{}
	if path == "" {
		return t, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("secops: opening timeline %s: %w", path, err)
	}
	t.file = f
	t.enc = json.NewEncoder(f)
	return t, nil
}

// Record appends one event. Implements Sink.
func (t *Timeline) Record(e Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, e)
	if t.enc == nil {
		return
	}
	if err := t.enc.Encode(e); err != nil && t.writeErr == nil {
		t.writeErr = err
	}
}

// Events returns a copy of the timeline in record order.
func (t *Timeline) Events() []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Event(nil), t.events...)
}

// Len is how many events the timeline holds.
func (t *Timeline) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.events)
}

// Close flushes and closes the file, reporting the first write failure if
// there was one. A timeline whose writes silently failed would be worse than
// no timeline: it would look like nothing happened.
func (t *Timeline) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil {
		return t.writeErr
	}
	err := t.file.Close()
	t.file, t.enc = nil, nil
	if t.writeErr != nil {
		return t.writeErr
	}
	return err
}

// Rebuild reconstructs a timeline from a JSONL log.
//
// This is what makes the claim "the timeline is built from the log" checkable
// rather than assumed. The harness reads its own artifact back through this
// and compares it to what it held in memory, so a timeline that recorded one
// thing and wrote another is a failure rather than a discrepancy nobody
// looks for.
func Rebuild(r io.Reader) ([]Event, error) {
	var out []Event
	scanner := bufio.NewScanner(r)
	// Events carry evidence maps, so a line is longer than the default 64 KiB
	// ceiling could guarantee. One MiB per line is far past anything this
	// package writes and still bounded.
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; scanner.Scan(); line++ {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("secops: timeline line %d: %w", line, err)
		}
		out = append(out, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("secops: reading timeline: %w", err)
	}
	return out, nil
}

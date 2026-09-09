package secops

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Normalize renders one scenario leg's events as canonical lines with every
// per-run value replaced, so two runs of the same replay can be compared byte
// for byte.
//
// What is replaced and why: event ids and timestamps become the event's
// ordinal within its own leg, because ids come from a process-wide sequence
// and timestamps from a real clock, and neither is a property of the
// detection. Request, trace and span ids are random per request. The evidence
// keys the caller names are the ones carrying a certificate thumbprint or an
// ephemeral upstream port.
//
// What is deliberately NOT replaced: the order of the events, their types,
// their controls, their outcomes, their tenants, and every other evidence
// value. Those are what determinism is a claim about. A normalizer that
// redacted a shade more would be able to make any two runs look identical,
// which is why the redaction list is frozen in the manifest rather than
// chosen here.
func Normalize(events []Event, evidenceKeys []string) ([]string, error) {
	redact := make(map[string]bool, len(evidenceKeys))
	for _, k := range evidenceKeys {
		redact[k] = true
	}
	out := make([]string, 0, len(events))
	for i, e := range events {
		ordinal := int64(i + 1)
		evidence := e.Evidence
		if evidence != nil {
			redacted := make(map[string]string, len(evidence))
			for k, v := range evidence {
				if redact[k] {
					redacted[k] = "<" + k + ">"
					continue
				}
				redacted[k] = v
			}
			evidence = redacted
		}
		line, err := json.Marshal(normalizedEvent{
			Ordinal:  ordinal,
			Type:     string(e.Type),
			TenantID: e.TenantID,
			KeyID:    e.KeyID,
			Route:    e.Route,
			Attempt:  e.Attempt,
			Hedged:   e.Hedged,
			Fallback: e.Fallback,
			Control:  e.Control,
			Outcome:  string(e.Outcome),
			Evidence: evidence,
			HasTrace: e.TraceID != "",
			HasSpan:  e.SpanID != "",
		})
		if err != nil {
			return nil, fmt.Errorf("secops: normalizing event %d: %w", e.ID, err)
		}
		out = append(out, string(line))
	}
	return out, nil
}

// normalizedEvent is the comparison form. It is a separate type rather than a
// mangled Event so that adding a field to Event cannot silently drop out of
// the determinism comparison: a new field has to be added here to be
// compared, and the compiler does not remind you, so the test in
// normalize_test.go counts the fields.
//
// HasTrace and HasSpan replace the ids themselves. The ids are random, but
// WHETHER an event carried them is exactly what the planted negative control
// breaks, so the normalized form must still show it.
type normalizedEvent struct {
	Ordinal  int64             `json:"ordinal"`
	Type     string            `json:"event_type"`
	TenantID string            `json:"tenant_id"`
	KeyID    string            `json:"key_id,omitempty"`
	Route    string            `json:"route"`
	Attempt  int               `json:"provider_attempt"`
	Hedged   bool              `json:"hedged"`
	Fallback bool              `json:"fallback"`
	Control  string            `json:"control"`
	Outcome  string            `json:"outcome"`
	Evidence map[string]string `json:"evidence,omitempty"`
	HasTrace bool              `json:"has_trace_id"`
	HasSpan  bool              `json:"has_span_id"`
}

// NormalizedDigest joins normalized legs into the single blob the two runs
// are compared as. Legs are labelled and kept in replay order, so a
// difference points at a scenario rather than at a line number.
func NormalizedDigest(legs []NormalizedLeg) string {
	var b []byte
	for _, leg := range legs {
		b = append(b, "# "...)
		b = append(b, leg.Scenario...)
		b = append(b, ' ')
		b = strconv.AppendInt(b, int64(len(leg.Lines)), 10)
		b = append(b, '\n')
		for _, line := range leg.Lines {
			b = append(b, line...)
			b = append(b, '\n')
		}
	}
	return string(b)
}

// NormalizedLeg is one scenario's normalized events.
type NormalizedLeg struct {
	Scenario string
	Lines    []string
}

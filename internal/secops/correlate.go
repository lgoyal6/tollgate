package secops

import (
	"fmt"
	"sort"
	"time"
)

// Incident is one detection: a group of events that satisfied a frozen rule,
// with everything an operator needs to act on it and everything a reader
// needs to check it.
type Incident struct {
	ID       string `json:"incident_id"`
	Scenario string `json:"scenario"`
	// GroupKey is what made these events one incident: the tenant, or the
	// upstream host, depending on the scenario's rule.
	GroupKey string `json:"group_key"`

	FirstEventID int64     `json:"first_event_id"`
	FirstEventAt time.Time `json:"first_event_at"`
	// DetectionAt is when the event that SATISFIED the rule was recorded, not
	// when a human saw it. There is no human in this evaluation and claiming
	// otherwise would be the whole point of the exercise thrown away.
	DetectionAt      time.Time `json:"detection_time"`
	DetectionEventID int64     `json:"detection_event_id"`
	DetectionDelayMS int64     `json:"detection_delay_ms"`

	AffectedTenants     []string `json:"affected_tenants"`
	AffectedTenantCount int      `json:"affected_tenant_count"`

	FailedControl  string `json:"failed_control"`
	ControlOutcome string `json:"control_outcome"`
	RecoveryAction string `json:"recovery_action"`

	EvidenceEventIDs []int64  `json:"evidence_event_ids"`
	EvidenceTraceIDs []string `json:"evidence_trace_ids"`
	EvidenceTypes    []string `json:"evidence_event_types"`

	LinkageComplete bool `json:"linkage_complete"`
	// MissingLinkage names the fields that were absent, so a false here is
	// actionable instead of merely disappointing.
	MissingLinkage []string `json:"missing_linkage,omitempty"`
}

// Correlate groups events into incidents under the manifest's frozen rules.
//
// One incident per (scenario, group) over the slice it is given. A sustained
// attack is one incident with a first detection time rather than an alert per
// event, which is the same choice the spend detector makes and for the same
// reason: an alert per event is how a detection layer gets muted.
//
// Deterministic by construction. Events are processed in event-id order,
// groups are emitted in the order their first event appeared, and nothing
// consults a clock or a map iteration order.
func Correlate(events []Event, m *Manifest) []Incident {
	ordered := append([]Event(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	var out []Incident
	for _, sc := range m.MaliciousScenarios() {
		for i, g := range groupFor(ordered, sc.Rule) {
			inc, ok := assess(sc, g)
			if !ok {
				continue
			}
			inc.ID = fmt.Sprintf("%s#%d", sc.Key, i+1)
			out = append(out, inc)
		}
	}
	return out
}

// group is the events of one scenario that share a group key.
type group struct {
	key    string
	events []Event
}

// groupFor buckets the matching events, keeping first-appearance order so the
// result does not depend on map iteration.
func groupFor(events []Event, rule Rule) []group {
	match := make(map[EventType]bool, len(rule.MatchEventTypes))
	for _, t := range rule.MatchEventTypes {
		match[t] = true
	}
	var groups []group
	index := make(map[string]int)
	for _, e := range events {
		if !match[e.Type] {
			continue
		}
		key := groupKey(e, rule.GroupBy)
		if key == "" {
			continue
		}
		if at, ok := index[key]; ok {
			groups[at].events = append(groups[at].events, e)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, group{key: key, events: []Event{e}})
	}
	return groups
}

func groupKey(e Event, by string) string {
	switch by {
	case "tenant":
		return e.TenantID
	case "upstream":
		// The upstream is evidence rather than a column on the event,
		// because the tenant-facing chain does not always know one: a
		// request refused at auth never reached a route.
		return e.Evidence["upstream_host"]
	case "route":
		return e.Route
	default:
		return ""
	}
}

// assess applies one scenario's rule to one group.
func assess(sc Scenario, g group) (Incident, bool) {
	detection, ok := detectionEvent(sc.Rule, g.events)
	if !ok {
		return Incident{}, false
	}
	first := g.events[0]

	inc := Incident{
		Scenario:         sc.Key,
		GroupKey:         g.key,
		FirstEventID:     first.ID,
		FirstEventAt:     first.At,
		DetectionAt:      detection.At,
		DetectionEventID: detection.ID,
		DetectionDelayMS: detection.At.Sub(first.At).Milliseconds(),
		FailedControl:    sc.FailedControl,
		ControlOutcome:   string(detection.Outcome),
		RecoveryAction:   sc.RecoveryAction,
		LinkageComplete:  true,
	}
	if inc.DetectionDelayMS < 0 {
		// Cannot happen with a monotonic sequence and one clock, and is
		// reported rather than clamped silently if it ever does.
		inc.DetectionDelayMS = 0
		inc.MissingLinkage = append(inc.MissingLinkage, "detection_before_first_event")
		inc.LinkageComplete = false
	}

	tenants := map[string]bool{}
	traces := map[string]bool{}
	types := map[string]bool{}
	missing := map[string]bool{}
	for _, e := range g.events {
		inc.EvidenceEventIDs = append(inc.EvidenceEventIDs, e.ID)
		if e.TenantID != "" {
			tenants[e.TenantID] = true
		} else {
			missing["tenant_id"] = true
		}
		if e.TraceID != "" {
			traces[e.TraceID] = true
		} else {
			missing["trace_id"] = true
		}
		if e.Control == "" {
			missing["control"] = true
		}
		if e.Outcome == "" {
			missing["outcome"] = true
		}
		types[string(e.Type)] = true
	}
	inc.AffectedTenants = sortedKeys(tenants)
	inc.AffectedTenantCount = len(inc.AffectedTenants)
	inc.EvidenceTraceIDs = sortedKeys(traces)
	inc.EvidenceTypes = sortedKeys(types)
	if len(missing) > 0 {
		inc.LinkageComplete = false
		inc.MissingLinkage = append(inc.MissingLinkage, sortedKeys(missing)...)
		sort.Strings(inc.MissingLinkage)
	}
	return inc, true
}

// detectionEvent finds the event that satisfied the rule, in the four shapes
// the manifest's rules take.
func detectionEvent(rule Rule, events []Event) (Event, bool) {
	if len(events) < rule.MinEvents {
		return Event{}, false
	}
	switch {
	case rule.RequireOutcome != "":
		// A cascade: an outcome that only counts once enough of another
		// outcome has already happened.
		need := 0
		if rule.MinEventsWithOutcome != nil {
			need = rule.MinEventsWithOutcome.Count
		}
		seen := 0
		for _, e := range events {
			if rule.MinEventsWithOutcome != nil && e.Outcome == rule.MinEventsWithOutcome.Outcome {
				seen++
			}
			if e.Outcome == rule.RequireOutcome && seen >= need {
				return e, true
			}
		}
		return Event{}, false

	case rule.RequireEventType != "":
		// Supporting events plus one that is the finding.
		for _, e := range events {
			if e.Type == rule.RequireEventType {
				return e, true
			}
		}
		return Event{}, false

	case rule.WindowMS > 0:
		// A burst: the Nth event inside a sliding window.
		window := rule.Window()
		for i := rule.MinEvents - 1; i < len(events); i++ {
			if events[i].At.Sub(events[i-rule.MinEvents+1].At) <= window {
				return events[i], true
			}
		}
		return Event{}, false

	default:
		// A count with no window.
		return events[rule.MinEvents-1], true
	}
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

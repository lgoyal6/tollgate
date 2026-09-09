//go:build secops_planted_fault

package secops

// plantedFault is the negative control. It is compiled ONLY under
// -tags secops_planted_fault, which nothing but scripts/run-security-ops-eval.sh
// ever sets.
//
// The fault is deliberately small and specific: it strips the trace id from
// cert_mismatch events. The event is still emitted, the scenario is still
// detected, and the incident still names the right control. What breaks is
// the one thing that makes the evidence usable an hour later: the link from
// this decision to the trace that contains the request, the tenant and the
// upstream attempt. That is exactly the failure a linkage check exists to
// catch, and it is invisible to a detection-rate number.
func plantedFault(e *Event) {
	if e.Type == EventCertMismatch {
		e.TraceID = ""
	}
}

// PlantedFaultActive is true in the negative control build.
const PlantedFaultActive = true

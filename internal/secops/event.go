// Package secops is the gateway's security evidence layer: one structured
// event per decision an existing control already made, an append-only
// timeline built from those events, and a correlator that groups them into
// incidents under rules frozen in secops/manifest.json.
//
// It is detection only, and that is a design constraint rather than a stage.
// Nothing in this package refuses a request, bans a caller, disables a key or
// keeps a list of anybody. Where a request in the timeline was refused, it was
// refused by a control that already existed: certificate binding, key
// verification, the rate limiter, the circuit breaker, the upstream
// allow-list. The three detectors here that have no pre-existing control to
// observe (token replay, provider spend anomaly) report and never act.
//
// The events are emitted from the places where those controls decide, so the
// evidence cannot drift from the decision: if the middleware admitted a
// request, no event says it was refused.
package secops

import "time"

// EventType is the closed set of security events the gateway emits. Closed on
// purpose: these become span event names and log keys, so a caller-derived
// value here would be unbounded cardinality in a trace backend.
type EventType string

const (
	// EventAuthRejected is a credential the gateway refused: a malformed,
	// unknown, revoked or grace-expired API key, or a token that failed any
	// check other than certificate binding.
	EventAuthRejected EventType = "auth_rejected"
	// EventTokenReplay is a token id seen before, presented again from a
	// different peer identity inside its own lifetime.
	EventTokenReplay EventType = "token_replay"
	// EventCertMismatch is RFC 8705 binding failing: the token names a client
	// certificate that was not the one presented.
	EventCertMismatch EventType = "cert_mismatch"
	// EventRateBurst is one limiter refusal. A burst is several of these in a
	// window, which is the correlator's job, not this event's.
	EventRateBurst EventType = "rate_burst"
	// EventKeyRotation is a key used while it is in, or just past, its
	// rotation grace window.
	EventKeyRotation EventType = "key_rotation"
	// EventProviderAnomaly is abnormal use of a rotated key together with a
	// spend spike, in one window.
	EventProviderAnomaly EventType = "provider_anomaly"
	// EventSSRFRejected is an upstream target refused for being a cloud
	// instance metadata endpoint.
	EventSSRFRejected EventType = "ssrf_rejected"
	// EventUpstreamTimeoutCascade is one upstream attempt that timed out, was
	// refused by an open breaker, or was carried by a fallback.
	EventUpstreamTimeoutCascade EventType = "upstream_timeout_cascade"
)

// Outcome is what happened to the request the event describes. Also closed:
// the correlator's rules are written against these four values.
type Outcome string

const (
	OutcomeRejected Outcome = "rejected"
	OutcomeAllowed  Outcome = "allowed"
	OutcomeFellBack Outcome = "fell_back"
	OutcomeTimedOut Outcome = "timed_out"
)

// Control names the control that made the decision this event records. A
// constant per control rather than a free string, so an incident's
// failed_control cannot be a typo.
const (
	ControlAPIKeyVerification = "api_key_verification"
	ControlTokenVerification  = "oidc_token_verification"
	ControlCertificateBinding = "rfc8705_certificate_binding"
	ControlKeyRotationGrace   = "api_key_rotation_grace"
	ControlRateLimit          = "ratelimit_sliding_window"
	ControlTokenReplayFilter  = "oidc_token_replay_detector"
	ControlSpendAnomaly       = "provider_spend_anomaly_detector"
	ControlUpstreamAllowlist  = "upstream_metadata_allowlist"
	ControlCircuitBreaker     = "circuit_breaker"
	ControlRetryBudget        = "retry_budget"
	ControlRequestHedge       = "request_hedge"
)

// UnauthenticatedTenant is the tenant label on an event for a request that
// never resolved to a tenant. It mirrors reqctx.UnauthenticatedTenant, and
// the correlator treats it as a group like any other: a burst of refused
// credentials has no tenant by definition, and dropping those events would
// hide the one attack that is guaranteed to be unauthenticated.
const UnauthenticatedTenant = "unauthenticated"

// Event is one security decision, in the shape the timeline stores and the
// correlator reads. Field names are the JSON keys on purpose: the JSONL log
// is the interchange format, and Rebuild reads back exactly what Record
// wrote.
type Event struct {
	// ID is a monotonic sequence within the process. Shared across every
	// recorder in it, so two recorders cannot mint the same id.
	ID int64 `json:"event_id"`
	// At is when the decision was made, not when it was written.
	At   time.Time `json:"timestamp"`
	Type EventType `json:"event_type"`

	RequestID string `json:"request_id"`
	TraceID   string `json:"trace_id"`
	SpanID    string `json:"span_id"`
	TenantID  string `json:"tenant_id"`
	KeyID     string `json:"key_id,omitempty"`
	Route     string `json:"route"`

	// Attempt is the provider attempt index this event belongs to, 0 for the
	// first attempt and for anything decided before the proxy ran.
	Attempt int `json:"provider_attempt"`
	// Hedged is true when a backup attempt was fired for this request.
	Hedged bool `json:"hedged"`
	// Fallback is true when the request was ultimately carried by something
	// other than the primary attempt.
	Fallback bool `json:"fallback"`

	Control string  `json:"control"`
	Outcome Outcome `json:"outcome"`

	// Evidence is the detail an operator needs to confirm the event from the
	// timeline. Values are gateway-derived, never caller-supplied text.
	Evidence map[string]string `json:"evidence,omitempty"`
}

// LinkageComplete reports whether this event carries the four fields an
// incident needs to be traceable end to end: whose it was, which trace it
// belongs to, which control decided, and what the decision was.
//
// This is the whole point of the linkage requirement. An event missing any of
// the four is still evidence that something happened, and is useless for
// answering "was this the same caller as that one" an hour later.
func (e Event) LinkageComplete() bool {
	return e.TenantID != "" && e.TraceID != "" && e.Control != "" && e.Outcome != ""
}

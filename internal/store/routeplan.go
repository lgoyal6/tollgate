package store

import (
	"net/url"
	"strings"
	"time"
)

// Candidate is one upstream a request may be sent to, and the metadata the
// proxy needs in order to send it there.
//
// Metadata only, and that is the point of the type existing. A candidate never
// holds, reads, borrows or describes request bytes; it carries no credential,
// only the *name* of the environment variable the gateway should read one from.
// The proxy remains the only component that buffers a body, injects a secret,
// opens a connection, decides whether bytes are replayable, or streams a
// response back. Routing can therefore be decided, ordered, logged and traced
// without any of that being in scope.
type Candidate struct {
	Upstream *url.URL
	Timeout  time.Duration

	AuthHeader string
	AuthEnv    string
	AuthPrefix string

	// Fallback marks the one optional second candidate. There is never a third.
	Fallback bool
}

// InjectsCredential reports whether this candidate is configured to attach an
// upstream credential.
func (c Candidate) InjectsCredential() bool {
	return c.AuthHeader != "" && c.AuthEnv != ""
}

// Role names the candidate for logs and spans.
func (c Candidate) Role() string {
	if c.Fallback {
		return "fallback"
	}
	return "primary"
}

// RoutePlan is the order in which a matched route's upstreams may be tried:
// the primary, and at most one fallback.
//
// Not a routing policy engine, and not the first step towards one. There is no
// scoring, no weighting, no plugin point and no arbitrary-length candidate
// graph, because each of those turns "which upstream" into a thing an operator
// has to reason about at three in the morning. One optional fallback is the
// whole feature: it is enough to survive a single upstream refusing service,
// and small enough that the order is readable from one database row.
//
// The plan is built from the immutable configuration snapshot, so every request
// on one snapshot gets the same order.
type RoutePlan struct {
	Route      *Route
	Candidates []Candidate
	// Reason is a short, credential-free description of why the order is what
	// it is, suitable for a log line or a span attribute.
	Reason string
}

// PlanFor builds the ordered plan for one route.
//
// A route with no fallback configured produces a one-candidate plan, which is
// the same decision the gateway made before plans existed. That is why this is
// safe to derive anywhere: it cannot invent an upstream a route does not have.
func PlanFor(route *Route) *RoutePlan {
	primary := Candidate{
		Upstream:   route.Upstream,
		Timeout:    route.Timeout,
		AuthHeader: route.UpstreamAuthHeader,
		AuthEnv:    route.UpstreamAuthEnv,
		AuthPrefix: route.UpstreamAuthPrefix,
	}
	plan := &RoutePlan{
		Route:      route,
		Candidates: []Candidate{primary},
		Reason:     "single upstream configured for this route",
	}
	if route.FallbackUpstream == nil {
		return plan
	}
	plan.Candidates = append(plan.Candidates, Candidate{
		Upstream:   route.FallbackUpstream,
		Timeout:    route.Timeout,
		AuthHeader: route.FallbackAuthHeader,
		AuthEnv:    route.FallbackAuthEnv,
		AuthPrefix: route.FallbackAuthPrefix,
		Fallback:   true,
	})
	plan.Reason = "configured primary, then the route's one fallback"
	return plan
}

// Primary is the first candidate. A plan always has one.
func (p *RoutePlan) Primary() Candidate { return p.Candidates[0] }

// HasFallback reports whether a second candidate exists to fail over to.
func (p *RoutePlan) HasFallback() bool { return len(p.Candidates) > 1 }

// Order renders the candidate order for a log line or a span attribute: hosts
// only, in the order they would be tried. A host is not a secret; a full URL
// can be, because several providers take their key in a query parameter.
func (p *RoutePlan) Order() string {
	hosts := make([]string, 0, len(p.Candidates))
	for _, c := range p.Candidates {
		hosts = append(hosts, c.Upstream.Host)
	}
	return strings.Join(hosts, ",")
}

// PlanRoute resolves the tenant's route for a path and returns its ordered
// plan. The router calls this instead of MatchRoute so the order is fixed by
// the snapshot rather than decided per attempt.
func (s *Snapshot) PlanRoute(tenantID, path string) (*RoutePlan, bool) {
	route, ok := s.MatchRoute(tenantID, path)
	if !ok {
		return nil, false
	}
	return PlanFor(route), true
}

package gateway

import (
	dto "github.com/prometheus/client_model/go"

	"github.com/lgoyal6/tollgate/internal/admin"
	"github.com/lgoyal6/tollgate/internal/observability"
)

// usageFromMetrics answers the console's "who is burning the budget" question
// out of this process's own Prometheus registry, so the panel needs no
// separate storage and no Prometheus deployment.
//
// The numbers are therefore per replica. Behind three gateway pods the console
// shows the share that landed on the pod serving the console; the fleet-wide
// view is what scraping /metrics is for. The console says so on the page.
type usageFromMetrics struct{ m *observability.Metrics }

// TenantUsage sums the tenant-labelled counters into one row per tenant.
func (u usageFromMetrics) TenantUsage() map[string]admin.TenantCounters {
	out := map[string]admin.TenantCounters{}
	families, err := u.m.Registry.Gather()
	if err != nil {
		return out
	}
	for _, fam := range families {
		switch fam.GetName() {
		case "tollgate_requests_total":
			for _, met := range fam.GetMetric() {
				tenant, code := labels(met.GetLabel(), "tenant", "code")
				if tenant == "" {
					continue
				}
				c := out[tenant]
				c.Requests += met.GetCounter().GetValue()
				if code == "5xx" {
					c.ServerErr += met.GetCounter().GetValue()
				}
				out[tenant] = c
			}
		case "tollgate_ratelimit_decisions_total":
			for _, met := range fam.GetMetric() {
				tenant, outcome := labels(met.GetLabel(), "tenant", "outcome")
				if tenant == "" {
					continue
				}
				c := out[tenant]
				if outcome == "limited" {
					c.Limited += met.GetCounter().GetValue()
				} else {
					c.Admitted += met.GetCounter().GetValue()
				}
				out[tenant] = c
			}
		}
	}
	return out
}

// labels pulls two named label values out of one metric in a single pass.
func labels(pairs []*dto.LabelPair, a, b string) (string, string) {
	var av, bv string
	for _, l := range pairs {
		switch l.GetName() {
		case a:
			av = l.GetValue()
		case b:
			bv = l.GetValue()
		}
	}
	return av, bv
}

package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics is the gateway's Prometheus surface. The RED trio per tenant and
// route falls out of RequestDuration alone: Rate = rate(count), Errors =
// rate(count{code=~"5.."}), Duration = histogram quantiles. RequestsTotal is
// kept separately anyway so cheap increments survive histogram re-bucketing.
//
// Label cardinality discipline: tenant and route come from Postgres config
// (bounded), method is capped by HTTP, code is the status class. Nothing
// user-controlled becomes a label.
type Metrics struct {
	Registry *prometheus.Registry

	RequestsTotal   *prometheus.CounterVec   // tenant, route, method, code
	RequestDuration *prometheus.HistogramVec // tenant, route, method, code
	InFlight        prometheus.Gauge

	RateLimitDecisions  *prometheus.CounterVec // tenant, algorithm, outcome
	RateLimiterErrors   prometheus.Counter
	RateLimiterDuration prometheus.Histogram

	UpstreamDuration *prometheus.HistogramVec // upstream, code
	Retries          prometheus.Counter
	Hedges           prometheus.Counter
	HedgeWins        prometheus.Counter

	BreakerState       *prometheus.GaugeVec   // upstream (0 closed, 1 open, 2 half-open)
	BreakerTransitions *prometheus.CounterVec // upstream, to

	AuthFailures *prometheus.CounterVec // reason

	ConfigReloads        prometheus.Counter
	ConfigReloadFailures prometheus.Counter
}

var durationBuckets = []float64{
	0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		Registry: reg,
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tollgate_requests_total",
			Help: "Requests handled, by tenant, route, method and status code class.",
		}, []string{"tenant", "route", "method", "code"}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tollgate_request_duration_seconds",
			Help:    "End-to-end request latency observed at the gateway.",
			Buckets: durationBuckets,
		}, []string{"tenant", "route", "method", "code"}),
		InFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tollgate_in_flight_requests",
			Help: "Requests currently being served.",
		}),
		RateLimitDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tollgate_ratelimit_decisions_total",
			Help: "Rate limit admissions and rejections.",
		}, []string{"tenant", "algorithm", "outcome"}),
		RateLimiterErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tollgate_ratelimit_errors_total",
			Help: "Limiter backend failures (decision fell back to fail-open/closed).",
		}),
		RateLimiterDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "tollgate_ratelimit_check_duration_seconds",
			Help:    "Latency of the limiter admission check (Redis round trip).",
			Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1},
		}),
		UpstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tollgate_upstream_request_duration_seconds",
			Help:    "Latency of individual upstream attempts.",
			Buckets: durationBuckets,
		}, []string{"upstream", "code"}),
		Retries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tollgate_upstream_retries_total",
			Help: "Retry attempts sent to upstreams.",
		}),
		Hedges: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tollgate_hedged_requests_total",
			Help: "Backup (hedge) requests actually fired.",
		}),
		HedgeWins: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tollgate_hedge_wins_total",
			Help: "Requests where the hedge finished before the primary.",
		}),
		BreakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tollgate_circuit_breaker_state",
			Help: "Breaker state per upstream: 0 closed, 1 open, 2 half-open.",
		}, []string{"upstream"}),
		BreakerTransitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tollgate_circuit_breaker_transitions_total",
			Help: "Breaker state transitions per upstream.",
		}, []string{"upstream", "to"}),
		AuthFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tollgate_auth_failures_total",
			Help: "Rejected credentials by reason.",
		}, []string{"reason"}),
		ConfigReloads: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tollgate_config_reloads_total",
			Help: "Successful config snapshot reloads.",
		}),
		ConfigReloadFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tollgate_config_reload_failures_total",
			Help: "Failed config snapshot reloads (previous snapshot kept).",
		}),
	}

	reg.MustRegister(
		m.RequestsTotal, m.RequestDuration, m.InFlight,
		m.RateLimitDecisions, m.RateLimiterErrors, m.RateLimiterDuration,
		m.UpstreamDuration, m.Retries, m.Hedges, m.HedgeWins,
		m.BreakerState, m.BreakerTransitions,
		m.AuthFailures,
		m.ConfigReloads, m.ConfigReloadFailures,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// CodeClass buckets a status code for the `code` label ("2xx", "4xx", ...).
func CodeClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

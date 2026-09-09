package secops

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// SpendThresholds is the frozen rule for the provider spend anomaly
// detector, mirroring secops/manifest.json scenario provider_key_anomaly.
//
// All three conditions have to hold at once, which is the only reason this
// detector is worth having. Request rate alone is what the rate limiter
// already bounds. Spend alone is what the budget ledger already bounds. A
// rotated key alone is a routine event that happens every time somebody
// rotates. The conjunction - a credential that was supposed to be on its way
// out, spending real money fast - is the thing neither existing control
// notices, because each one is looking at a different column.
type SpendThresholds struct {
	Window            time.Duration
	MinRequests       int
	MinSpendMicros    int64
	RequireRotatedKey bool
}

// Enabled reports whether the thresholds describe a rule at all. A detector
// with a zero window and a zero floor would fire on the first request.
func (t SpendThresholds) Enabled() bool {
	return t.Window > 0 && t.MinRequests > 0 && t.MinSpendMicros > 0
}

// SpendWindows keeps one rolling window per tenant and key.
//
// Bounded by the number of live (tenant, key) pairs, which comes from
// Postgres config rather than from request data, and pruned as it goes: an
// entry whose window has emptied is deleted, so a departed tenant leaves
// nothing behind.
type SpendWindows struct {
	thresholds SpendThresholds
	mu         sync.Mutex
	windows    map[string]*spendWindow
}

type spendWindow struct {
	// at and micros are parallel: the settlement times and what each one
	// cost, oldest first.
	at     []time.Time
	micros []int64
	// firedAt is when this window last raised an anomaly. One event per
	// window length, so a sustained attack is one incident with a first
	// detection time rather than an alert per request.
	firedAt time.Time
}

func NewSpendWindows(t SpendThresholds) *SpendWindows {
	return &SpendWindows{thresholds: t, windows: make(map[string]*spendWindow)}
}

// spendVerdict is what one settlement did to its window.
type spendVerdict struct {
	fired    bool
	requests int
	micros   int64
}

func (s *SpendWindows) observe(tenantID, keyID string, costMicros int64, now time.Time) spendVerdict {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := tenantID + "\x00" + keyID
	w := s.windows[key]
	if w == nil {
		w = &spendWindow{}
		s.windows[key] = w
	}

	cutoff := now.Add(-s.thresholds.Window)
	drop := 0
	for drop < len(w.at) && !w.at[drop].After(cutoff) {
		drop++
	}
	w.at, w.micros = w.at[drop:], w.micros[drop:]

	w.at = append(w.at, now)
	w.micros = append(w.micros, costMicros)

	var total int64
	for _, m := range w.micros {
		total += m
	}
	v := spendVerdict{requests: len(w.at), micros: total}

	if len(w.at) < s.thresholds.MinRequests || total < s.thresholds.MinSpendMicros {
		return v
	}
	if !w.firedAt.IsZero() && now.Sub(w.firedAt) < s.thresholds.Window {
		return v
	}
	w.firedAt = now
	v.fired = true
	return v
}

// NoteSpend records one settled request against the tenant and key's rolling
// window, and emits provider_anomaly when the frozen rule is satisfied.
//
// It observes the budget ledger's settlement, which is the only point in the
// gateway that knows what a request actually cost: the hold taken before
// forwarding is an upper bound computed from the caller's own declared
// ceiling, and using that would report an anomaly for anyone who declared a
// large max_tokens and then sent a short prompt.
//
// It refuses nothing. The budget ledger remains the only thing that can turn
// down a request on spend, and this detector cannot change what it does.
func (r *Recorder) NoteSpend(ctx context.Context, costMicros int64, rotatedKey bool) {
	if r == nil || r.spend == nil {
		return
	}
	if r.spend.thresholds.RequireRotatedKey && !rotatedKey {
		return
	}
	info := reqctxInfo(ctx)
	v := r.spend.observe(info.tenant, info.key, costMicros, r.now())
	if !v.fired {
		return
	}
	r.Emit(ctx, Event{
		Type:    EventProviderAnomaly,
		Control: ControlSpendAnomaly,
		Outcome: OutcomeAllowed,
		Evidence: map[string]string{
			"window_ms":              strconv.FormatInt(r.spend.thresholds.Window.Milliseconds(), 10),
			"requests_in_window":     strconv.Itoa(v.requests),
			"spend_micros_in_window": strconv.FormatInt(v.micros, 10),
			"min_requests":           strconv.Itoa(r.spend.thresholds.MinRequests),
			"min_spend_micros":       strconv.FormatInt(r.spend.thresholds.MinSpendMicros, 10),
			"key_in_rotation_grace":  boolText(rotatedKey),
			"refused":                boolText(false),
		},
	})
}

package resilience

import (
	"context"
	"net/http"
	"time"
)

// HedgeResult is what the winning attempt produced.
type HedgeResult struct {
	Resp *http.Response
	Err  error
	// Attempt is which attempt won (0 = primary, 1 = hedge).
	Attempt int
	// Hedged reports whether the backup request was actually fired.
	Hedged bool
}

// attemptFn runs one attempt. It receives a context the hedger may cancel
// and returns a response whose Body the caller owns, or an error.
type attemptFn func(ctx context.Context, attempt int) (*http.Response, error)

type hedgeOutcome struct {
	resp    *http.Response
	err     error
	attempt int
}

func (o hedgeOutcome) usable() bool {
	return o.err == nil && o.resp != nil && o.resp.StatusCode < 500
}

// Hedge races a primary attempt against one delayed backup. If the primary
// answers before the delay expires, the backup never launches - hedging
// spends extra upstream work only on the slow tail. Once both are in flight
// the first usable response (no transport error, not a 5xx) wins; the
// loser's context is cancelled and its response drained.
//
// The returned cancel func must be called after the winner's Body has been
// consumed; it releases the winner's context.
func Hedge(ctx context.Context, delay time.Duration, run attemptFn) (HedgeResult, context.CancelFunc) {
	results := make(chan hedgeOutcome, 2)
	var cancels [2]context.CancelFunc

	launch := func(attempt int) {
		actx, cancel := context.WithCancel(ctx)
		cancels[attempt] = cancel
		go func() {
			resp, err := run(actx, attempt)
			results <- hedgeOutcome{resp: resp, err: err, attempt: attempt}
		}()
	}

	launch(0)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	hedged := false
	inFlight := 1
	var fallback *hedgeOutcome // a failure held in case the other attempt also fails

	finish := func(winner hedgeOutcome) (HedgeResult, context.CancelFunc) {
		for i, c := range cancels {
			if c != nil && i != winner.attempt {
				c()
			}
		}
		if fallback != nil && fallback.attempt != winner.attempt && fallback.resp != nil {
			fallback.resp.Body.Close()
		}
		if inFlight > 0 {
			// Reap the cancelled attempt in the background so its transport
			// resources are returned to the pool.
			go func(n int) {
				for range n {
					if o := <-results; o.resp != nil {
						o.resp.Body.Close()
					}
				}
			}(inFlight)
		}
		cancel := cancels[winner.attempt]
		if cancel == nil {
			cancel = func() {}
		}
		return HedgeResult{Resp: winner.resp, Err: winner.err, Attempt: winner.attempt, Hedged: hedged}, cancel
	}

	for {
		select {
		case <-timer.C:
			if !hedged {
				hedged = true
				launch(1)
				inFlight++
			}
		case o := <-results:
			inFlight--
			if o.usable() {
				return finish(o)
			}
			if inFlight > 0 {
				// The other attempt may still succeed; hold this failure.
				fallback = &o
				continue
			}
			if fallback != nil && fallback.resp != nil && o.resp == nil {
				// Both failed: prefer surfacing a real HTTP response over a
				// transport error.
				o, fallback = *fallback, &o
			}
			return finish(o)
		case <-ctx.Done():
			return finish(hedgeOutcome{err: ctx.Err(), attempt: 0})
		}
	}
}

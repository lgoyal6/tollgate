// Package resilience contains the failure-handling primitives the proxy
// composes: a rolling-window circuit breaker, jittered exponential backoff,
// and request hedging.
package resilience

import (
	"errors"
	"sync"
	"time"
)

// ErrOpen is returned by Allow while the breaker is rejecting traffic.
var ErrOpen = errors.New("circuit breaker open")

// State is the classic three-state breaker state.
type State int32

const (
	Closed State = iota
	Open
	HalfOpen
)

func (s State) String() string {
	switch s {
	case Closed:
		return "closed"
	case Open:
		return "open"
	default:
		return "half_open"
	}
}

// BreakerConfig tunes a Breaker. The failure ratio is evaluated over a
// rolling window of Buckets sub-intervals, so one old burst of errors ages
// out instead of tripping the breaker forever.
type BreakerConfig struct {
	Window       time.Duration // rolling window covered by all buckets
	Buckets      int
	MinRequests  int     // don't evaluate the ratio below this sample size
	FailureRatio float64 // trip threshold, e.g. 0.5
	Cooldown     time.Duration
	// HalfOpenProbes is both the number of concurrent probes half-open
	// admits and the successes required to close.
	HalfOpenProbes int
}

func DefaultBreakerConfig() BreakerConfig {
	return BreakerConfig{
		Window:         10 * time.Second,
		Buckets:        10,
		MinRequests:    20,
		FailureRatio:   0.5,
		Cooldown:       5 * time.Second,
		HalfOpenProbes: 3,
	}
}

type bucket struct {
	successes int
	failures  int
}

// Breaker is a rolling-window circuit breaker guarding one upstream.
//
//	Closed    -> Open      when ratio >= FailureRatio over >= MinRequests
//	Open      -> HalfOpen  after Cooldown
//	HalfOpen  -> Closed    after HalfOpenProbes consecutive probe successes
//	HalfOpen  -> Open      on any probe failure
type Breaker struct {
	mu  sync.Mutex
	cfg BreakerConfig
	now func() time.Time // injectable for tests

	state       State
	buckets     []bucket
	cur         int
	bucketStart time.Time
	openedAt    time.Time

	probesInFlight int
	probeSuccesses int

	// OnStateChange, if set, is called (locked) on every transition; used to
	// export breaker state as a metric. Keep it fast.
	OnStateChange func(from, to State)
}

func NewBreaker(cfg BreakerConfig) *Breaker {
	b := &Breaker{cfg: cfg, now: time.Now}
	b.buckets = make([]bucket, cfg.Buckets)
	b.bucketStart = b.now()
	return b
}

// State reports the current state (advancing Open->HalfOpen if cooldown has
// elapsed is deferred to the next Allow; this is a read-only peek).
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Allow asks to send one request. On success it returns a done callback that
// MUST be called exactly once with the outcome; on ErrOpen the request must
// be rejected.
func (b *Breaker) Allow() (done func(success bool), err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case Open:
		if b.now().Sub(b.openedAt) < b.cfg.Cooldown {
			return nil, ErrOpen
		}
		b.transition(HalfOpen)
		fallthrough
	case HalfOpen:
		if b.probesInFlight >= b.cfg.HalfOpenProbes {
			return nil, ErrOpen
		}
		b.probesInFlight++
		return b.probeDone, nil
	default: // Closed
		return b.closedDone, nil
	}
}

func (b *Breaker) closedDone(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != Closed {
		// A late completion from before a transition; ignore.
		return
	}
	b.advance()
	if success {
		b.buckets[b.cur].successes++
		return
	}
	b.buckets[b.cur].failures++
	total, failures := 0, 0
	for _, bk := range b.buckets {
		total += bk.successes + bk.failures
		failures += bk.failures
	}
	if total >= b.cfg.MinRequests && float64(failures)/float64(total) >= b.cfg.FailureRatio {
		b.openedAt = b.now()
		b.transition(Open)
	}
}

func (b *Breaker) probeDone(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != HalfOpen {
		return
	}
	b.probesInFlight--
	if !success {
		b.openedAt = b.now()
		b.transition(Open)
		return
	}
	b.probeSuccesses++
	if b.probeSuccesses >= b.cfg.HalfOpenProbes {
		b.transition(Closed)
	}
}

// advance rotates the rolling window to the bucket covering now. Caller
// holds the lock and state is Closed.
func (b *Breaker) advance() {
	width := b.cfg.Window / time.Duration(b.cfg.Buckets)
	steps := int(b.now().Sub(b.bucketStart) / width)
	if steps <= 0 {
		return
	}
	if steps > b.cfg.Buckets {
		steps = b.cfg.Buckets
	}
	for i := 0; i < steps; i++ {
		b.cur = (b.cur + 1) % b.cfg.Buckets
		b.buckets[b.cur] = bucket{}
	}
	b.bucketStart = b.bucketStart.Add(time.Duration(steps) * width)
	if b.now().Sub(b.bucketStart) > b.cfg.Window {
		// Idle longer than the whole window: re-anchor.
		b.bucketStart = b.now()
	}
}

// transition changes state, resetting whatever the target state needs.
// Caller holds the lock.
func (b *Breaker) transition(to State) {
	from := b.state
	if from == to {
		return
	}
	b.state = to
	switch to {
	case HalfOpen:
		b.probesInFlight = 0
		b.probeSuccesses = 0
	case Closed:
		for i := range b.buckets {
			b.buckets[i] = bucket{}
		}
		b.cur = 0
		b.bucketStart = b.now()
	}
	if b.OnStateChange != nil {
		b.OnStateChange(from, to)
	}
}

// BreakerGroup lazily creates one Breaker per upstream host.
type BreakerGroup struct {
	mu  sync.Mutex
	cfg BreakerConfig
	m   map[string]*Breaker
	// OnStateChange receives the upstream host along with the transition.
	OnStateChange func(host string, from, to State)
}

func NewBreakerGroup(cfg BreakerConfig) *BreakerGroup {
	return &BreakerGroup{cfg: cfg, m: make(map[string]*Breaker)}
}

func (g *BreakerGroup) For(host string) *Breaker {
	g.mu.Lock()
	defer g.mu.Unlock()
	b, ok := g.m[host]
	if !ok {
		b = NewBreaker(g.cfg)
		if g.OnStateChange != nil {
			cb := g.OnStateChange
			b.OnStateChange = func(from, to State) { cb(host, from, to) }
		}
		g.m[host] = b
	}
	return b
}

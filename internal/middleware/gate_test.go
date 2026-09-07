package middleware

import (
	"testing"

	"github.com/lgoyal6/tollgate/internal/limits"
)

func TestGateGroupReleasesIdleTenantEntries(t *testing.T) {
	gg := &gateGroup{cfg: limits.Config{MaxInFlightPerTenant: 2}}

	for i := 0; i < 10_000; i++ {
		_, done := gg.gateFor(string(rune(i)))
		done()
	}

	gg.mu.Lock()
	defer gg.mu.Unlock()
	if got := len(gg.gates); got != 0 {
		t.Fatalf("idle gate entries = %d, want 0", got)
	}
}

func TestGateGroupSharesGateWhileTenantRequestsOverlap(t *testing.T) {
	gg := &gateGroup{cfg: limits.Config{MaxInFlightPerTenant: 2}}

	first, doneFirst := gg.gateFor("acme")
	second, doneSecond := gg.gateFor("acme")
	if first != second {
		t.Fatal("overlapping requests for one tenant received different gates")
	}

	doneFirst()
	gg.mu.Lock()
	if got := len(gg.gates); got != 1 {
		gg.mu.Unlock()
		t.Fatalf("gate was evicted with one request still using it: entries = %d", got)
	}
	gg.mu.Unlock()

	doneSecond()
	gg.mu.Lock()
	defer gg.mu.Unlock()
	if got := len(gg.gates); got != 0 {
		t.Fatalf("gate survived its last request: entries = %d", got)
	}
}

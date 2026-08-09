//go:build js && wasm

// Browser demo: the distributed-correctness experiment from the README, run
// with the real ratelimit package on a virtual clock. Two gateways admit the
// same offered load against the same policy; one keeps per-replica counters
// (the naive approach), one checks a single shared store (what the Redis Lua
// scripts give every replica). The naive one admits ~Nx the ceiling.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"syscall/js"
	"time"

	"github.com/lgoyal6/tollgate/internal/ratelimit"
	"github.com/lgoyal6/tollgate/internal/store"
)

type secondSample struct {
	Second        int   `json:"second"`
	PerReplica    int64 `json:"per_replica"`
	SharedStore   int64 `json:"shared_store"`
	OfferedPerSec int64 `json:"offered"`
}

type result struct {
	Timeline       []secondSample `json:"timeline"`
	TotalOffered   int64          `json:"total_offered"`
	TotalPerRep    int64          `json:"total_per_replica"`
	TotalShared    int64          `json:"total_shared"`
	CeilingPerSec  float64        `json:"ceiling_per_sec"`
	MaxAdmitted    int64          `json:"max_admitted"`
	OverAdmitRatio float64        `json:"over_admit_ratio"`
}

// tgRun(algorithm, ratePerSec, burst, replicas, offeredRps, seconds) -> JSON
func tgRun(_ js.Value, args []js.Value) any {
	algo := args[0].String()
	rate := args[1].Float()
	burst := int64(args[2].Int())
	replicas := args[3].Int()
	offered := args[4].Int()
	seconds := args[5].Int()

	p := ratelimit.Policy{}
	if algo == "sliding_window" {
		p.Algorithm = store.AlgoSlidingWindow
		p.Window = time.Second
		p.Limit = int64(rate)
	} else {
		p.Algorithm = store.AlgoTokenBucket
		p.Rate = rate
		p.Burst = burst
	}
	if err := p.Validate(); err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}

	// Virtual clock shared by every limiter.
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	// N per-replica limiters vs one shared limiter that all replicas consult.
	perReplica := make([]*ratelimit.MemoryLimiter, replicas)
	for i := range perReplica {
		perReplica[i] = ratelimit.NewMemoryLimiterWithClock(clock)
	}
	shared := ratelimit.NewMemoryLimiterWithClock(clock)

	ctx := context.Background()
	res := result{CeilingPerSec: rate}

	// Offered load is spread evenly across each second; requests round-robin
	// over the replicas, exactly like a load balancer.
	rr := 0
	for s := 0; s < seconds; s++ {
		sample := secondSample{Second: s, OfferedPerSec: int64(offered)}
		for r := 0; r < offered; r++ {
			now = now.Add(time.Second / time.Duration(offered))
			replica := rr % replicas
			rr++

			d1, _ := perReplica[replica].Allow(ctx, "tenant-a", p, "k")
			if d1.Allowed {
				sample.PerReplica++
			}
			d2, _ := shared.Allow(ctx, "tenant-a", p, "k")
			if d2.Allowed {
				sample.SharedStore++
			}
		}
		res.Timeline = append(res.Timeline, sample)
		res.TotalOffered += sample.OfferedPerSec
		res.TotalPerRep += sample.PerReplica
		res.TotalShared += sample.SharedStore
	}

	res.MaxAdmitted = p.MaxAdmitted(time.Duration(seconds) * time.Second)
	if res.TotalShared > 0 {
		res.OverAdmitRatio = float64(res.TotalPerRep) / float64(res.TotalShared)
	}
	out, _ := json.Marshal(res)
	return string(out)
}

func main() {
	js.Global().Set("tgRun", js.FuncOf(tgRun))
	select {} // keep the Go runtime alive for callbacks
}

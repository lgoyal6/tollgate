package gateway

import (
	"context"
	"time"

	"github.com/lgoyal6/tollgate/internal/admin"
	"github.com/lgoyal6/tollgate/internal/outbox"
	"github.com/lgoyal6/tollgate/internal/reqctx"
)

// sealUsageWindows closes one usage window and writes it to the ledger.
//
// The counters come from this replica's own Prometheus registry, which is where
// they already were; what changes is that a closed window now leaves a durable
// row and a durable message instead of only a gauge that a restart resets. The
// request path is untouched: nothing here runs per request.
//
// Deltas against the previous snapshot, because Prometheus counters are
// cumulative and a window is the difference. A counter that went backwards
// means the registry was reset, which for a single process means it restarted;
// that window is skipped rather than recorded as a negative charge.
func (g *Gateway) sealUsageWindows(ctx context.Context, previous map[string]admin.TenantCounters, start, end time.Time) (map[string]admin.TenantCounters, error) {
	current := usageFromMetrics{g.metrics}.TenantUsage()
	var windows []outbox.Window
	for tenant, now := range current {
		// Health probes and rejected keys all land under one metrics label that
		// is not an account. Sealing it would queue a charge every interval,
		// forever, addressed to a tenant no billing system has; a Kubernetes
		// readiness probe alone would keep the outbox permanently non-empty.
		if tenant == reqctx.UnauthenticatedTenant {
			continue
		}
		was := previous[tenant]
		requests := int64(now.Requests - was.Requests)
		if requests <= 0 {
			continue
		}
		windows = append(windows, outbox.Window{
			TenantID: tenant, WindowStart: start, WindowEnd: end,
			Requests:  requests,
			Admitted:  max(int64(now.Admitted-was.Admitted), 0),
			Limited:   max(int64(now.Limited-was.Limited), 0),
			ServerErr: max(int64(now.ServerErr-was.ServerErr), 0),
		})
	}
	if len(windows) == 0 {
		return current, nil
	}
	sealed, err := outbox.SealWindows(ctx, g.store.Pool, windows, nil)
	if err != nil {
		// The snapshot is deliberately NOT advanced on failure, so the next tick
		// bills the whole span rather than losing the traffic in between.
		return previous, err
	}
	g.logger.Debug("usage window sealed", "tenants", sealed, "window_start", start)
	return current, nil
}

// runUsageSealer seals a window every interval until the context is cancelled.
//
// It is a goroutine in the gateway rather than a cron job because the numbers
// live in this process's registry and nowhere else; a separate sealer would
// have nothing to read. Delivery is somebody else's process: cmd/tollgate-outbox
// relay drains what this queues, and can be killed and restarted at will
// precisely because the queue is in Postgres.
func (g *Gateway) runUsageSealer(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	previous := map[string]admin.TenantCounters{}
	start := time.Now().UTC().Truncate(interval)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			end := now.UTC()
			next, err := g.sealUsageWindows(ctx, previous, start, end)
			if err != nil {
				g.logger.Error("sealing usage window", "err", err)
				continue
			}
			previous, start = next, end
		}
	}
}

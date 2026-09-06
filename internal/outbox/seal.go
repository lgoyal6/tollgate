package outbox

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Window is one tenant's counters for one closed interval.
type Window struct {
	TenantID    string
	WindowStart time.Time
	WindowEnd   time.Time
	Requests    int64
	Admitted    int64
	Limited     int64
	ServerErr   int64
}

// CrashPoint names a place the process may be killed, for the crash tests.
// Nothing in the delivery path branches on it beyond calling the hook, so a nil
// hook - the production case - costs a nil check.
type CrashPoint string

const (
	// CrashAfterCommit fires the instant the sealing transaction commits, so
	// the process dies owning a committed ledger row and a committed message it
	// has not begun to deliver.
	CrashAfterCommit CrashPoint = "after_commit"
	// CrashBeforeSend fires after the attempt is durably recorded and before
	// the request leaves. The database cannot tell afterwards whether the
	// request left; that is the point.
	CrashBeforeSend CrashPoint = "before_send"
	// CrashAfterSend fires after the consumer has answered and before the
	// answer is recorded. The consumer has the effect; the producer does not
	// know it.
	CrashAfterSend CrashPoint = "after_send"
)

// Crasher is called at a named point. Tests install one that really kills the
// process; production installs none.
type Crasher func(CrashPoint)

func (c Crasher) at(p CrashPoint) {
	if c != nil {
		c(p)
	}
}

// SealWindows writes the ledger rows and the messages that report them in one
// transaction.
//
// This is the atomic part of "atomic side effects and delivery". Either the
// window is sealed and the charge is queued, or neither. There is no ordering
// of two writes to get wrong because there is only one write.
//
// Re-sealing the same window is a no-op on both tables, so the caller may retry
// freely; that is what makes a crash before the commit harmless.
func SealWindows(ctx context.Context, pool *pgxpool.Pool, windows []Window, crash Crasher) (int, error) {
	if len(windows) == 0 {
		return 0, nil
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("beginning seal tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	sealed := 0
	for _, w := range windows {
		tag, err := tx.Exec(ctx, `
			INSERT INTO usage_ledger
			    (tenant_id, window_start, window_end, requests, admitted, limited, server_err)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id, window_start) DO NOTHING`,
			w.TenantID, w.WindowStart, w.WindowEnd, w.Requests, w.Admitted, w.Limited, w.ServerErr)
		if err != nil {
			return 0, fmt.Errorf("sealing %s at %s: %w", w.TenantID, w.WindowStart, err)
		}
		if tag.RowsAffected() == 0 {
			// Already sealed. The message that reports this window was written
			// by the same transaction that wrote the row, so if the row is here
			// the message was enqueued; re-enqueueing would be asking to be
			// charged twice for a window already accounted for.
			continue
		}
		if err := Enqueue(ctx, tx, UsageKey(w.TenantID, w.WindowStart), TopicUsageSealed, UsageEvent{
			TenantID:    w.TenantID,
			WindowStart: w.WindowStart,
			WindowEnd:   w.WindowEnd,
			Requests:    w.Requests,
			Admitted:    w.Admitted,
			Limited:     w.Limited,
			ServerErr:   w.ServerErr,
		}); err != nil {
			return 0, err
		}
		sealed++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing seal: %w", err)
	}
	crash.at(CrashAfterCommit)
	return sealed, nil
}

// SealWindowsDualWrite is the version without an outbox, kept as the negative
// control for the crash tests: the ledger row commits, then the delivery is
// attempted separately. A process killed between the two has lost the charge
// permanently, and no restart recovers it because nothing recorded that it was
// owed. It is exported so the harness can run it; nothing in the gateway calls
// it.
func SealWindowsDualWrite(ctx context.Context, pool *pgxpool.Pool, windows []Window, sink Sink, crash Crasher) error {
	for _, w := range windows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO usage_ledger
			    (tenant_id, window_start, window_end, requests, admitted, limited, server_err)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id, window_start) DO NOTHING`,
			w.TenantID, w.WindowStart, w.WindowEnd, w.Requests, w.Admitted, w.Limited, w.ServerErr); err != nil {
			return fmt.Errorf("dual-write ledger insert: %w", err)
		}
		crash.at(CrashAfterCommit)
		if _, err := sink.Deliver(ctx, Message{
			IdempotencyKey: UsageKey(w.TenantID, w.WindowStart),
			Topic:          TopicUsageSealed,
			Payload:        mustJSON(UsageEvent{TenantID: w.TenantID, WindowStart: w.WindowStart, WindowEnd: w.WindowEnd, Requests: w.Requests, Admitted: w.Admitted, Limited: w.Limited, ServerErr: w.ServerErr}),
		}); err != nil {
			return fmt.Errorf("dual-write delivery: %w", err)
		}
	}
	return nil
}

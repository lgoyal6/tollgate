// Package outbox carries a side effect and the state change it belongs to
// across a process crash.
//
// The problem it solves is the dual write: commit a row, then make an HTTP
// call. A process killed between the two has produced a state change nobody
// downstream will ever hear about, and no amount of retrying inside the dead
// process helps, because the process is gone. Writing the message into the same
// transaction as the state change removes that window: after the commit, the
// intent to deliver is as durable as the fact it reports.
//
// What this package does NOT do is make delivery happen once. Delivery is
// retried, so the network sees the message more than once. Landing once is the
// consumer's job, and Sink implements it: the effect and the inbox row commit
// together, so a redelivered key applies nothing. See RECORD_c13_outbox.md for
// the precise guarantee and the assumptions it rests on.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// State values as they appear in the outbox.state column.
const (
	StatePending   = "PENDING"
	StateInflight  = "INFLIGHT"
	StateUnknown   = "UNKNOWN"
	StateDelivered = "DELIVERED"
	StateFailed    = "FAILED"
)

// Message is one side effect waiting to be delivered.
type Message struct {
	ID             int64
	IdempotencyKey string
	Topic          string
	Payload        json.RawMessage
	Attempts       int
}

// Enqueue writes a message inside the caller's transaction.
//
// The caller MUST be inside the transaction that performs the state change.
// Passing a pool here instead of a transaction would reintroduce the exact dual
// write this package exists to remove, which is why the signature takes a
// pgx.Tx and not a *pgxpool.Pool.
//
// A repeated key is dropped rather than treated as an error: sealing the same
// usage window twice is a legitimate retry of the producer, and the second
// attempt must not enqueue a second charge.
func Enqueue(ctx context.Context, tx pgx.Tx, key, topic string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding outbox payload for %s: %w", key, err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox (idempotency_key, topic, payload)
		VALUES ($1, $2, $3)
		ON CONFLICT (idempotency_key) DO NOTHING`,
		key, topic, body); err != nil {
		return fmt.Errorf("enqueueing %s: %w", key, err)
	}
	return nil
}

// UsageEvent is the payload for the usage.window.sealed topic.
type UsageEvent struct {
	TenantID    string    `json:"tenant_id"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Requests    int64     `json:"requests"`
	Admitted    int64     `json:"admitted"`
	Limited     int64     `json:"limited"`
	ServerErr   int64     `json:"server_err"`
}

// TopicUsageSealed is the only topic today. It exists as a constant because the
// consumer switches on it and a typo would deliver into nothing.
const TopicUsageSealed = "usage.window.sealed"

// UsageKey is the idempotency key for a sealed window.
//
// It is a function of WHAT happened - this tenant, this window - and never of
// WHEN it was attempted or by whom. A key that varied per attempt would make
// every retry look like a new charge to the consumer, which is the failure this
// whole mechanism is built to avoid.
func UsageKey(tenantID string, windowStart time.Time) string {
	return fmt.Sprintf("usage:%s:%d", tenantID, windowStart.UTC().Unix())
}

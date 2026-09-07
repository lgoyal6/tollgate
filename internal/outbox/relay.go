package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Sink is the downstream. Deliver applies the effect; Lookup answers whether a
// key was already applied.
//
// Lookup is what makes an ambiguous outcome resolvable. Without it a message
// whose attempting process died can only be redelivered and hoped about; with
// it the producer can ask the one party that actually knows.
type Sink interface {
	Deliver(ctx context.Context, m Message) (receipt string, err error)
	Lookup(ctx context.Context, idempotencyKey string) (receipt string, found bool, err error)
}

// ErrNoLookup is what a sink returns from Lookup when it cannot answer. A
// message whose sink cannot answer stays UNKNOWN; nothing guesses on its
// behalf.
var ErrNoLookup = errors.New("sink does not support lookup by idempotency key")

// DeliveryRefusedError means the sink rejected a request before applying its
// effect. Only this explicit classification is safe to retry. A generic error
// may be a lost response after a successful commit and therefore becomes
// UNKNOWN until reconciliation asks the sink what happened.
type DeliveryRefusedError struct {
	Cause error
}

func (e *DeliveryRefusedError) Error() string { return e.Cause.Error() }
func (e *DeliveryRefusedError) Unwrap() error { return e.Cause }

// DeliveryRefused marks an error as a confirmed refusal with no effect.
func DeliveryRefused(cause error) error {
	return &DeliveryRefusedError{Cause: cause}
}

// Relay moves messages out of the outbox. One Relay is one process's worth of
// delivery; several may run at once, and the lease is what keeps them off each
// other's rows.
type Relay struct {
	Pool  *pgxpool.Pool
	Sink  Sink
	Owner string
	// Lease is how long a claimed row is left alone before another pass decides
	// its owner is gone. Too short and a slow but living delivery is declared
	// ambiguous; too long and recovery after a crash waits.
	Lease   time.Duration
	Batch   int
	Backoff func(attempt int) time.Duration
	Crash   Crasher
	Now     func() time.Time
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Relay) backoff(attempt int) time.Duration {
	if r.Backoff != nil {
		return r.Backoff(attempt)
	}
	d := time.Duration(1<<min(attempt, 6)) * time.Second
	return min(d, 60*time.Second)
}

// PassResult reports what one relay pass did.
type PassResult struct {
	Expired   int // INFLIGHT rows whose owner is presumed dead, moved to UNKNOWN
	Claimed   int
	Delivered int
	Unknown   int
	Retrying  int
	Failed    int
}

// Once runs a single pass: expire dead leases, claim what is due, deliver it.
func (r *Relay) Once(ctx context.Context) (PassResult, error) {
	var res PassResult
	expired, err := r.ExpireLeases(ctx)
	if err != nil {
		return res, err
	}
	res.Expired = expired

	msgs, err := r.claim(ctx)
	if err != nil {
		return res, err
	}
	res.Claimed = len(msgs)

	for _, m := range msgs {
		// The attempt is already committed at this point. A process killed on
		// the next line leaves a row that says "attempt N began" and nothing
		// more, which is exactly as much as is true.
		r.Crash.at(CrashBeforeSend)
		receipt, derr := r.Sink.Deliver(ctx, m)
		// The consumer has answered. It has the effect. Nothing in this
		// database knows that yet.
		r.Crash.at(CrashAfterSend)
		if derr != nil {
			var refused *DeliveryRefusedError
			if !errors.As(derr, &refused) {
				if err := r.recordUnknown(ctx, m.ID, derr); err != nil {
					return res, err
				}
				res.Unknown++
				continue
			}
			failed, err := r.recordFailure(ctx, m, derr)
			if err != nil {
				return res, err
			}
			if failed {
				res.Failed++
			} else {
				res.Retrying++
			}
			continue
		}
		if err := r.recordDelivered(ctx, m.ID, receipt, "delivered"); err != nil {
			return res, err
		}
		res.Delivered++
	}
	return res, nil
}

func (r *Relay) recordUnknown(ctx context.Context, id int64, cause error) error {
	_, err := r.Pool.Exec(ctx, `
		UPDATE outbox
		   SET state = 'UNKNOWN',
		       lease_owner = NULL,
		       lease_expires_at = NULL,
		       last_error = $2,
		       updated_at = now()
		 WHERE id = $1`, id, "delivery outcome unknown: "+cause.Error())
	if err != nil {
		return fmt.Errorf("recording ambiguous delivery of %d: %w", id, err)
	}
	return nil
}

// ExpireLeases moves INFLIGHT rows whose lease has run out to UNKNOWN.
//
// It deliberately does NOT move them back to PENDING. Going back to PENDING
// would be asserting that the consumer did not receive the message, which this
// database has no way to know; that assertion is exactly the silent resolution
// this state exists to prevent. UNKNOWN is a claim about our own ignorance and
// is always true.
func (r *Relay) ExpireLeases(ctx context.Context) (int, error) {
	tag, err := r.Pool.Exec(ctx, `
		UPDATE outbox
		   SET state = 'UNKNOWN',
		       lease_owner = NULL,
		       lease_expires_at = NULL,
		       last_error = 'attempting process did not report back before its lease expired',
		       updated_at = now()
		 WHERE state = 'INFLIGHT' AND lease_expires_at < $1`, r.now())
	if err != nil {
		return 0, fmt.Errorf("expiring leases: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// claim takes up to Batch due rows, records the attempt, and commits before any
// delivery is attempted. The commit is the durable attempt state: it is what
// survives the kill.
func (r *Relay) claim(ctx context.Context) ([]Message, error) {
	batch := r.Batch
	if batch <= 0 {
		batch = 32
	}
	now := r.now()
	rows, err := r.Pool.Query(ctx, `
		UPDATE outbox SET
		    state = 'INFLIGHT',
		    attempts = attempts + 1,
		    last_attempt_at = $1,
		    lease_owner = $2,
		    lease_expires_at = $1 + $3::interval,
		    updated_at = now()
		 WHERE id IN (
		     SELECT id FROM outbox
		      WHERE state = 'PENDING' AND next_attempt_at <= $1
		      ORDER BY id
		      FOR UPDATE SKIP LOCKED
		      LIMIT $4
		 )
		 RETURNING id, idempotency_key, topic, payload, attempts`,
		now, r.Owner, fmt.Sprintf("%d milliseconds", r.Lease.Milliseconds()), batch)
	if err != nil {
		return nil, fmt.Errorf("claiming outbox rows: %w", err)
	}
	defer rows.Close()

	var out []Message
	for rows.Next() {
		var m Message
		var payload []byte
		if err := rows.Scan(&m.ID, &m.IdempotencyKey, &m.Topic, &payload, &m.Attempts); err != nil {
			return nil, err
		}
		m.Payload = json.RawMessage(payload)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *Relay) recordDelivered(ctx context.Context, id int64, receipt, resolution string) error {
	_, err := r.Pool.Exec(ctx, `
		UPDATE outbox
		   SET state = 'DELIVERED', receipt = $2, resolution = $3,
		       delivered_at = now(), lease_owner = NULL, lease_expires_at = NULL,
		       last_error = NULL, updated_at = now()
		 WHERE id = $1`, id, receipt, resolution)
	if err != nil {
		return fmt.Errorf("recording delivery of %d: %w", id, err)
	}
	return nil
}

// recordFailure puts a row back in PENDING with a backoff, or gives up. A
// refused delivery is the one case where the producer does know the effect did
// not land, so PENDING is a true statement here in a way it is not after a
// crash.
func (r *Relay) recordFailure(ctx context.Context, m Message, cause error) (bool, error) {
	var state string
	err := r.Pool.QueryRow(ctx, `
		UPDATE outbox
		   SET state = CASE WHEN attempts >= max_attempts THEN 'FAILED' ELSE 'PENDING' END,
		       next_attempt_at = $2,
		       last_error = $3,
		       lease_owner = NULL, lease_expires_at = NULL,
		       updated_at = now()
		 WHERE id = $1
		 RETURNING state`, m.ID, r.now().Add(r.backoff(m.Attempts)), cause.Error()).Scan(&state)
	if err != nil {
		return false, fmt.Errorf("recording failure of %d: %w", m.ID, err)
	}
	return state == StateFailed, nil
}

// ReconcileResult reports how the ambiguous rows were settled.
type ReconcileResult struct {
	Examined int
	// Confirmed: the consumer holds the key, so the effect landed and the
	// producer simply never heard it.
	Confirmed int
	// Absent: the consumer does not hold the key, so redelivery is safe and the
	// row goes back to PENDING.
	Absent int
	// Unresolved: the consumer could not be asked. The row stays UNKNOWN. This
	// number is the one worth alerting on.
	Unresolved int
}

// Reconcile settles UNKNOWN rows by asking the consumer whether it has the key.
//
// Neither outcome is assumed. A consumer that cannot be reached leaves the row
// where it is, and the row stays visible as unresolved for as long as that is
// true. The alternatives - assume delivered, or assume not delivered - are a
// silently lost charge and a silently duplicated one respectively, and the
// negative controls in the record show both happening.
func (r *Relay) Reconcile(ctx context.Context) (ReconcileResult, error) {
	var res ReconcileResult
	rows, err := r.Pool.Query(ctx, `
		SELECT id, idempotency_key FROM outbox WHERE state = 'UNKNOWN' ORDER BY id`)
	if err != nil {
		return res, fmt.Errorf("listing unknown rows: %w", err)
	}
	type pending struct {
		id  int64
		key string
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.key); err != nil {
			rows.Close()
			return res, err
		}
		todo = append(todo, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}

	for _, p := range todo {
		res.Examined++
		receipt, found, err := r.Sink.Lookup(ctx, p.key)
		if err != nil {
			res.Unresolved++
			if _, uerr := r.Pool.Exec(ctx, `
				UPDATE outbox SET last_error = $2, updated_at = now() WHERE id = $1`,
				p.id, "unresolved: "+err.Error()); uerr != nil {
				return res, uerr
			}
			continue
		}
		if found {
			if err := r.recordDelivered(ctx, p.id, receipt, "confirmed_by_consumer_after_crash"); err != nil {
				return res, err
			}
			res.Confirmed++
			continue
		}
		if _, err := r.Pool.Exec(ctx, `
			UPDATE outbox
			   SET state = 'PENDING', next_attempt_at = now(),
			       resolution = 'absent_at_consumer_after_crash',
			       last_error = NULL, updated_at = now()
			 WHERE id = $1`, p.id); err != nil {
			return res, err
		}
		res.Absent++
	}
	return res, nil
}

// Counts reports the outbox by state, for the harness and for an operator.
func Counts(ctx context.Context, pool *pgxpool.Pool) (map[string]int, error) {
	rows, err := pool.Query(ctx, `SELECT state, count(*) FROM outbox GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

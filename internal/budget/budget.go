// Package budget is tollgate's durable spend ledger.
//
// The gateway's rate limiter bounds how many requests a teammate may send. It does
// not bound what they cost, and on an LLM upstream those are different numbers by
// three orders of magnitude. This package adds the money half: a conservative hold
// taken before a request is forwarded, settled against real usage afterwards, and
// durable across a gateway crash.
//
// All amounts are int64 micros (1e-6 USD). No floats anywhere on the money path.
//
// # What the ceiling does and does not guarantee
//
// The hold is computed from the caller's own declared output ceiling (max_tokens)
// and a known model price. It therefore bounds spend only as far as those two hold:
//
//   - If the provider bills MORE than the declared ceiling implies, settlement
//     records the real amount and the tenant can finish above its limit. The
//     overshoot is bounded by one request, is visible in the ledger, and the next
//     request is refused - but it is not prevented. Clamping the settlement to the
//     hold would make the books balance while the invoice did not.
//   - A request with no declared ceiling, or on a model with no known price, has no
//     computable upper bound. Those are tracked, never refused. See EstimateUpperBound.
//
// So this is a budget that stops a runaway loop, not a hard spend cap enforceable
// against an arbitrary upstream.
package budget

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// State of one charge. See migrations/003_budget_ledger.sql for why "uncertain"
// exists and why it is not the same as "released".
type State string

const (
	StateReserved  State = "reserved"
	StateSettled   State = "settled"
	StateReleased  State = "released"
	StateUncertain State = "uncertain"
)

var (
	// ErrOverBudget is returned when a hold would push committed spend past the
	// tenant's limit. The request must not be forwarded.
	ErrOverBudget = errors.New("budget: reservation would exceed tenant limit")
	// ErrNoBudget means the tenant has no budget row; callers decide whether that
	// is "unlimited" or "deny". The gateway treats it as unlimited so enabling this
	// feature cannot brick an existing deployment.
	ErrNoBudget = errors.New("budget: tenant has no budget configured")
	// ErrNotReserved is returned when settling something that was never held.
	ErrNotReserved = errors.New("budget: no open reservation for this request")
)

// Ledger is the durable spend store. Safe for concurrent use.
type Ledger struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Ledger { return &Ledger{pool: pool} }

// Status is a tenant's current position.
type Status struct {
	TenantID  string
	Limit     *int64 // nil = untracked ceiling
	Reserved  int64
	Settled   int64
	Committed int64 // Reserved + Settled: what admission actually compares
	Remaining *int64
}

// Reserve holds upperBoundMicros against the tenant's budget before the request is
// forwarded, and is the only place admission can refuse on cost.
//
// requestID makes this idempotent: replaying the same reserve returns the existing
// hold rather than taking a second one. That matters because a client retry after a
// timeout is indistinguishable, at this layer, from a fresh request.
//
// The tenant row is locked FOR UPDATE for the whole check-and-insert. Without that
// lock two concurrent requests both read the same headroom and both admit - the
// classic oversubscription race, and the one the concurrency test pins.
func (l *Ledger) Reserve(ctx context.Context, tenantID, requestID string, upperBoundMicros int64, model string) (Status, error) {
	if upperBoundMicros < 0 {
		return Status{}, fmt.Errorf("budget: negative reservation %d", upperBoundMicros)
	}
	var st Status
	err := pgx.BeginFunc(ctx, l.pool, func(tx pgx.Tx) error {
		// Idempotency first: if this request already holds (or spent) money, report
		// that and take nothing further.
		var existing State
		err := tx.QueryRow(ctx,
			`SELECT state FROM spend_entries WHERE tenant_id = $1 AND request_id = $2`,
			tenantID, requestID).Scan(&existing)
		if err == nil {
			s, serr := statusTx(ctx, tx, tenantID)
			if serr != nil {
				return serr
			}
			st = s
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		var limit *int64
		var reserved, settled int64
		err = tx.QueryRow(ctx,
			`SELECT limit_micros, reserved_micros, settled_micros
			   FROM tenant_budgets WHERE tenant_id = $1 FOR UPDATE`,
			tenantID).Scan(&limit, &reserved, &settled)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoBudget
		}
		if err != nil {
			return err
		}

		if limit != nil && reserved+settled+upperBoundMicros > *limit {
			return ErrOverBudget
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO spend_entries (tenant_id, request_id, state, reserved_micros, model)
			 VALUES ($1, $2, 'reserved', $3, $4)`,
			tenantID, requestID, upperBoundMicros, nullIfEmpty(model)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE tenant_budgets
			    SET reserved_micros = reserved_micros + $2, updated_at = now()
			  WHERE tenant_id = $1`, tenantID, upperBoundMicros); err != nil {
			return err
		}
		st = mkStatus(tenantID, limit, reserved+upperBoundMicros, settled)
		return nil
	})
	return st, err
}

// Settle converts an open hold into real spend. Idempotent by requestID: a replayed
// provider callback, or a retry of the gateway's own settle, is a no-op.
//
// actualMicros may exceed the hold - providers can bill more than a conservative
// estimate - and the ledger records the truth rather than clamping to the reservation.
// Clamping would make the books balance while the invoice did not.
func (l *Ledger) Settle(ctx context.Context, tenantID, requestID string, actualMicros int64) (Status, error) {
	if actualMicros < 0 {
		return Status{}, fmt.Errorf("budget: negative settlement %d", actualMicros)
	}
	var st Status
	err := pgx.BeginFunc(ctx, l.pool, func(tx pgx.Tx) error {
		var state State
		var held int64
		err := tx.QueryRow(ctx,
			`SELECT state, reserved_micros FROM spend_entries
			  WHERE tenant_id = $1 AND request_id = $2 FOR UPDATE`,
			tenantID, requestID).Scan(&state, &held)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotReserved
		}
		if err != nil {
			return err
		}
		if state == StateSettled || state == StateReleased {
			s, serr := statusTx(ctx, tx, tenantID)
			if serr != nil {
				return serr
			}
			st = s
			return nil // already terminal: idempotent no-op
		}

		if _, err := tx.Exec(ctx,
			`UPDATE spend_entries
			    SET state = 'settled', settled_micros = $3, updated_at = now()
			  WHERE tenant_id = $1 AND request_id = $2`,
			tenantID, requestID, actualMicros); err != nil {
			return err
		}
		// The hold comes off and the real amount goes on, in one statement so the
		// totals are never transiently wrong to a concurrent reader.
		if _, err := tx.Exec(ctx,
			`UPDATE tenant_budgets
			    SET reserved_micros = reserved_micros - $2,
			        settled_micros  = settled_micros + $3,
			        updated_at = now()
			  WHERE tenant_id = $1`, tenantID, held, actualMicros); err != nil {
			return err
		}
		s, serr := statusTx(ctx, tx, tenantID)
		if serr != nil {
			return serr
		}
		st = s
		return nil
	})
	return st, err
}

// Release gives a hold back. Call it ONLY when the request provably never reached
// the upstream. A client that disconnects mid-stream has not proven that: the
// provider may still bill for the whole completion, so that case is MarkUncertain.
func (l *Ledger) Release(ctx context.Context, tenantID, requestID, reason string) error {
	return pgx.BeginFunc(ctx, l.pool, func(tx pgx.Tx) error {
		var state State
		var held int64
		err := tx.QueryRow(ctx,
			`SELECT state, reserved_micros FROM spend_entries
			  WHERE tenant_id = $1 AND request_id = $2 FOR UPDATE`,
			tenantID, requestID).Scan(&state, &held)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotReserved
		}
		if err != nil {
			return err
		}
		if state != StateReserved {
			return nil // settled, already released, or uncertain: leave it alone
		}
		if _, err := tx.Exec(ctx,
			`UPDATE spend_entries SET state='released', settled_micros=0, note=$3,
			                          updated_at=now()
			  WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID, nullIfEmpty(reason)); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`UPDATE tenant_budgets SET reserved_micros = reserved_micros - $2, updated_at=now()
			  WHERE tenant_id = $1`, tenantID, held)
		return err
	})
}

// MarkUncertain records that the outcome is unknown and KEEPS the hold. This is the
// honest state for a stream that broke after bytes went upstream: tollgate cannot
// know what the provider will bill, so the money stays committed until an operator
// or a provider reconciliation resolves it.
func (l *Ledger) MarkUncertain(ctx context.Context, tenantID, requestID, reason string) error {
	ct, err := l.pool.Exec(ctx,
		`UPDATE spend_entries SET state='uncertain', note=$3, updated_at=now()
		  WHERE tenant_id=$1 AND request_id=$2 AND state='reserved'`,
		tenantID, requestID, nullIfEmpty(reason))
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotReserved
	}
	return nil
}

// Status reports a tenant's current position.
func (l *Ledger) Status(ctx context.Context, tenantID string) (Status, error) {
	var st Status
	err := pgx.BeginFunc(ctx, l.pool, func(tx pgx.Tx) error {
		s, err := statusTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		st = s
		return nil
	})
	return st, err
}

// OpenEntry is a hold that outlived its request.
type OpenEntry struct {
	TenantID  string
	RequestID string
	State     State
	Micros    int64
	Age       time.Duration
	Note      string
}

// OpenOlderThan lists holds still open past a cutoff: the recovery scan after a
// gateway crash, and the operator's queue for genuinely stuck money.
func (l *Ledger) OpenOlderThan(ctx context.Context, age time.Duration) ([]OpenEntry, error) {
	rows, err := l.pool.Query(ctx,
		`SELECT tenant_id, request_id, state, reserved_micros,
		        EXTRACT(EPOCH FROM (now() - created_at)), COALESCE(note,'')
		   FROM spend_entries
		  WHERE state IN ('reserved','uncertain')
		    AND created_at < now() - make_interval(secs => $1)
		  ORDER BY created_at`, age.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpenEntry
	for rows.Next() {
		var e OpenEntry
		var secs float64
		if err := rows.Scan(&e.TenantID, &e.RequestID, &e.State, &e.Micros, &secs, &e.Note); err != nil {
			return nil, err
		}
		e.Age = time.Duration(secs * float64(time.Second))
		out = append(out, e)
	}
	return out, rows.Err()
}

// Drift is the gap between a tenant's denormalised totals and the same numbers
// re-derived from the entries. It must be zero; anything else is a bug in this
// package, not a condition to paper over, so the reconcile test asserts on it.
type Drift struct {
	TenantID                    string
	ReservedDelta, SettledDelta int64
}

// Reconcile re-derives every tenant's totals from spend_entries and reports rows
// that disagree with the cached counters.
func (l *Ledger) Reconcile(ctx context.Context) ([]Drift, error) {
	rows, err := l.pool.Query(ctx, `
		SELECT b.tenant_id,
		       b.reserved_micros - COALESCE(d.reserved, 0),
		       b.settled_micros  - COALESCE(d.settled, 0)
		  FROM tenant_budgets b
		  LEFT JOIN (
		      SELECT tenant_id,
		             SUM(reserved_micros) FILTER (WHERE state IN ('reserved','uncertain')) AS reserved,
		             SUM(settled_micros)  FILTER (WHERE state = 'settled')                 AS settled
		        FROM spend_entries GROUP BY tenant_id
		  ) d ON d.tenant_id = b.tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Drift
	for rows.Next() {
		var d Drift
		if err := rows.Scan(&d.TenantID, &d.ReservedDelta, &d.SettledDelta); err != nil {
			return nil, err
		}
		if d.ReservedDelta != 0 || d.SettledDelta != 0 {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

// SetLimit creates or updates a tenant's budget.
func (l *Ledger) SetLimit(ctx context.Context, tenantID string, limitMicros *int64, period string) error {
	if period == "" {
		period = "total"
	}
	_, err := l.pool.Exec(ctx,
		`INSERT INTO tenant_budgets (tenant_id, limit_micros, period)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (tenant_id)
		 DO UPDATE SET limit_micros = EXCLUDED.limit_micros,
		               period = EXCLUDED.period,
		               updated_at = now()`, tenantID, limitMicros, period)
	return err
}

func statusTx(ctx context.Context, tx pgx.Tx, tenantID string) (Status, error) {
	var limit *int64
	var reserved, settled int64
	err := tx.QueryRow(ctx,
		`SELECT limit_micros, reserved_micros, settled_micros
		   FROM tenant_budgets WHERE tenant_id = $1`, tenantID).Scan(&limit, &reserved, &settled)
	if errors.Is(err, pgx.ErrNoRows) {
		return Status{}, ErrNoBudget
	}
	if err != nil {
		return Status{}, err
	}
	return mkStatus(tenantID, limit, reserved, settled), nil
}

func mkStatus(tenantID string, limit *int64, reserved, settled int64) Status {
	st := Status{
		TenantID:  tenantID,
		Limit:     limit,
		Reserved:  reserved,
		Settled:   settled,
		Committed: reserved + settled,
	}
	if limit != nil {
		rem := *limit - st.Committed
		st.Remaining = &rem
	}
	return st
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

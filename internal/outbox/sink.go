package outbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	_ "embed"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed sink_schema.sql
var sinkSchema string

// BillingSink is the consumer: it charges a tenant for a sealed usage window,
// and it is the party that decides how many times that charge lands.
//
// Dedupe is a switch because the negative control needs it off. With it off the
// sink is an ordinary at-least-once consumer and a redelivered message charges
// twice, which is what the crash tests show before turning it on. Nothing in
// the gateway ever constructs one with Dedupe false.
type BillingSink struct {
	Pool   *pgxpool.Pool
	Dedupe bool
}

// MigrateSink creates the consumer's own schema in the consumer's own database.
func MigrateSink(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, sinkSchema); err != nil {
		return fmt.Errorf("creating sink schema: %w", err)
	}
	return nil
}

// ApplyResult reports what the consumer did with one delivery.
type ApplyResult struct {
	Receipt   string `json:"receipt"`
	Duplicate bool   `json:"duplicate"`
}

// Apply charges for a usage window, at most once per idempotency key.
//
// The inbox row and the charge are written in ONE transaction of THIS database.
// That is the entire dedup guarantee: if the charge is visible then so is the
// key that suppresses the next delivery of it, and if the key is visible then
// the charge it stands for was written by the same commit. Splitting them - a
// "have I seen this?" SELECT, then an INSERT - would leave a window where two
// concurrent deliveries both see nothing and both charge.
//
// billing_charges deliberately carries NO unique constraint on
// idempotency_key. If it did, Postgres would be doing the deduplication and
// this inbox would be decoration; the counts in the crash tests would prove a
// property of the schema rather than of the mechanism.
func (s *BillingSink) Apply(ctx context.Context, key, topic string, payload json.RawMessage) (ApplyResult, error) {
	var ev UsageEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return ApplyResult{}, fmt.Errorf("decoding %s: %w", topic, err)
	}
	if topic != TopicUsageSealed {
		return ApplyResult{}, fmt.Errorf("unknown topic %q", topic)
	}

	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	receipt := "rcpt_" + randomHex(12)
	if s.Dedupe {
		var existing string
		err = tx.QueryRow(ctx, `
			INSERT INTO inbox (idempotency_key, topic, payload, receipt)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (idempotency_key) DO NOTHING
			RETURNING receipt`, key, topic, payload, receipt).Scan(&existing)
		if errors.Is(err, pgx.ErrNoRows) {
			// The key is already here, so the charge it stands for is already
			// here too, by the same commit. Report the original receipt and
			// charge nothing. The counter says how loud the relay was being.
			var prior string
			if err := tx.QueryRow(ctx, `
				UPDATE inbox SET deliveries = deliveries + 1
				 WHERE idempotency_key = $1 RETURNING receipt`, key).Scan(&prior); err != nil {
				return ApplyResult{}, fmt.Errorf("reading prior receipt for %s: %w", key, err)
			}
			if err := tx.Commit(ctx); err != nil {
				return ApplyResult{}, err
			}
			return ApplyResult{Receipt: prior, Duplicate: true}, nil
		}
		if err != nil {
			return ApplyResult{}, fmt.Errorf("recording inbox row for %s: %w", key, err)
		}
	} else {
		// Control mode: keep a record of the delivery but let it through.
		if _, err := tx.Exec(ctx, `
			INSERT INTO inbox (idempotency_key, topic, payload, receipt)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (idempotency_key) DO UPDATE SET deliveries = inbox.deliveries + 1`,
			key, topic, payload, receipt); err != nil {
			return ApplyResult{}, err
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO billing_charges (idempotency_key, tenant_id, window_start, requests, amount_cents)
		VALUES ($1, $2, $3, $4, $5)`,
		key, ev.TenantID, ev.WindowStart, ev.Requests, ev.Requests); err != nil {
		return ApplyResult{}, fmt.Errorf("charging %s: %w", ev.TenantID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Receipt: receipt, Duplicate: false}, nil
}

// Receipt answers the reconciliation question: do you have this key?
func (s *BillingSink) Receipt(ctx context.Context, key string) (string, bool, error) {
	var receipt string
	err := s.Pool.QueryRow(ctx, `SELECT receipt FROM inbox WHERE idempotency_key = $1`, key).Scan(&receipt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return receipt, true, nil
}

// Handler is the consumer's HTTP surface: one endpoint to deliver into, one to
// reconcile against.
func (s *BillingSink) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/charges", func(w http.ResponseWriter, req *http.Request) {
		key := req.Header.Get("Idempotency-Key")
		topic := req.Header.Get("X-Outbox-Topic")
		if key == "" || topic == "" {
			http.Error(w, "Idempotency-Key and X-Outbox-Topic are required", http.StatusBadRequest)
			return
		}
		var body json.RawMessage
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res, err := s.Apply(req.Context(), key, topic, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	})
	mux.HandleFunc("GET /v1/charges/{key}", func(w http.ResponseWriter, req *http.Request) {
		receipt, found, err := s.Receipt(req.Context(), req.PathValue("key"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ApplyResult{Receipt: receipt, Duplicate: true})
	})
	return mux
}

// HTTPSink is the producer's view of a remote consumer.
type HTTPSink struct {
	BaseURL string
	Client  *http.Client
	// LookupDisabled models a downstream that offers no way to ask whether it
	// holds a key. Reconciliation then cannot settle anything and says so.
	LookupDisabled bool
}

func (h HTTPSink) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (h HTTPSink) Deliver(ctx context.Context, m Message) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+"/v1/charges", bytes.NewReader(m.Payload))
	if err != nil {
		return "", DeliveryRefused(err)
	}
	req.Header.Set("Idempotency-Key", m.IdempotencyKey)
	req.Header.Set("X-Outbox-Topic", m.Topic)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		err := fmt.Errorf("sink returned %s", resp.Status)
		if resp.StatusCode/100 == 4 {
			return "", DeliveryRefused(err)
		}
		return "", err
	}
	var out ApplyResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Receipt, nil
}

func (h HTTPSink) Lookup(ctx context.Context, key string) (string, bool, error) {
	if h.LookupDisabled {
		return "", false, ErrNoLookup
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.BaseURL+"/v1/charges/"+key, nil)
	if err != nil {
		return "", false, err
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode/100 != 2 {
		return "", false, fmt.Errorf("sink lookup returned %s", resp.Status)
	}
	var out ApplyResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", false, err
	}
	return out.Receipt, true, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

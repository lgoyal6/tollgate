-- Producer side of the transactional outbox.
--
-- The gateway's usage numbers lived only in this process's Prometheus registry,
-- so "what did tenant X burn between 10:00 and 10:01" had no durable answer and
-- nothing downstream could be billed for it. Sealing a window writes the ledger
-- row and the message that reports it in ONE transaction; a relay delivers the
-- message afterwards. The point is that there is no moment where the ledger row
-- exists and the intent to report it does not.

BEGIN;

-- One row per tenant per closed window. The primary key is what makes sealing
-- the same window twice a no-op rather than a double count.
CREATE TABLE IF NOT EXISTS usage_ledger (
    tenant_id    TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end   TIMESTAMPTZ NOT NULL,
    requests     BIGINT      NOT NULL DEFAULT 0 CHECK (requests   >= 0),
    admitted     BIGINT      NOT NULL DEFAULT 0 CHECK (admitted   >= 0),
    limited      BIGINT      NOT NULL DEFAULT 0 CHECK (limited    >= 0),
    server_err   BIGINT      NOT NULL DEFAULT 0 CHECK (server_err >= 0),
    sealed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, window_start),
    CHECK (window_end > window_start)
);

CREATE TABLE IF NOT EXISTS outbox (
    id               BIGSERIAL PRIMARY KEY,
    -- Derived from the state change, never from the attempt, so every retry of
    -- the same fact carries the same key. This is the whole basis of the
    -- consumer's ability to deduplicate.
    idempotency_key  TEXT        NOT NULL UNIQUE,
    topic            TEXT        NOT NULL,
    payload          JSONB       NOT NULL,
    -- PENDING   : never attempted, or an attempt is known to have failed.
    -- INFLIGHT  : an attempt was durably recorded and has not reported back.
    -- UNKNOWN   : the attempting process died. Whether the consumer received
    --             it is not knowable from this database, and nothing here will
    --             guess. Reconciliation asks the consumer.
    -- DELIVERED : the consumer acknowledged, and its receipt is stored.
    -- FAILED    : attempts exhausted. The effect has NOT landed; this is a
    --             deliberate stop, not a success.
    state            TEXT        NOT NULL DEFAULT 'PENDING'
                     CHECK (state IN ('PENDING','INFLIGHT','UNKNOWN','DELIVERED','FAILED')),
    attempts         INT         NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts     INT         NOT NULL DEFAULT 10 CHECK (max_attempts > 0),
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A lease, not a lock: a process that is SIGKILLed cannot release anything,
    -- so the lease has to expire on its own or the row is stranded forever.
    lease_owner      TEXT,
    lease_expires_at TIMESTAMPTZ,
    last_attempt_at  TIMESTAMPTZ,
    last_error       TEXT,
    -- How an UNKNOWN row was settled, kept so the settlement is auditable
    -- rather than inferred from the state alone.
    resolution       TEXT,
    receipt          TEXT,
    delivered_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A delivered row without a receipt would be a claim with no evidence.
    CHECK (state <> 'DELIVERED' OR receipt IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS outbox_due_idx
    ON outbox (next_attempt_at) WHERE state = 'PENDING';
CREATE INDEX IF NOT EXISTS outbox_lease_idx
    ON outbox (lease_expires_at) WHERE state = 'INFLIGHT';
CREATE INDEX IF NOT EXISTS outbox_unresolved_idx
    ON outbox (id) WHERE state = 'UNKNOWN';

COMMIT;

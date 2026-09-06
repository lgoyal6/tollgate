-- Consumer side. This lives in the SINK's own database, not the gateway's, so
-- that "the effect and the inbox row commit together" is a claim about one
-- transaction in one database and not a trick played across two.

BEGIN;

-- The inbox is the deduplication record. A key present here means this sink has
-- already applied the effect for that message, whatever the producer believes.
CREATE TABLE IF NOT EXISTS inbox (
    idempotency_key TEXT PRIMARY KEY,
    topic           TEXT        NOT NULL,
    payload         JSONB       NOT NULL,
    receipt         TEXT        NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Every redelivery bumps this. It is the measure of how much duplicate
    -- traffic the at-least-once relay actually produced.
    deliveries      INT         NOT NULL DEFAULT 1
);

-- The effect. Exactly this table is what "landed once" is counted from.
CREATE TABLE IF NOT EXISTS billing_charges (
    id              BIGSERIAL PRIMARY KEY,
    idempotency_key TEXT        NOT NULL REFERENCES inbox(idempotency_key),
    tenant_id       TEXT        NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    requests        BIGINT      NOT NULL,
    amount_cents    BIGINT      NOT NULL,
    charged_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS billing_charges_tenant_idx
    ON billing_charges (tenant_id, window_start);

COMMIT;

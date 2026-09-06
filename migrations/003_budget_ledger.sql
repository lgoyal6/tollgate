-- Durable spend budgets.
--
-- tollgate already stops a teammate sending too many *requests*. The problem the
-- README actually describes - "someone's agent loop goes runaway at 3am and the
-- shared budget is gone" - is about *money*, and a rate limit does not bound it: one
-- request inside the rate limit can cost more than a thousand cheap ones.
--
-- Money is BIGINT micros (1 micro = 1e-6 USD, so $1.00 = 1000000). Never floating
-- point: provider prices are quoted in dollars per million tokens, and repeatedly
-- adding IEEE-754 fractions to a running balance loses cents.
--
-- Lifecycle of one charge, and why it has four states rather than two:
--
--   reserved  -> a conservative upper bound is held BEFORE the request is forwarded,
--                because the true cost is only known after the response. Admission
--                compares limit against settled + reserved, so concurrent requests
--                cannot each be admitted against the same headroom.
--   settled   -> the request finished and reported real usage. Terminal.
--   released  -> the request provably never reached the upstream (connection refused,
--                admission rejected downstream). Only then is the hold given back.
--   uncertain -> the stream broke after bytes were sent upstream. Liability is unknown,
--                so the reservation is KEPT. Releasing here is the bug that lets a
--                client disconnect mid-stream to get its usage for free.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_budgets (
    tenant_id       TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- NULL limit means "track spend but never refuse" - useful before prices are known.
    limit_micros    BIGINT CHECK (limit_micros IS NULL OR limit_micros >= 0),
    period          TEXT NOT NULL DEFAULT 'total'
                    CHECK (period IN ('total', 'daily', 'monthly')),
    period_start    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Denormalised running totals. Kept in the same transaction as the entry that
    -- moves them, so they can never drift from spend_entries; the reconcile query in
    -- queries.go re-derives both and is the check that they have not.
    reserved_micros BIGINT NOT NULL DEFAULT 0 CHECK (reserved_micros >= 0),
    settled_micros  BIGINT NOT NULL DEFAULT 0 CHECK (settled_micros >= 0),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS spend_entries (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Caller-supplied idempotency key. Unique per tenant, so a retried settle or a
    -- replayed callback cannot double-charge, and a duplicate reserve returns the
    -- existing hold instead of taking a second one.
    request_id    TEXT NOT NULL,
    state         TEXT NOT NULL
                  CHECK (state IN ('reserved', 'settled', 'released', 'uncertain')),
    reserved_micros BIGINT NOT NULL CHECK (reserved_micros >= 0),
    settled_micros  BIGINT CHECK (settled_micros IS NULL OR settled_micros >= 0),
    model         TEXT,
    note          TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, request_id)
);

-- Recovery scan: "which holds outlived their request?" after a gateway crash.
CREATE INDEX IF NOT EXISTS spend_entries_open_idx
    ON spend_entries (tenant_id, state, created_at)
    WHERE state IN ('reserved', 'uncertain');

-- Deliberately NO tollgate_notify_config trigger here: spend changes on every
-- request, and waking every replica's config watcher that often would turn the
-- hot-reload channel into a firehose.

COMMIT;

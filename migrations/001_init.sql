-- tollgate schema: tenants, routes, api_keys, and NOTIFY triggers that drive
-- the gateway's zero-restart hot reload.

BEGIN;

CREATE TABLE IF NOT EXISTS tenants (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    rl_algorithm  TEXT NOT NULL DEFAULT 'token_bucket'
                  CHECK (rl_algorithm IN ('token_bucket', 'sliding_window')),
    -- token bucket
    rl_rate       DOUBLE PRECISION NOT NULL DEFAULT 50 CHECK (rl_rate > 0),
    rl_burst      BIGINT NOT NULL DEFAULT 100 CHECK (rl_burst > 0),
    -- sliding window log
    rl_window_ms  BIGINT NOT NULL DEFAULT 1000 CHECK (rl_window_ms > 0),
    rl_limit      BIGINT NOT NULL DEFAULT 50 CHECK (rl_limit > 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS routes (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    path_prefix    TEXT NOT NULL CHECK (path_prefix LIKE '/%'),
    upstream_url   TEXT NOT NULL,
    strip_prefix   BOOLEAN NOT NULL DEFAULT false,
    timeout_ms     BIGINT NOT NULL DEFAULT 5000 CHECK (timeout_ms > 0),
    retry_max      INT NOT NULL DEFAULT 0 CHECK (retry_max >= 0 AND retry_max <= 5),
    hedge_enabled  BOOLEAN NOT NULL DEFAULT false,
    hedge_delay_ms BIGINT NOT NULL DEFAULT 50 CHECK (hedge_delay_ms > 0),
    required_scope TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, path_prefix)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    secret_hash  BYTEA NOT NULL,
    scopes       TEXT[] NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'grace', 'revoked')),
    grace_until  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS routes_tenant_idx ON routes (tenant_id);

-- Any change to gateway config wakes every replica's watcher.
CREATE OR REPLACE FUNCTION tollgate_notify_config() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('tollgate_config', TG_TABLE_NAME);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tenants_notify ON tenants;
CREATE TRIGGER tenants_notify
    AFTER INSERT OR UPDATE OR DELETE ON tenants
    FOR EACH STATEMENT EXECUTE FUNCTION tollgate_notify_config();

DROP TRIGGER IF EXISTS routes_notify ON routes;
CREATE TRIGGER routes_notify
    AFTER INSERT OR UPDATE OR DELETE ON routes
    FOR EACH STATEMENT EXECUTE FUNCTION tollgate_notify_config();

DROP TRIGGER IF EXISTS api_keys_notify ON api_keys;
CREATE TRIGGER api_keys_notify
    AFTER INSERT OR UPDATE OR DELETE ON api_keys
    FOR EACH STATEMENT EXECUTE FUNCTION tollgate_notify_config();

COMMIT;

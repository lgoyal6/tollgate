-- Per-route upstream credential injection: the route names a header and an
-- environment variable; the gateway injects `<header>: <prefix><$env>` on the
-- outbound request. The secret itself never touches the database — it lives
-- in the gateway's environment (compose env / Kubernetes Secret), so the
-- shared provider key stays out of teammates' hands AND out of Postgres.

BEGIN;

ALTER TABLE routes
    ADD COLUMN IF NOT EXISTS upstream_auth_header TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS upstream_auth_env    TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS upstream_auth_prefix TEXT NOT NULL DEFAULT '';

COMMIT;

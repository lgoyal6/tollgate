-- One optional fallback upstream per route.
--
-- Deliberately four nullable-by-default columns on `routes` rather than a
-- candidates table. A route may have exactly one fallback, so a table would
-- model a cardinality the gateway does not have and would need a constraint to
-- take it back again. Every existing row gets '' and behaves exactly as before:
-- no operator action, no backfill, no migration window.
--
-- The fallback names its own credential the same way the primary does: a header,
-- an environment variable and a prefix. The secret itself never touches the
-- database. A fallback upstream is usually a different provider with a different
-- key, so sharing the primary's env var would be the wrong default and the kind
-- of wrong that sends one provider's credential to another provider.

BEGIN;

ALTER TABLE routes
    ADD COLUMN IF NOT EXISTS fallback_upstream_url  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fallback_auth_header   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fallback_auth_env      TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fallback_auth_prefix   TEXT NOT NULL DEFAULT '';

COMMIT;

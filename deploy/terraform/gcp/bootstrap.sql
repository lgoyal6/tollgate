-- Applied once, as the postgres role, after `terraform apply`. The environment
-- is not reproducible without it, and Terraform cannot express it: there is no
-- postgres provider in this module and these are grants inside the instance,
-- not resources on it.
--
-- What it fixes, measured rather than assumed. Cloud SQL for PostgreSQL grants
-- every user it creates membership in cloudsqlsuperuser, and cloudsqlsuperuser
-- owns every database created through the API. So immediately after apply:
--
--   tollgate_prod  -> connects to tollgate_stage   SUCCEEDS
--   tollgate_stage -> connects to tollgate_prod    SUCCEEDS
--
-- even with REVOKE CONNECT ... FROM PUBLIC in place, because the roles reach
-- the databases as their owner and not as PUBLIC. One login role per
-- environment is a naming convention until the shared owner role is taken away.

-- 0. PostgreSQL 16 will not hand a database to a role the current role is not
--    a member of, so the admin role joins each one first. This is the only
--    reason these two lines exist; nothing else uses the membership.
GRANT tollgate_prod  TO postgres;
GRANT tollgate_stage TO postgres;

-- 1. Each database is owned by the role that serves it, not by a role every
--    other environment is also a member of.
ALTER DATABASE tollgate_prod  OWNER TO tollgate_prod;
ALTER DATABASE tollgate_stage OWNER TO tollgate_stage;

-- 2. Drop the shared membership that made every role equivalent.
REVOKE cloudsqlsuperuser FROM tollgate_prod;
REVOKE cloudsqlsuperuser FROM tollgate_stage;

-- 3. And only then does restricting CONNECT mean anything.
REVOKE CONNECT ON DATABASE tollgate_prod  FROM PUBLIC;
REVOKE CONNECT ON DATABASE tollgate_stage FROM PUBLIC;
GRANT  CONNECT ON DATABASE tollgate_prod  TO tollgate_prod;
GRANT  CONNECT ON DATABASE tollgate_stage TO tollgate_stage;

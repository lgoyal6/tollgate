-- Demo tenants for local development and load testing. Upstream hostnames
-- are parameterized: scripts/seed.sh substitutes __UPSTREAM_A__ and
-- __UPSTREAM_B__ for the environment (compose vs. kubernetes).
--
-- API keys are issued separately via tollgate-admin (hashes never live in
-- seed files); scripts/seed.sh does that too.

BEGIN;

INSERT INTO tenants (id, name, rl_algorithm, rl_rate, rl_burst, rl_window_ms, rl_limit) VALUES
  -- Baseline/benchmark tenant: limits high enough to never trip while
  -- measuring pure proxy overhead.
  ('loadtest', 'Load Test',    'token_bucket',   200000, 400000, 1000, 200000),
  -- The distributed-correctness demo tenant: exactly 300 admissions/second,
  -- sliding window so the ceiling is crisp.
  ('metered',  'Metered',      'sliding_window', 50, 100, 1000, 300),
  -- Token bucket demo tenant with a small burst.
  ('bursty',   'Bursty',       'token_bucket',   100, 200, 1000, 100),
  -- The noisy neighbour in the fairness test: modest quota it will exceed.
  ('noisy',    'Noisy Tenant', 'sliding_window', 50, 100, 1000, 200),
  -- The well-behaved victim in the fairness test.
  ('quiet',    'Quiet Tenant', 'sliding_window', 50, 100, 1000, 200)
ON CONFLICT (id) DO UPDATE SET
  rl_algorithm = EXCLUDED.rl_algorithm,
  rl_rate      = EXCLUDED.rl_rate,
  rl_burst     = EXCLUDED.rl_burst,
  rl_window_ms = EXCLUDED.rl_window_ms,
  rl_limit     = EXCLUDED.rl_limit;

INSERT INTO routes (tenant_id, path_prefix, upstream_url, strip_prefix, timeout_ms, retry_max, hedge_enabled, hedge_delay_ms) VALUES
  ('loadtest', '/echo/',  'http://__UPSTREAM_A__', true, 5000, 0, false, 50),
  ('loadtest', '/slow/',  'http://__UPSTREAM_B__', true, 5000, 1, true,  60),
  ('metered',  '/echo/',  'http://__UPSTREAM_A__', true, 5000, 0, false, 50),
  ('bursty',   '/echo/',  'http://__UPSTREAM_A__', true, 5000, 0, false, 50),
  ('noisy',    '/echo/',  'http://__UPSTREAM_A__', true, 5000, 0, false, 50),
  ('quiet',    '/echo/',  'http://__UPSTREAM_A__', true, 5000, 0, false, 50)
ON CONFLICT (tenant_id, path_prefix) DO UPDATE SET
  upstream_url = EXCLUDED.upstream_url,
  strip_prefix = EXCLUDED.strip_prefix,
  timeout_ms   = EXCLUDED.timeout_ms,
  retry_max    = EXCLUDED.retry_max,
  hedge_enabled = EXCLUDED.hedge_enabled,
  hedge_delay_ms = EXCLUDED.hedge_delay_ms;

COMMIT;

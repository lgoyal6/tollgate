-- Token bucket, atomic check-and-decrement.
--
-- KEYS[1]  bucket key (hash with fields: tokens, ts)
-- ARGV[1]  capacity (burst), integer > 0
-- ARGV[2]  refill rate, tokens per second, float > 0
-- ARGV[3]  cost of this request, integer > 0
-- ARGV[4]  key TTL in milliseconds
--
-- Returns {allowed (0|1), remaining tokens (string, floor), retry_after_ms (int)}
--
-- Time comes from Redis TIME, not the gateway, so every replica shares one
-- clock and replica clock skew cannot corrupt the bucket. Redis >= 5
-- replicates scripts by effects, so writing after TIME is safe.
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2]) -- microseconds

local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end

local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
tokens = tokens + (elapsed * rate / 1000000)
if tokens > capacity then tokens = capacity end

local allowed = 0
local retry_after_ms = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_after_ms = math.ceil(((cost - tokens) / rate) * 1000)
end

redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', KEYS[1], ttl)

return {allowed, tostring(math.floor(tokens)), retry_after_ms}

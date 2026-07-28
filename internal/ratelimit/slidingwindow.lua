-- Sliding window log, atomic check-and-insert.
--
-- KEYS[1]  window key (sorted set: score = arrival time in microseconds)
-- ARGV[1]  limit: max requests per window, integer > 0
-- ARGV[2]  window size in milliseconds
-- ARGV[3]  unique member suffix (request id) so two replicas admitting in
--          the same microsecond cannot collapse into one ZSET member
--
-- Returns {allowed (0|1), remaining (int), retry_after_ms (int)}
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2]) -- microseconds

local limit = tonumber(ARGV[1])
local window_us = tonumber(ARGV[2]) * 1000

redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window_us)
local count = redis.call('ZCARD', KEYS[1])

local allowed = 0
local retry_after_ms = 0
if count < limit then
  redis.call('ZADD', KEYS[1], now, tostring(now) .. '-' .. ARGV[3])
  allowed = 1
  count = count + 1
else
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  if oldest[2] then
    retry_after_ms = math.ceil((tonumber(oldest[2]) + window_us - now) / 1000)
    if retry_after_ms < 1 then retry_after_ms = 1 end
  else
    retry_after_ms = 1
  end
end

redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]) + 1000)

local remaining = limit - count
if remaining < 0 then remaining = 0 end
return {allowed, remaining, retry_after_ms}

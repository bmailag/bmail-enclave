// Package ratelimit provides Redis-backed distributed rate limiting with
// automatic in-memory fallback when Redis is unavailable.
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisOpTimeout  = 2 * time.Second
	maxInMemBuckets = 10000
)

// RedisRateLimiter provides distributed rate limiting backed by Redis.
// If Redis is unavailable, it falls back to an in-memory counter map.
type RedisRateLimiter struct {
	redis  *redis.Client
	prefix string // Redis key prefix

	// In-memory fallback.
	mu       sync.Mutex
	counters map[string]*bucket
	nowFunc  func() time.Time // injectable for testing
}

type bucket struct {
	count     int
	windowEnd time.Time
}

// Option configures a RedisRateLimiter.
type Option func(*RedisRateLimiter)

// WithRedis sets the Redis client for distributed rate limiting.
func WithRedis(rdb *redis.Client) Option {
	return func(rl *RedisRateLimiter) { rl.redis = rdb }
}

// WithPrefix sets the Redis key prefix (e.g., "auth:login:").
func WithPrefix(prefix string) Option {
	return func(rl *RedisRateLimiter) { rl.prefix = prefix }
}

// New creates a new distributed rate limiter.
func New(opts ...Option) *RedisRateLimiter {
	rl := &RedisRateLimiter{
		prefix:   "ratelimit:",
		counters: make(map[string]*bucket),
		nowFunc:  time.Now,
	}
	for _, opt := range opts {
		opt(rl)
	}
	return rl
}

// luaIncr atomically increments a key and sets expiry on first access.
var luaIncr = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return count
`)

// Allow checks whether an operation identified by key should be allowed
// within the given limit and window.
func (rl *RedisRateLimiter) Allow(key string, limit int, window time.Duration) bool {
	fullKey := rl.prefix + key

	// Try Redis first.
	if rl.redis != nil {
		allowed, err := rl.allowRedis(fullKey, limit, window)
		if err == nil {
			return allowed
		}
		slog.Warn("ratelimit: redis unavailable, falling back to in-memory", "prefix", rl.prefix, "error", err)
	}

	return rl.allowInMemory(fullKey, limit, window)
}

func (rl *RedisRateLimiter) allowRedis(key string, limit int, window time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
	defer cancel()

	windowSec := int(window.Seconds())
	if windowSec < 1 {
		windowSec = 1
	}

	count, err := luaIncr.Run(ctx, rl.redis, []string{key}, windowSec).Int64()
	if err != nil {
		return false, err
	}

	return count <= int64(limit), nil
}

func (rl *RedisRateLimiter) allowInMemory(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.nowFunc()

	b, exists := rl.counters[key]
	if !exists || now.After(b.windowEnd) {
		rl.counters[key] = &bucket{
			count:     1,
			windowEnd: now.Add(window),
		}
		if len(rl.counters) > maxInMemBuckets {
			rl.cleanStaleLocked(now)
		}
		return true
	}

	b.count++
	return b.count <= limit
}

func (rl *RedisRateLimiter) cleanStaleLocked(now time.Time) {
	for k, b := range rl.counters {
		if now.After(b.windowEnd) {
			delete(rl.counters, k)
		}
	}
}

// Count returns the current count for a key (for testing/monitoring).
func (rl *RedisRateLimiter) Count(key string) int {
	fullKey := rl.prefix + key

	if rl.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
		defer cancel()
		val, err := rl.redis.Get(ctx, fullKey).Int()
		if err == nil {
			return val
		}
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if b, ok := rl.counters[fullKey]; ok {
		return b.count
	}
	return 0
}

// String returns a description of the limiter (for logging).
func (rl *RedisRateLimiter) String() string {
	if rl.redis != nil {
		return fmt.Sprintf("RedisRateLimiter{prefix=%s, redis=connected}", rl.prefix)
	}
	return fmt.Sprintf("RedisRateLimiter{prefix=%s, redis=nil (in-memory)}", rl.prefix)
}

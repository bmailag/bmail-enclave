package smtp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// connSalt is a random per-process secret mixed into IP hashes so that the
// daily hash output is unpredictable across server restarts.
var (
	connSalt     [32]byte
	connSaltOnce sync.Once
)

func initConnSalt() {
	connSaltOnce.Do(func() {
		if _, err := rand.Read(connSalt[:]); err != nil {
			panic("smtp: failed to generate conn rate-limit salt: " + err.Error())
		}
	})
}

// dailySalt rotates daily to prevent long-term IP tracking via Redis keys.
var (
	ipSalt     []byte
	ipSaltDay  int
	ipSaltLock sync.Mutex
)

// hashIP produces a privacy-preserving, daily-rotated hash of an IP address.
// Raw IPs must never be stored in Redis (which runs outside the SGX enclave).
func hashIP(ip string) string {
	initConnSalt()

	ipSaltLock.Lock()
	today := time.Now().UTC().YearDay()
	if ipSalt == nil || today != ipSaltDay {
		h := sha256.Sum256(append(connSalt[:], []byte(fmt.Sprintf("smtp-conn-salt:%d:%d", time.Now().UTC().Year(), today))...))
		ipSalt = h[:]
		ipSaltDay = today
	}
	salt := ipSalt
	ipSaltLock.Unlock()

	h := sha256.Sum256(append(salt, []byte(ip)...))
	return hex.EncodeToString(h[:16]) // 128-bit hash is sufficient for rate limiting
}

const (
	// Default per-IP connection rate limit (connections per window).
	defaultConnRateLimit = 30

	// Default rate limit window duration.
	defaultConnRateWindow = 1 * time.Minute

	// Redis key prefix for SMTP connection rate limiting.
	smtpRateKeyPrefix = "smtp:rate:"
)

// ConnRateLimiter provides per-IP inbound connection rate limiting.
// It uses Redis as the primary backend and falls back to an in-memory
// map when Redis is unavailable.
type ConnRateLimiter struct {
	redis  *redis.Client
	limit  int
	window time.Duration

	// In-memory fallback.
	mu       sync.Mutex
	counters map[string]*connBucket
	nowFunc  func() time.Time // injectable for testing
}

type connBucket struct {
	count     int
	windowEnd time.Time
}

// ConnRateLimitOption configures a ConnRateLimiter.
type ConnRateLimitOption func(*ConnRateLimiter)

// WithConnRateRedis sets the Redis client for distributed rate limiting.
func WithConnRateRedis(rdb *redis.Client) ConnRateLimitOption {
	return func(rl *ConnRateLimiter) { rl.redis = rdb }
}

// WithConnRateLimit sets the maximum connections per window per IP.
func WithConnRateLimit(limit int) ConnRateLimitOption {
	return func(rl *ConnRateLimiter) { rl.limit = limit }
}

// WithConnRateWindow sets the rate limit window duration.
func WithConnRateWindow(d time.Duration) ConnRateLimitOption {
	return func(rl *ConnRateLimiter) { rl.window = d }
}

// NewConnRateLimiter creates a new per-IP connection rate limiter.
// If no Redis client is provided, it operates purely in-memory.
func NewConnRateLimiter(opts ...ConnRateLimitOption) *ConnRateLimiter {
	rl := &ConnRateLimiter{
		limit:    defaultConnRateLimit,
		window:   defaultConnRateWindow,
		counters: make(map[string]*connBucket),
		nowFunc:  time.Now,
	}
	for _, opt := range opts {
		opt(rl)
	}
	return rl
}

// Allow checks whether a connection from the given address should be allowed.
// The addr should be a net.Addr from the SMTP connection (host:port format).
func (rl *ConnRateLimiter) Allow(addr net.Addr) bool {
	ip := extractIP(addr)
	if ip == "" {
		return true // can't determine IP, allow
	}

	// Hash the IP before storing in Redis or in-memory maps.
	// Raw IPs must not leak outside the enclave via Redis keys.
	hashedIP := hashIP(ip)

	// Try Redis first.
	if rl.redis != nil {
		allowed, err := rl.allowRedis(hashedIP)
		if err == nil {
			return allowed
		}
		// Redis unavailable — log once and fall through to in-memory.
		slog.Warn("smtp rate limiter: redis unavailable, falling back to in-memory", "error", err)
	}

	return rl.allowInMemory(hashedIP)
}

// rateLimitLua atomically increments a key and sets expiry on first access.
// This prevents the race where INCR succeeds but EXPIRE fails, leaving a key without TTL.
var rateLimitLua = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return count
`)

// allowRedis uses a Redis Lua script for atomic rate limiting.
func (rl *ConnRateLimiter) allowRedis(ip string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := fmt.Sprintf("%s%s", smtpRateKeyPrefix, ip)
	windowSec := int(rl.window.Seconds())

	count, err := rateLimitLua.Run(ctx, rl.redis, []string{key}, windowSec).Int64()
	if err != nil {
		return false, err
	}

	return count <= int64(rl.limit), nil
}

// allowInMemory provides a fallback using a simple in-memory map.
func (rl *ConnRateLimiter) allowInMemory(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.nowFunc()

	bucket, exists := rl.counters[ip]
	if !exists || now.After(bucket.windowEnd) {
		rl.counters[ip] = &connBucket{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		// Opportunistically clean stale entries.
		if len(rl.counters) > 10000 {
			rl.cleanStaleLocked(now)
		}
		return true
	}

	bucket.count++
	return bucket.count <= rl.limit
}

// cleanStaleLocked removes expired entries. Must be called with mu held.
func (rl *ConnRateLimiter) cleanStaleLocked(now time.Time) {
	for k, b := range rl.counters {
		if now.After(b.windowEnd) {
			delete(rl.counters, k)
		}
	}
}

// extractIP extracts the IP address from a net.Addr.
func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}

package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bmailag/bmail/internal/ratelimit"
)

// CountMinSketch is a probabilistic data structure for frequency estimation.
// It provides approximate counts with a guarantee of never underestimating.
type CountMinSketch struct {
	width  int
	depth  int
	matrix [][]uint64
	mu     sync.Mutex
}

// NewCountMinSketch creates a new count-min sketch with the given width and depth.
// Width controls accuracy; depth controls confidence.
func NewCountMinSketch(width, depth int) *CountMinSketch {
	matrix := make([][]uint64, depth)
	for i := range matrix {
		matrix[i] = make([]uint64, width)
	}
	return &CountMinSketch{
		width:  width,
		depth:  depth,
		matrix: matrix,
	}
}

// Increment adds one to the count for the given key.
func (cms *CountMinSketch) Increment(key []byte) {
	cms.mu.Lock()
	defer cms.mu.Unlock()
	for i := 0; i < cms.depth; i++ {
		idx := cms.hash(i, key)
		cms.matrix[i][idx]++
	}
}

// Estimate returns the approximate count for the given key.
// The returned value is always >= the true count.
func (cms *CountMinSketch) Estimate(key []byte) int {
	cms.mu.Lock()
	defer cms.mu.Unlock()
	var min uint64 = ^uint64(0)
	for i := 0; i < cms.depth; i++ {
		idx := cms.hash(i, key)
		if cms.matrix[i][idx] < min {
			min = cms.matrix[i][idx]
		}
	}
	return int(min)
}

// hash computes the index for row i using SHA-256 keyed by the row index.
func (cms *CountMinSketch) hash(row int, key []byte) int {
	var h hash.Hash = sha256.New()
	rowBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(rowBytes, uint32(row))
	h.Write(rowBytes)
	h.Write(key)
	sum := h.Sum(nil)
	val := binary.BigEndian.Uint64(sum[:8])
	return int(val % uint64(cms.width))
}

// Reset zeroes out all counters in the sketch.
func (cms *CountMinSketch) Reset() {
	cms.mu.Lock()
	defer cms.mu.Unlock()
	for i := range cms.matrix {
		for j := range cms.matrix[i] {
			cms.matrix[i][j] = 0
		}
	}
}

// GatewayRateLimiter provides privacy-preserving rate limiting.
// Authenticated requests are rate-limited by user_id (via Redis when available).
// Unauthenticated requests use a count-min sketch keyed by H(IP || daily_salt)
// so that IP addresses are never stored in the clear.
type GatewayRateLimiter struct {
	authLimit   int // per minute
	unauthLimit int // per minute
	redisRL     *ratelimit.RedisRateLimiter // optional Redis-backed limiter for auth users

	mu          sync.Mutex
	authCounts  map[string]*rateBucket
	unauthSketch *CountMinSketch
	dailySalt   [32]byte
	saltRotated time.Time

	// window tracking for unauthenticated: we reset the sketch every minute
	windowStart time.Time
}

// rateBucket tracks request count within a time window.
type rateBucket struct {
	count     int
	windowStart time.Time
}

// NewGatewayRateLimiter creates a rate limiter with the given limits.
// If redisRL is non-nil, authenticated user limits are enforced via Redis
// for multi-instance consistency. Unauthenticated limits always use the
// privacy-preserving count-min sketch (IP hashes never leave the process).
//
// Session validation lives in the sessionrl subpackage; this limiter
// stays auth-free so the gateway enclave's import closure does not pull
// in internal/auth.
func NewGatewayRateLimiter(authLimit, unauthLimit int, redisRL ...*ratelimit.RedisRateLimiter) *GatewayRateLimiter {
	salt := [32]byte{}
	rand.Read(salt[:])
	now := time.Now()
	rl := &GatewayRateLimiter{
		authLimit:    authLimit,
		unauthLimit:  unauthLimit,
		authCounts:   make(map[string]*rateBucket),
		unauthSketch: NewCountMinSketch(4096, 4),
		dailySalt:    salt,
		saltRotated:  now,
		windowStart:  now,
	}
	if len(redisRL) > 0 && redisRL[0] != nil {
		rl.redisRL = redisRL[0]
	}
	return rl
}

// AuthLimit returns the configured per-minute limit for authenticated users.
// Used by middleware in other packages that want to set X-RateLimit-Limit
// headers without reaching into private fields.
func (rl *GatewayRateLimiter) AuthLimit() int {
	return rl.authLimit
}

// rotateSaltIfNeeded rotates the daily salt and resets the sketch.
// Must be called with mu held.
func (rl *GatewayRateLimiter) rotateSaltIfNeeded(now time.Time) {
	if now.Sub(rl.saltRotated) >= 24*time.Hour {
		rand.Read(rl.dailySalt[:])
		rl.saltRotated = now
		rl.unauthSketch.Reset()
	}
}

// resetWindowIfNeeded resets the sketch counters every minute.
// Must be called with mu held.
func (rl *GatewayRateLimiter) resetWindowIfNeeded(now time.Time) {
	if now.Sub(rl.windowStart) >= time.Minute {
		rl.unauthSketch.Reset()
		rl.windowStart = now
		// Also clean stale auth buckets.
		for k, b := range rl.authCounts {
			if now.Sub(b.windowStart) >= time.Minute {
				delete(rl.authCounts, k)
			}
		}
	}
}

// Allow checks whether a request should be allowed. It returns true if allowed.
func (rl *GatewayRateLimiter) Allow(userID string, remoteAddr string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()

	rl.rotateSaltIfNeeded(now)
	rl.resetWindowIfNeeded(now)

	if userID != "" {
		// Use Redis for authenticated rate limiting when available (multi-instance safe).
		if rl.redisRL != nil {
			return rl.redisRL.Allow("gateway:auth:"+userID, rl.authLimit, time.Minute)
		}
		// Fallback to in-memory.
		bucket, ok := rl.authCounts[userID]
		if !ok || now.Sub(bucket.windowStart) >= time.Minute {
			rl.authCounts[userID] = &rateBucket{count: 1, windowStart: now}
			return true
		}
		bucket.count++
		return bucket.count <= rl.authLimit
	}

	// Unauthenticated: if limit is 0, skip (IP-based limiting handled elsewhere).
	if rl.unauthLimit <= 0 {
		return true
	}

	// Hash IP with daily salt, then use Redis if available.
	key := hashIPWithSalt(remoteAddr, rl.dailySalt[:])
	if rl.redisRL != nil {
		// Use the hex-encoded hash as the Redis key (no raw IPs in Redis).
		return rl.redisRL.Allow("gateway:unauth:"+hex.EncodeToString(key), rl.unauthLimit, time.Minute)
	}
	// Fallback to count-min sketch.
	rl.unauthSketch.Increment(key)
	return rl.unauthSketch.Estimate(key) <= rl.unauthLimit
}

// hashIPWithSalt computes SHA-256(normalizedIP || salt).
// IPv6 addresses are normalized via net.ParseIP to prevent bypass
// via equivalent representations (e.g. ::1 vs 0:0:0:0:0:0:0:1).
func hashIPWithSalt(remoteAddr string, salt []byte) []byte {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	// Normalize IP address representation.
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	h := sha256.New()
	h.Write([]byte(host))
	h.Write(salt)
	return h.Sum(nil)
}

// ExtractClientIP returns the real client IP.
//
// Priority:
//  1. CF-Connecting-IP — set by Cloudflare, contains the true client IP.
//     Trusted because the gateway is only reachable through CF (firewall).
//  2. X-Real-IP / X-Forwarded-For — trusted only when RemoteAddr is loopback
//     (request came from a local reverse proxy like nginx).
//  3. RemoteAddr — direct TCP peer, used as fallback.
func ExtractClientIP(r *http.Request) string {
	// Cloudflare always sets CF-Connecting-IP to the real visitor IP.
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}

	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return r.RemoteAddr // Direct connection — use RemoteAddr as-is
	}
	// Request came from local proxy — trust forwarded headers.
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Use the first (leftmost) entry — set by the outermost proxy.
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	return r.RemoteAddr
}

// IPOnlyRateLimitMiddleware returns middleware that rate-limits purely by IP
// address using the privacy-preserving count-min sketch. This is for services
// that have no session context (e.g. the standalone auth service).
// Client IP is auto-detected from loopback (see extractClientIP).
func IPOnlyRateLimitMiddleware(limit int) func(http.Handler) http.Handler {
	limiter := NewGatewayRateLimiter(limit, limit)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := ExtractClientIP(r)
			if !limiter.Allow("", clientIP) {
				w.Header().Set("Retry-After", "60")
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
				w.Header().Set("X-RateLimit-Remaining", "0")
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

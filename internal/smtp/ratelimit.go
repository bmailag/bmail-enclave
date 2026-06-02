package smtp

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/bmailag/bmail/internal/ratelimit"
)

// Rate limit tiers (messages per day). Names mirror the values stored
// in users.tier, so callers can pass `user.Tier` straight in.
const (
	TierFree       = "free"
	TierMail       = "mail"
	TierUnlimited  = "unlimited"
	TierBusiness   = "business"
	TierEnterprise = "enterprise"
	// Legacy alias retained so older call sites compile; treated like
	// "mail" for limit purposes.
	TierPaid = "paid"

	// Daily send caps. Free is intentionally tight (real personal use
	// is well under this — anyone routinely sending more is either a
	// power user who should be paying or a spammer); paid is a generous
	// ceiling that mostly exists as a tripwire for hijacked accounts
	// rather than a meaningful cap on real use.
	limitFree     = 15
	limitMail     = 1000
	limitBusiness = 5000

	// Per-tenant (custom domain) aggregate daily send cap. Protects the
	// shared outbound IP from a single tenant flooding (many mailboxes, or
	// one compromised mailbox) even when each mailbox stays under its own
	// per-user cap. Generous tripwire, not a tight cap; tune via
	// WithTenantDailyCap. 0 = disabled.
	tenantDailyCapDefault = 10000

	// First 72h of a new free account: 5/day with 3 unique recipients.
	// Anti-abuse layer — spammers can't economically scale fake accounts
	// when each one is limited to 5 outbound for 3 days. After the window
	// expires, the account moves to standard limitFree (25/day).
	// Paid signups skip this ramp entirely (skin in the game).
	newFreeAccountWindow      = 72 * time.Hour
	newFreeAccountDailyLimit  = 5
	newFreeAccountUniqueRcpts = 3

	// Per-message recipient cap (enforced separately in handleSend).
	// Free: 5 unique recipients per message. Paid: no per-message cap.
	maxRecipientsPerMessageFree = 5
)

type accountCounter struct {
	count     int
	windowEnd time.Time
	createdAt time.Time
}

// RateLimiter provides per-user outbound rate limiting.
// Uses Redis when available for multi-instance consistency, with in-memory fallback.
type RateLimiter struct {
	mu             sync.Mutex
	counters       map[uuid.UUID]*accountCounter
	tenantCounters map[uuid.UUID]*accountCounter // per-tenant aggregate (in-memory fallback)
	tenantDailyCap int
	nowFunc        func() time.Time // injectable for testing
	redisRL        *ratelimit.RedisRateLimiter
}

// RateLimiterOption configures a RateLimiter.
type RateLimiterOption func(*RateLimiter)

// WithSMTPRedis sets the Redis-backed rate limiter for distributed SMTP limiting.
func WithSMTPRedis(rl *ratelimit.RedisRateLimiter) RateLimiterOption {
	return func(r *RateLimiter) { r.redisRL = rl }
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter(opts ...RateLimiterOption) *RateLimiter {
	rl := &RateLimiter{
		counters:       make(map[uuid.UUID]*accountCounter),
		tenantCounters: make(map[uuid.UUID]*accountCounter),
		tenantDailyCap: tenantDailyCapDefault,
		nowFunc:        time.Now,
	}
	for _, opt := range opts {
		opt(rl)
	}
	return rl
}

// WithTenantDailyCap overrides the per-tenant aggregate daily send cap.
// 0 disables per-tenant limiting.
func WithTenantDailyCap(n int) RateLimiterOption {
	return func(r *RateLimiter) { r.tenantDailyCap = n }
}

// AllowTenant enforces the per-tenant aggregate daily send cap (custom-domain
// shared-IP protection), independent of per-user limits. Returns true if
// allowed. A zero/negative configured cap disables the check.
func (rl *RateLimiter) AllowTenant(tenantID uuid.UUID) bool {
	limit := rl.tenantDailyCap
	if limit <= 0 {
		return true
	}
	if rl.redisRL != nil {
		return rl.redisRL.Allow("smtp:send:tenant:"+tenantID.String(), limit, 24*time.Hour)
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.nowFunc()
	ac, exists := rl.tenantCounters[tenantID]
	if !exists {
		ac = &accountCounter{windowEnd: now.Truncate(24 * time.Hour).Add(24 * time.Hour), createdAt: now}
		rl.tenantCounters[tenantID] = ac
	}
	if now.After(ac.windowEnd) {
		ac.count = 0
		ac.windowEnd = now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	}
	if ac.count >= limit {
		return false
	}
	ac.count++
	return true
}

// RegisterAccount registers a new account for new-account throttling.
// Call this when a user is first created.
func (rl *RateLimiter) RegisterAccount(userID uuid.UUID) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.nowFunc()
	rl.counters[userID] = &accountCounter{
		count:     0,
		windowEnd: now.Truncate(24 * time.Hour).Add(24 * time.Hour),
		createdAt: now,
	}
}

// Allow checks whether the user is allowed to send another message given their tier.
// Returns true if allowed, false if rate limited.
//
// Free tier accounts in their first 72h are clamped to
// newFreeAccountDailyLimit regardless of the standard tier limit. Paid
// accounts are not subject to the new-account ramp.
func (rl *RateLimiter) Allow(userID uuid.UUID, tier string) bool {
	limit := tierLimit(tier)

	// First-72h ramp on new free accounts. Implemented in-memory so it
	// works even without Redis (the in-memory counter is per-receiver,
	// per-process; in a multi-instance deploy a spammer could in theory
	// double-dip across instances during the ramp window, but Redis
	// also enforces the daily tier cap as the authoritative bound).
	rl.mu.Lock()
	now := rl.nowFunc()
	ac, exists := rl.counters[userID]
	if tier == TierFree && exists && now.Before(ac.createdAt.Add(newFreeAccountWindow)) {
		// Reset counter if window has expired.
		if now.After(ac.windowEnd) {
			ac.count = 0
			ac.windowEnd = now.Truncate(24 * time.Hour).Add(24 * time.Hour)
		}
		if ac.count >= newFreeAccountDailyLimit {
			rl.mu.Unlock()
			return false
		}
		ac.count++
		rl.mu.Unlock()

		// Also check Redis for tier limit if available — defence in depth.
		if rl.redisRL != nil {
			if !rl.redisRL.Allow("smtp:send:"+userID.String(), limit, 24*time.Hour) {
				return false
			}
		}
		return true
	}
	rl.mu.Unlock()

	// Use Redis when available for distributed enforcement.
	if rl.redisRL != nil {
		return rl.redisRL.Allow("smtp:send:"+userID.String(), limit, 24*time.Hour)
	}

	// In-memory fallback.
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if !exists {
		ac = &accountCounter{
			count:     0,
			windowEnd: now.Truncate(24 * time.Hour).Add(24 * time.Hour),
			createdAt: now,
		}
		rl.counters[userID] = ac
	}

	// Reset counter if window has expired.
	if now.After(ac.windowEnd) {
		ac.count = 0
		ac.windowEnd = now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	}

	if ac.count >= limit {
		return false
	}

	ac.count++
	return true
}

// tierLimit returns the daily message limit for the given tier. Unknown
// tiers default to free.
func tierLimit(tier string) int {
	switch tier {
	case TierMail, TierUnlimited, TierPaid:
		return limitMail
	case TierBusiness, TierEnterprise:
		return limitBusiness
	default:
		return limitFree
	}
}

// MaxRecipientsPerMessage returns the per-message recipient cap for a
// given tier. Free is hard-capped at maxRecipientsPerMessageFree to
// break spam economics; paid tiers have no per-message cap (return 0,
// meaning "no limit").
func MaxRecipientsPerMessage(tier string) int {
	if tier == TierFree {
		return maxRecipientsPerMessageFree
	}
	return 0
}

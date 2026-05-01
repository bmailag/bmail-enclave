package smtp

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// bounceRateLimiter tracks bounce generation per source domain to mitigate
// backscatter attacks. An attacker who forges MAIL FROM addresses could
// otherwise cause us to flood innocent third parties with DSNs.
type bounceRateLimiter struct {
	mu     sync.Mutex
	counts map[string]*bounceBucket
	limit  int
	window time.Duration
}

type bounceBucket struct {
	count       int
	windowStart time.Time
}

var defaultBounceLimiter = &bounceRateLimiter{
	counts: make(map[string]*bounceBucket),
	limit:  10,
	window: time.Minute,
}

// AllowBounce checks whether a bounce to the given source address is permitted
// under the current rate limit. Returns false if the limit is exceeded.
// Keyed by full address (not just domain) to prevent backscatter amplification
// via multiple forged sender addresses on the same domain.
func AllowBounce(sourceAddress string) bool {
	return defaultBounceLimiter.allow(sourceAddress)
}

func (l *bounceRateLimiter) allow(domain string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	// Evict expired entries when the map grows too large.
	if len(l.counts) > 10000 {
		for k, b := range l.counts {
			if now.Sub(b.windowStart) > l.window {
				delete(l.counts, k)
			}
		}
	}

	bucket, ok := l.counts[domain]
	if !ok || now.Sub(bucket.windowStart) > l.window {
		l.counts[domain] = &bounceBucket{count: 1, windowStart: now}
		return true
	}
	if bucket.count >= l.limit {
		return false
	}
	bucket.count++
	return true
}

// GenerateBounce produces an RFC 3464 Delivery Status Notification (DSN).
// If permanent is true, it generates a failure DSN (5.x.x codes).
// If permanent is false, it generates a delayed/retry-exhausted DSN (4.x.x codes).
// Returns the RFC 5322 formatted bounce message as bytes.
//
// Security note: For internal Bmail recipients, the caller must encrypt
// this DSN with the recipient's public key before storing it (same as any
// other message). For external senders (outbound bounces), the DSN must
// remain plaintext per RFC 3461 — this is an accepted risk documented in
// ARCHITECTURE.md.
// sanitizeHeader strips CR, LF, and NUL characters to prevent header injection.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ", "\x00", "").Replace(s)
}

func GenerateBounce(originalFrom, originalTo, reason string, permanent bool) []byte {
	originalFrom = sanitizeHeader(originalFrom)
	originalTo = sanitizeHeader(originalTo)
	now := time.Now().UTC()
	date := now.Format(time.RFC1123Z)
	bounceDomain := "bmail.ag"
	if idx := strings.LastIndex(originalFrom, "@"); idx >= 0 {
		bounceDomain = originalFrom[idx+1:]
	}
	msgID := fmt.Sprintf("<%d.bounce@%s>", now.UnixNano(), bounceDomain)

	subject := "Delivery Status Notification (Delayed)"
	statusCode := "4.0.0"
	action := "delayed"
	if permanent {
		subject = "Delivery Status Notification (Failure)"
		statusCode = "5.0.0"
		action = "failed"
	}

	boundary := fmt.Sprintf("=_bmail_dsn_%d", now.UnixNano())

	var b strings.Builder

	// RFC 5322 headers
	fmt.Fprintf(&b, "From: mailer-daemon@%s\r\n", bounceDomain)
	fmt.Fprintf(&b, "To: %s\r\n", originalFrom)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", date)
	fmt.Fprintf(&b, "Message-ID: %s\r\n", msgID)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/report; report-type=delivery-status;\r\n")
	fmt.Fprintf(&b, "\tboundary=\"%s\"\r\n", boundary)
	fmt.Fprintf(&b, "\r\n")

	// Part 1: Human-readable explanation
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&b, "\r\n")
	if permanent {
		fmt.Fprintf(&b, "Your message to %s could not be delivered.\r\n", originalTo)
		fmt.Fprintf(&b, "\r\n")
		fmt.Fprintf(&b, "This is a permanent error. The message will not be retried.\r\n")
	} else {
		fmt.Fprintf(&b, "Delivery of your message to %s has been delayed.\r\n", originalTo)
		fmt.Fprintf(&b, "\r\n")
		fmt.Fprintf(&b, "The server has exhausted all retry attempts.\r\n")
	}
	fmt.Fprintf(&b, "\r\n")
	// Sanitize reason to prevent CRLF header injection.
	sanitizedReason := strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ", "\x00", "").Replace(reason)
	fmt.Fprintf(&b, "Diagnostic information:\r\n")
	fmt.Fprintf(&b, "%s\r\n", sanitizedReason)
	fmt.Fprintf(&b, "\r\n")

	// Part 2: message/delivery-status (RFC 3464 Section 2.2)
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: message/delivery-status\r\n")
	fmt.Fprintf(&b, "\r\n")
	// Per-message DSN fields
	fmt.Fprintf(&b, "Reporting-MTA: dns; bmail.ag\r\n")
	fmt.Fprintf(&b, "Arrival-Date: %s\r\n", date)
	fmt.Fprintf(&b, "\r\n")
	// Per-recipient DSN fields
	fmt.Fprintf(&b, "Final-Recipient: rfc822; %s\r\n", originalTo)
	fmt.Fprintf(&b, "Action: %s\r\n", action)
	fmt.Fprintf(&b, "Status: %s\r\n", statusCode)
	fmt.Fprintf(&b, "Diagnostic-Code: smtp; %s\r\n", sanitizedReason)
	fmt.Fprintf(&b, "\r\n")

	// Closing boundary
	fmt.Fprintf(&b, "--%s--\r\n", boundary)

	return []byte(b.String())
}

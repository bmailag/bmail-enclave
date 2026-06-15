// Package gateway provides privacy-preserving middleware and handlers for
// the Bmail API gateway running inside an SGX enclave.
package gateway

import (
	"net/http"
	"strings"
)

// allowedHeaders is the whitelist of request headers forwarded to handlers.
// Everything else is silently dropped to prevent privacy leaks.
var allowedHeaders = map[string]bool{
	"Authorization":    true,
	"Content-Type":     true,
	"Content-Length":   true,
	"Accept":           true,
	"X-Csrf-Token":     true,
	"X-Request-Id":     true,
	"Last-Event-Id":    true, // SSE reconnect
	"Cache-Control":    true,
	"If-None-Match":    true,
	"Origin":           true, // needed for CORS (handled by CORS middleware)
	"Stripe-Signature": true, // Stripe webhook signature verification
	"X-Client-Type":     true, // mobile client identification
	"X-Account-Index":   true, // multi-account cookie selection
	"X-Platform-Secret": true, // platform admin authentication (localhost only)
	"X-Meet-Secret":     true, // meet service participant-cap lookup (server-to-server)
}

// SessionCookieName is the name of the session cookie used by the gateway.
const SessionCookieName = "bmail_session"

// SanitizeMiddleware enforces a whitelist of allowed request headers.
// Only explicitly allowed headers are forwarded; all others are dropped.
// No information about the request source is logged.
func SanitizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rebuild header map with only allowed headers.
		sanitized := make(http.Header)
		for key, values := range r.Header {
			if allowedHeaders[http.CanonicalHeaderKey(key)] {
				sanitized[http.CanonicalHeaderKey(key)] = values
			}
		}

		// Preserve bmail cookies (session, refresh, CSRF, affiliate).
		var preservedCookies []*http.Cookie
		for _, c := range r.Cookies() {
			if strings.HasPrefix(c.Name, "bmail_") {
				preservedCookies = append(preservedCookies, c)
			}
		}
		// Clear Cookie header (it was already removed by whitelist), then re-add preserved cookies.
		delete(sanitized, "Cookie")
		r.Header = sanitized
		for _, c := range preservedCookies {
			r.AddCookie(c)
		}

		// Enforce Accept header to only allow application/json.
		accept := r.Header.Get("Accept")
		if accept != "" && accept != "application/json" && accept != "*/*" {
			r.Header.Set("Accept", "application/json")
		}

		next.ServeHTTP(w, r)
	})
}

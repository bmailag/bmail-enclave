package security

import (
	"net/http"
)

// SecurityHeaders is an HTTP middleware that adds standard security headers
// to every response. These headers protect against common web attacks:
//
//   - Content-Security-Policy: restricts resource loading to same origin + WASM
//   - X-Content-Type-Options: prevents MIME-sniffing
//   - X-Frame-Options: prevents clickjacking
//   - Strict-Transport-Security: enforces HTTPS with a 1-year max-age + preload
//   - Referrer-Policy: prevents leaking URLs in the Referer header
//   - Permissions-Policy: disables unnecessary browser APIs
//   - X-XSS-Protection: legacy XSS filter (disabled in favor of CSP)
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// CSP: default to self, allow connect to self for API calls.
		// F-11: 'wasm-unsafe-eval' is required because Go's WASM runtime uses
		// WebAssembly.instantiate() to compile the crypto module (web/wasm/main.go).
		// This is the least-privilege directive for WASM — strictly more restrictive
		// than 'unsafe-eval' and only permits WebAssembly compilation, not eval().
		// See W3C CSP Level 3: https://w3c.github.io/webappsec-csp/#directive-script-src
		// Cloudflare Turnstile loads its API script from challenges.cloudflare.com
		// and renders the widget inside an iframe sourced from the same origin.
		// Without explicit script-src and frame-src entries, the widget fails
		// silently — the script never loads (script-src 'self') and the
		// iframe is blocked (frame-src falls back to default-src 'self').
		// Adding the origin to both directives is the documented Turnstile
		// integration requirement; nothing else is needed (the widget's own
		// network calls happen inside the frame and don't inherit our CSP).
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				// blob: — the DeepFilterNet3 noise-suppression worklet (in the
				// embedded Meet tab) registers via an AudioWorklet.addModule()
				// on a same-origin blob: URL. blob: URLs are page-created and
				// same-origin, so this is a mild relaxation (no third party).
				"script-src 'self' 'wasm-unsafe-eval' blob: https://challenges.cloudflare.com; "+
				"style-src 'self'; "+
				"img-src 'self' data:; "+
				// F-36: api.github.com previously allowed here so /verify
				// could fetch release JSON cross-origin. Now proxied via
				// the gateway's /verify/latest-release +
				// /verify/latest-enclave-release endpoints, so connect-src
				// is back to just 'self'. Closes the "any XSS can exfil
				// to a Gist via the GitHub allowance" amplifier.
				// meet.{fullxp.net,bmail.ag} + wss: the embedded Meet tab
				// (<MeetRoom>) runs on bmail's origin and talks to the meet
				// service (/v1/* + wss signaling). Its runtime assets load
				// same-origin from /meet-assets, so only connect-src needs
				// the meet origin — not script-src/worker-src.
				// *.meet.bmail.ag:7443 — the SFU fleet nodes the meet client
				// opens a LiveKit wss to once a room switches to SFU (the
				// per-node Caddy TLS endpoint). connect-src governs WebSockets,
				// so without this the SFU signaling socket is blocked (mesh is
				// unaffected — ICE/TURN isn't gated by connect-src).
				"connect-src 'self' https://meet.fullxp.net wss://meet.fullxp.net https://meet.bmail.ag wss://meet.bmail.ag https://*.meet.bmail.ag:7443 wss://*.meet.bmail.ag:7443; "+
				"font-src 'self'; "+
				"frame-src 'self' https://challenges.cloudflare.com; "+
				"object-src 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'")

		// Prevent MIME sniffing.
		h.Set("X-Content-Type-Options", "nosniff")

		// Prevent framing (clickjacking).
		h.Set("X-Frame-Options", "DENY")

		// HSTS: 1 year, include subdomains, preload eligible.
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Do not send referrer to other origins.
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Disable unnecessary browser features.
		h.Set("Permissions-Policy",
			"camera=(self), microphone=(self), geolocation=(), payment=(), usb=()")

		// Legacy XSS protection header — set to 0 because modern CSP is better
		// and the filter itself can introduce vulnerabilities.
		h.Set("X-XSS-Protection", "0")

		next.ServeHTTP(w, r)
	})
}

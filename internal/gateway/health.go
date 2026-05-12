package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// The Metrics struct + /metrics HTTP endpoint that used to live in
// this file were removed: they published running request counts,
// latency histograms, memory, goroutines, and uptime, which together
// let an outside observer estimate active users and traffic patterns.
// On a privacy-focused mail server that's a side channel — not
// something to keep around even bearer-gated. Health + readiness
// remain (no per-request observation, no user-correlated state).

// HealthHandler returns an HTTP handler for the /healthz endpoint.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// DependencyChecker checks a single dependency's health.
type DependencyChecker func(ctx context.Context) error

// ReadinessChecker aggregates dependency checks for /readyz endpoints.
type ReadinessChecker struct {
	checks map[string]DependencyChecker
}

// NewReadinessChecker creates a new ReadinessChecker.
func NewReadinessChecker() *ReadinessChecker {
	return &ReadinessChecker{checks: make(map[string]DependencyChecker)}
}

// Add registers a named dependency check.
func (rc *ReadinessChecker) Add(name string, check DependencyChecker) {
	rc.checks[name] = check
}

// Handler returns an HTTP handler that runs all checks and returns 200 or 503.
func (rc *ReadinessChecker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		results := make(map[string]string)
		allOK := true
		for name, check := range rc.checks {
			if err := check(ctx); err != nil {
				results[name] = err.Error()
				allOK = false
			} else {
				results[name] = "ok"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if !allOK {
			w.WriteHeader(http.StatusServiceUnavailable)
			results["status"] = "not ready"
		} else {
			results["status"] = "ready"
		}
		json.NewEncoder(w).Encode(results)
	}
}

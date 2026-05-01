package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// latencyBucketBounds defines the upper bounds (in seconds) for each histogram bucket.
var latencyBucketBounds = [11]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Metrics tracks basic service metrics without external dependencies.
type Metrics struct {
	startTime      time.Time
	requestCount   atomic.Int64
	errorCount     atomic.Int64

	// Latency histogram (overall, not per-endpoint).
	latencyBuckets [11]atomic.Int64 // cumulative counts for each bucket bound
	latencySum     atomic.Int64     // total duration in microseconds
	latencyCount   atomic.Int64     // total observations

	// Status code family counters: index 0=1xx, 1=2xx, 2=3xx, 3=4xx, 4=5xx, 5=other.
	statusCounts [6]atomic.Int64
}

// NewMetrics creates a new Metrics tracker.
func NewMetrics() *Metrics {
	return &Metrics{startTime: time.Now()}
}

// IncRequests increments the request counter.
func (m *Metrics) IncRequests() { m.requestCount.Add(1) }

// IncErrors increments the error counter.
func (m *Metrics) IncErrors() { m.errorCount.Add(1) }

// MetricsMiddleware wraps a handler to count requests and errors.
func (m *Metrics) MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.IncRequests()
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		if rw.status >= 500 {
			m.IncErrors()
		}
		m.recordLatency(time.Since(start))
		m.recordStatus(rw.status)
	})
}

// recordLatency updates the latency histogram with the given duration.
func (m *Metrics) recordLatency(d time.Duration) {
	sec := d.Seconds()
	for i, bound := range latencyBucketBounds {
		if sec <= bound {
			m.latencyBuckets[i].Add(1)
		}
	}
	m.latencySum.Add(int64(d / time.Microsecond))
	m.latencyCount.Add(1)
}

// recordStatus increments the counter for the given HTTP status code family.
func (m *Metrics) recordStatus(code int) {
	idx := code/100 - 1 // 1xx->0, 2xx->1, ...5xx->4
	if idx < 0 || idx > 4 {
		idx = 5 // other
	}
	m.statusCounts[idx].Add(1)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush implements http.Flusher by delegating to the underlying ResponseWriter.
// Required for SSE (Server-Sent Events) to work through the metrics middleware.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

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

// MetricsHandler returns an HTTP handler for the /metrics endpoint.
// Outputs metrics in Prometheus exposition text format (no PII).
func (m *Metrics) MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		fmt.Fprintf(w, "# HELP bmail_http_requests_total Total HTTP requests\n")
		fmt.Fprintf(w, "# TYPE bmail_http_requests_total counter\n")
		fmt.Fprintf(w, "bmail_http_requests_total %d\n", m.requestCount.Load())

		fmt.Fprintf(w, "# HELP bmail_http_errors_total Total HTTP 5xx errors\n")
		fmt.Fprintf(w, "# TYPE bmail_http_errors_total counter\n")
		fmt.Fprintf(w, "bmail_http_errors_total %d\n", m.errorCount.Load())

		fmt.Fprintf(w, "# HELP bmail_uptime_seconds Service uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE bmail_uptime_seconds gauge\n")
		fmt.Fprintf(w, "bmail_uptime_seconds %.1f\n", time.Since(m.startTime).Seconds())

		fmt.Fprintf(w, "# HELP bmail_goroutines Current number of goroutines\n")
		fmt.Fprintf(w, "# TYPE bmail_goroutines gauge\n")
		fmt.Fprintf(w, "bmail_goroutines %d\n", runtime.NumGoroutine())

		fmt.Fprintf(w, "# HELP bmail_alloc_bytes Current heap allocation in bytes\n")
		fmt.Fprintf(w, "# TYPE bmail_alloc_bytes gauge\n")
		fmt.Fprintf(w, "bmail_alloc_bytes %d\n", memStats.Alloc)

		fmt.Fprintf(w, "# HELP bmail_sys_bytes Total memory obtained from OS\n")
		fmt.Fprintf(w, "# TYPE bmail_sys_bytes gauge\n")
		fmt.Fprintf(w, "bmail_sys_bytes %d\n", memStats.Sys)

		fmt.Fprintf(w, "# HELP bmail_gc_cycles_total Total GC cycles\n")
		fmt.Fprintf(w, "# TYPE bmail_gc_cycles_total counter\n")
		fmt.Fprintf(w, "bmail_gc_cycles_total %d\n", memStats.NumGC)

		// Latency histogram
		fmt.Fprintf(w, "# HELP bmail_http_request_duration_seconds HTTP request latency in seconds\n")
		fmt.Fprintf(w, "# TYPE bmail_http_request_duration_seconds histogram\n")
		var cumulative int64
		for i, bound := range latencyBucketBounds {
			cumulative += m.latencyBuckets[i].Load()
			fmt.Fprintf(w, "bmail_http_request_duration_seconds_bucket{le=\"%g\"} %d\n", bound, cumulative)
		}
		totalCount := m.latencyCount.Load()
		fmt.Fprintf(w, "bmail_http_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", totalCount)
		fmt.Fprintf(w, "bmail_http_request_duration_seconds_sum %.6f\n", float64(m.latencySum.Load())/1e6)
		fmt.Fprintf(w, "bmail_http_request_duration_seconds_count %d\n", totalCount)

		// Per-status-code-family counters
		fmt.Fprintf(w, "# HELP bmail_http_requests_by_status HTTP requests by status code family\n")
		fmt.Fprintf(w, "# TYPE bmail_http_requests_by_status counter\n")
		families := []string{"1xx", "2xx", "3xx", "4xx", "5xx", "other"}
		for i, fam := range families {
			cnt := m.statusCounts[i].Load()
			if cnt > 0 {
				fmt.Fprintf(w, "bmail_http_requests_by_status{family=\"%s\"} %d\n", fam, cnt)
			}
		}
	}
}

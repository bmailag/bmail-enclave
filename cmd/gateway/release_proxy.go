package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// releaseProxy serves /verify/latest-release and
// /verify/latest-enclave-release. The /verify page used to fetch these
// directly from api.github.com; F-36 removes api.github.com from the
// gateway's connect-src CSP so an XSS can't piggyback on the GitHub
// allowance to exfil. This proxy hits the same two URLs server-side,
// caches for 5 minutes, and returns the JSON unchanged.
//
// Hardcoded URL allowlist — these are the only two GitHub endpoints
// the verify page needs. Nothing on this handler is user-controlled,
// so no SSRF surface to defend against.

type releaseProxy struct {
	client http.Client
	mu     sync.Mutex
	cache  map[string]releaseCacheEntry
}

type releaseCacheEntry struct {
	body        []byte
	contentType string
	expires     time.Time
}

const releaseCacheTTL = 5 * time.Minute

var releaseURLs = map[string]string{
	"latest-release":         "https://api.github.com/repos/bmailag/bmail/releases/latest",
	"latest-enclave-release": "https://api.github.com/repos/bmailag/bmail-enclave/releases/latest",
}

func newReleaseProxy() *releaseProxy {
	return &releaseProxy{
		client: http.Client{Timeout: 10 * time.Second},
		cache:  make(map[string]releaseCacheEntry),
	}
}

func (p *releaseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/verify/")
	upstream, ok := releaseURLs[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Cache hit?
	p.mu.Lock()
	if entry, ok := p.cache[name]; ok && time.Now().Before(entry.expires) {
		body := entry.body
		ct := entry.contentType
		p.mu.Unlock()
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(body)
		return
	}
	p.mu.Unlock()

	// Fetch upstream.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream, nil)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "bmail-verify-proxy/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "upstream returned non-200", http.StatusBadGateway)
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB cap is plenty for GH release JSON
	if err != nil {
		http.Error(w, "upstream read failed", http.StatusBadGateway)
		return
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}

	p.mu.Lock()
	p.cache[name] = releaseCacheEntry{
		body:        body,
		contentType: ct,
		expires:     time.Now().Add(releaseCacheTTL),
	}
	p.mu.Unlock()

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(body)
}

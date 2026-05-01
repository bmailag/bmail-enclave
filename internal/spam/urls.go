package spam

import (
	"net/url"
	"regexp"
	"strings"
)

// urlRegex matches HTTP(S) URLs in text.
var urlRegex = regexp.MustCompile(`https?://[^\s<>"'\)]+`)

// hrefRegex extracts href values from HTML anchor tags.
var hrefRegex = regexp.MustCompile(`(?i)href\s*=\s*["']?(https?://[^"'\s>]+)`)

// defaultShorteners is the set of known URL shortener domains.
var defaultShorteners = map[string]bool{
	"bit.ly":      true,
	"t.co":        true,
	"goo.gl":      true,
	"tinyurl.com": true,
	"ow.ly":       true,
	"is.gd":       true,
	"buff.ly":     true,
	"rebrand.ly":  true,
	"short.io":    true,
	"cutt.ly":     true,
	"rb.gy":       true,
}

// ExtractURLs extracts all URLs from a message body (plaintext and HTML).
func ExtractURLs(body []byte) []string {
	seen := make(map[string]bool)
	var urls []string

	text := string(body)

	// Extract from plain text (capped to prevent resource exhaustion).
	for _, match := range urlRegex.FindAllString(text, 1000) {
		clean := strings.TrimRight(match, ".,;:!?")
		if !seen[clean] {
			seen[clean] = true
			urls = append(urls, clean)
		}
	}

	// Extract from HTML href attributes.
	for _, submatch := range hrefRegex.FindAllStringSubmatch(text, 1000) {
		if len(submatch) > 1 {
			clean := strings.TrimRight(submatch[1], ".,;:!?")
			if !seen[clean] {
				seen[clean] = true
				urls = append(urls, clean)
			}
		}
	}

	return urls
}

// ScoreURLs scores a list of URLs based on shortener usage and blocklist matches.
// Each shortener hit adds 1.0, each blocklist match adds 3.0.
func ScoreURLs(urls []string, blocklist map[string]bool) float64 {
	if blocklist == nil {
		blocklist = make(map[string]bool)
	}

	var score float64
	checkedShorteners := make(map[string]bool)
	checkedBlocked := make(map[string]bool)

	for _, rawURL := range urls {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if host == "" {
			continue
		}

		// Check URL shorteners (score once per shortener domain).
		if defaultShorteners[host] && !checkedShorteners[host] {
			score += 1.0
			checkedShorteners[host] = true
		}

		// Check blocklist (score once per blocked domain).
		if blocklist[host] && !checkedBlocked[host] {
			score += 3.0
			checkedBlocked[host] = true
		}
	}

	return score
}

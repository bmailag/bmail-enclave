package domain

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// GenerateMTASTSPolicy generates the content of an MTA-STS policy file.
// This file is served at https://mta-sts.{domain}/.well-known/mta-sts.txt
//
// The policy enforces TLS for all listed MX hosts with a 1-week max age.
func GenerateMTASTSPolicy(domain string, mxHosts []string) string {
	var b strings.Builder
	b.WriteString("version: STSv1\n")
	b.WriteString("mode: enforce\n")
	for _, mx := range mxHosts {
		fmt.Fprintf(&b, "mx: %s\n", mx)
	}
	b.WriteString("max_age: 604800\n")
	return b.String()
}

// GenerateMTASTSRecord generates the DNS TXT record for MTA-STS.
// This record is published at _mta-sts.{domain} and signals to senders
// that the domain supports MTA-STS.
func GenerateMTASTSRecord(domain string) string {
	return fmt.Sprintf("_mta-sts.%s. IN TXT \"v=STSv1; id=20260307\"", domain)
}

// MTASTSPolicy represents a parsed MTA-STS policy.
type MTASTSPolicy struct {
	Version string   // "STSv1"
	Mode    string   // "enforce", "testing", or "none"
	MX      []string // allowed MX hostnames (may contain wildcards like *.example.com)
	MaxAge  int      // max cache age in seconds
}

// ParseMTASTSPolicy parses the body of a .well-known/mta-sts.txt file.
func ParseMTASTSPolicy(body string) (*MTASTSPolicy, error) {
	p := &MTASTSPolicy{}
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "version":
			p.Version = val
		case "mode":
			p.Mode = val
		case "mx":
			p.MX = append(p.MX, val)
		case "max_age":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("invalid max_age: %s", val)
			}
			p.MaxAge = n
		}
	}
	if p.Version != "STSv1" {
		return nil, fmt.Errorf("unsupported MTA-STS version: %q", p.Version)
	}
	if p.Mode != "enforce" && p.Mode != "testing" && p.Mode != "none" {
		return nil, fmt.Errorf("invalid MTA-STS mode: %q", p.Mode)
	}
	// Cap max_age to 7 days to limit the impact of a poisoned first-fetch.
	const maxAllowedAge = 7 * 24 * 3600 // 604800 seconds
	if p.MaxAge > maxAllowedAge {
		p.MaxAge = maxAllowedAge
	}
	return p, nil
}

// DNSSEC/DANE future enhancement: MTA-STS relies on DNS TXT records that are
// vulnerable to spoofing without DNSSEC. For full protection, use a DNSSEC-validating
// resolver or DNS-over-HTTPS (DoH) to verify _mta-sts TXT records. This prevents
// an attacker from suppressing the STS signal via DNS spoofing. See RFC 8461 §4.

// MatchesMX returns true if the given hostname matches any of the policy's MX patterns.
func (p *MTASTSPolicy) MatchesMX(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pattern := range p.MX {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == host {
			return true
		}
		// Wildcard: *.example.com matches mail.example.com but not sub.mail.example.com
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && !strings.Contains(host[:len(host)-len(suffix)], ".") {
				return true
			}
		}
	}
	return false
}

package smtp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"golang.org/x/net/publicsuffix"
)

// spfDNSCounter tracks DNS lookups during SPF evaluation (RFC 7208 max 10).
type spfDNSCounter struct {
	count int
	limit int
}

func newSPFDNSCounter() *spfDNSCounter {
	return &spfDNSCounter{limit: 10}
}

// inc increments the counter and returns true if the limit is exceeded.
func (c *spfDNSCounter) inc() bool {
	c.count++
	return c.count > c.limit
}

// CheckSPF checks the SPF record for the given sender.
// Returns a result string: "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror".
func CheckSPF(ctx context.Context, ip net.IP, helo, from string) (result string, err error) {
	// Extract domain from the MAIL FROM address.
	domain := from
	if idx := strings.LastIndex(from, "@"); idx >= 0 {
		domain = from[idx+1:]
	}
	if domain == "" {
		domain = helo
	}
	if domain == "" {
		return "none", nil
	}

	counter := newSPFDNSCounter()
	return checkSPFWithCounter(ctx, ip, domain, counter)
}

func checkSPFWithCounter(ctx context.Context, ip net.IP, domain string, counter *spfDNSCounter) (string, error) {
	// Look up SPF TXT record for the domain.
	txtRecords, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		// DNS lookup failure is a temperror per RFC 7208.
		return "temperror", fmt.Errorf("SPF DNS lookup for %s: %w", domain, err)
	}

	// 2.4.4: Find SPF records — reject if more than one exists.
	var spfRecords []string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1 ") || txt == "v=spf1" {
			spfRecords = append(spfRecords, txt)
		}
	}

	if len(spfRecords) == 0 {
		return "none", nil
	}
	if len(spfRecords) > 1 {
		// RFC 7208 Section 4.5: multiple SPF records is a permerror.
		return "permerror", fmt.Errorf("multiple SPF records for %s", domain)
	}

	spfRecord := spfRecords[0]
	ipStr := ip.String()
	parts := strings.Fields(spfRecord)

	for _, part := range parts[1:] { // skip "v=spf1"
		qualifier := "+"
		mechanism := part
		if len(mechanism) > 0 && (mechanism[0] == '+' || mechanism[0] == '-' || mechanism[0] == '~' || mechanism[0] == '?') {
			qualifier = string(mechanism[0])
			mechanism = mechanism[1:]
		}

		matched := false

		switch {
		case mechanism == "all":
			matched = true

		case strings.HasPrefix(mechanism, "ip4:"):
			cidr := mechanism[4:]
			matched = matchIPCIDR(ip, cidr)

		case strings.HasPrefix(mechanism, "ip6:"):
			cidr := mechanism[4:]
			matched = matchIPCIDR(ip, cidr)

		case mechanism == "a" || strings.HasPrefix(mechanism, "a:") || strings.HasPrefix(mechanism, "a/"):
			// 2.4.1: DNS query counter check.
			if counter.inc() {
				return "permerror", fmt.Errorf("SPF DNS lookup limit exceeded")
			}

			// 2.4.2: Parse CIDR and optional domain for "a" mechanism.
			aDomain, prefix := parseMechanismDomainCIDR(mechanism, "a", domain)

			ips, lookupErr := net.DefaultResolver.LookupHost(ctx, aDomain)
			if lookupErr == nil {
				for _, resolvedIP := range ips {
					if prefix > 0 {
						matched = matchIPWithPrefix(ip, net.ParseIP(resolvedIP), prefix)
					} else {
						if resolvedIP == ipStr {
							matched = true
						}
					}
					if matched {
						break
					}
				}
			}

		case mechanism == "mx" || strings.HasPrefix(mechanism, "mx:") || strings.HasPrefix(mechanism, "mx/"):
			// 2.4.1: DNS query counter check.
			if counter.inc() {
				return "permerror", fmt.Errorf("SPF DNS lookup limit exceeded")
			}

			// 2.4.2: Parse CIDR and optional domain for "mx" mechanism.
			mxDomain, prefix := parseMechanismDomainCIDR(mechanism, "mx", domain)

			mxRecords, mxErr := net.DefaultResolver.LookupMX(ctx, mxDomain)
			if mxErr == nil {
				for _, mx := range mxRecords {
					if counter.inc() {
						return "permerror", fmt.Errorf("SPF DNS lookup limit exceeded")
					}
					mxIPs, lookupErr := net.DefaultResolver.LookupHost(ctx, mx.Host)
					if lookupErr == nil {
						for _, resolvedIP := range mxIPs {
							if prefix > 0 {
								matched = matchIPWithPrefix(ip, net.ParseIP(resolvedIP), prefix)
							} else {
								if resolvedIP == ipStr {
									matched = true
								}
							}
							if matched {
								break
							}
						}
					}
					if matched {
						break
					}
				}
			}

		case strings.HasPrefix(mechanism, "include:"):
			// 2.4.1: DNS query counter check.
			if counter.inc() {
				return "permerror", fmt.Errorf("SPF DNS lookup limit exceeded")
			}
			includeDomain := mechanism[8:]
			includeResult, _ := checkSPFWithCounter(ctx, ip, includeDomain, counter)
			if includeResult == "permerror" {
				return "permerror", fmt.Errorf("SPF DNS lookup limit exceeded")
			}
			if includeResult == "pass" {
				matched = true
			}

		case strings.HasPrefix(mechanism, "redirect="):
			// 2.4.1: DNS query counter check.
			if counter.inc() {
				return "permerror", fmt.Errorf("SPF DNS lookup limit exceeded")
			}
			redirectDomain := mechanism[9:]
			return checkSPFWithCounter(ctx, ip, redirectDomain, counter)

		case mechanism == "ptr" || strings.HasPrefix(mechanism, "ptr:"):
			// 2.4.3: ptr mechanism is deprecated (RFC 7208 Section 5.5).
			// Must not crash — return neutral.
			return "neutral", nil

		case strings.HasPrefix(mechanism, "exists:"):
			// 2.4.1: DNS query counter check.
			if counter.inc() {
				return "permerror", fmt.Errorf("SPF DNS lookup limit exceeded")
			}
			existsDomain := mechanism[7:]
			ips, lookupErr := net.DefaultResolver.LookupHost(ctx, existsDomain)
			if lookupErr == nil && len(ips) > 0 {
				matched = true
			}
		}

		if matched {
			switch qualifier {
			case "+":
				return "pass", nil
			case "-":
				return "fail", nil
			case "~":
				return "softfail", nil
			case "?":
				return "neutral", nil
			}
		}
	}

	return "neutral", nil
}

// parseMechanismDomainCIDR parses a mechanism like "a", "a:domain", "a/24", "a:domain/24".
// Returns the domain to look up and the CIDR prefix length (0 means no CIDR).
func parseMechanismDomainCIDR(mechanism, name, defaultDomain string) (string, int) {
	rest := mechanism[len(name):]
	targetDomain := defaultDomain
	prefix := 0

	if rest == "" {
		return targetDomain, 0
	}

	// Separate domain and CIDR parts.
	if rest[0] == ':' {
		rest = rest[1:]
		// Check for CIDR in the domain part.
		if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
			targetDomain = rest[:slashIdx]
			fmt.Sscanf(rest[slashIdx+1:], "%d", &prefix)
		} else {
			targetDomain = rest
		}
	} else if rest[0] == '/' {
		fmt.Sscanf(rest[1:], "%d", &prefix)
	}

	return targetDomain, prefix
}

// matchIPWithPrefix checks if clientIP matches resolvedIP within the given CIDR prefix length.
func matchIPWithPrefix(clientIP, resolvedIP net.IP, prefix int) bool {
	if resolvedIP == nil {
		return false
	}

	// Use net/netip for reliable prefix matching.
	cAddr, cOk := netip.AddrFromSlice(clientIP)
	rAddr, rOk := netip.AddrFromSlice(resolvedIP)
	if !cOk || !rOk {
		return false
	}
	cAddr = cAddr.Unmap()
	rAddr = rAddr.Unmap()

	// Clamp prefix to valid range.
	maxBits := cAddr.BitLen()
	if prefix > maxBits {
		prefix = maxBits
	}
	if prefix < 0 {
		prefix = 0
	}

	p := netip.PrefixFrom(rAddr, prefix).Masked()
	return p.Contains(cAddr)
}

// matchIPCIDR checks if an IP matches a CIDR or single IP string.
func matchIPCIDR(ip net.IP, cidr string) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()

	if !strings.Contains(cidr, "/") {
		target, err := netip.ParseAddr(cidr)
		if err != nil {
			return false
		}
		return addr == target.Unmap()
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return prefix.Contains(addr)
}

// CheckDKIM verifies DKIM signatures on the given raw message.
// Returns the result ("pass", "fail", "none") and the signing domain.
func CheckDKIM(ctx context.Context, message []byte) (result string, domain string, err error) {
	verifications, err := dkim.Verify(strings.NewReader(string(message)))
	if err != nil {
		return "none", "", fmt.Errorf("DKIM verify: %w", err)
	}

	if len(verifications) == 0 {
		return "none", "", nil
	}

	// Check each verification -- pass if any passes.
	for _, v := range verifications {
		if v.Err == nil {
			return "pass", v.Domain, nil
		}
	}

	// All failed -- return the first domain.
	return "fail", verifications[0].Domain, nil
}

// CheckDKIMAlignment validates that the DKIM signing domain aligns with the From header domain.
// mode is "s" for strict or "r" for relaxed (default).
// Returns true if alignment passes.
func CheckDKIMAlignment(fromDomain, dkimDomain, mode string) bool {
	return domainsAlign(fromDomain, dkimDomain, mode)
}

// CheckDMARC checks the DMARC policy for the sender domain.
// It verifies SPF and DKIM alignment per RFC 7489.
func CheckDMARC(ctx context.Context, fromDomain string, spfResult, spfDomain, dkimResult, dkimDomain string) (result string, err error) {
	if fromDomain == "" {
		return "none", nil
	}

	// Look up _dmarc.domain TXT record.
	dmarcDomain := "_dmarc." + fromDomain
	txtRecords, err := net.DefaultResolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		return "none", nil // No DMARC record = none
	}

	var dmarcRecord string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			dmarcRecord = txt
			break
		}
	}
	if dmarcRecord == "" {
		return "none", nil
	}

	// 2.4.7: Validate DMARC record tag format.
	policy, err := parseDMARCPolicyStrict(dmarcRecord)
	if err != nil {
		return "permerror", fmt.Errorf("DMARC record invalid: %w", err)
	}

	// Check SPF alignment: SPF must pass and the domain must align.
	spfAligned := spfResult == "pass" && domainsAlign(fromDomain, spfDomain, policy["aspf"])

	// 2.4.5: Check DKIM alignment: DKIM must pass and domain must align per DMARC mode.
	dkimAligned := dkimResult == "pass" && domainsAlign(fromDomain, dkimDomain, policy["adkim"])

	// DMARC passes if either SPF or DKIM is aligned.
	if spfAligned || dkimAligned {
		return "pass", nil
	}

	// 2.4.8: Policy enforcement — differentiate reject vs quarantine.
	p := policy["p"]
	switch p {
	case "reject":
		return "reject", nil
	case "quarantine":
		return "quarantine", nil
	default:
		// p=none or unspecified: report but don't enforce.
		return "fail", nil
	}
}

// parseDMARCPolicyStrict parses a DMARC TXT record into key-value pairs.
// 2.4.7: Validates tag format per RFC 7489 and rejects duplicate tags.
func parseDMARCPolicyStrict(record string) (map[string]string, error) {
	policy := make(map[string]string)
	parts := strings.Split(record, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx < 0 {
			return nil, fmt.Errorf("invalid tag (no '='): %q", part)
		}
		key := strings.TrimSpace(part[:idx])
		value := strings.TrimSpace(part[idx+1:])

		if key == "" {
			return nil, fmt.Errorf("empty tag name in %q", part)
		}

		// Validate tag name: alphanumeric only per RFC 7489.
		for _, c := range key {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				return nil, fmt.Errorf("invalid tag name %q", key)
			}
		}

		// Reject duplicate tags.
		if _, exists := policy[key]; exists {
			return nil, fmt.Errorf("duplicate tag %q", key)
		}

		policy[key] = value
	}

	// Must start with v=DMARC1.
	if policy["v"] != "DMARC1" {
		return nil, fmt.Errorf("missing or invalid v= tag")
	}

	return policy, nil
}

// parseDMARCPolicy is the legacy parser kept for backward compatibility (tests).
func parseDMARCPolicy(record string) map[string]string {
	policy := make(map[string]string)
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx >= 0 {
			key := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+1:])
			policy[key] = value
		}
	}
	return policy
}

// orgDomain extracts the organizational domain (eTLD+1) from a fully qualified
// domain using the Public Suffix List via golang.org/x/net/publicsuffix.
// This correctly handles multi-part TLDs like co.uk, com.au, pvt.k12.ma.us, etc.
func orgDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Fallback for invalid or unlisted domains: use last 2 labels.
		parts := strings.Split(domain, ".")
		if len(parts) <= 2 {
			return domain
		}
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return etld1
}

// domainsAlign checks if two domains align per DMARC relaxed or strict mode.
// 2.4.6: Fixed to use org domain extraction for relaxed mode.
func domainsAlign(fromDomain, authDomain, mode string) bool {
	if fromDomain == "" || authDomain == "" {
		return false
	}
	fromDomain = strings.ToLower(fromDomain)
	authDomain = strings.ToLower(authDomain)

	if mode == "s" {
		// Strict: exact match.
		return fromDomain == authDomain
	}

	// Relaxed (default): organizational domain must match.
	return orgDomain(fromDomain) == orgDomain(authDomain)
}

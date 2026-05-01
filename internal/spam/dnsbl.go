package spam

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultDNSBLLists is the default set of DNS blocklists to query.
var DefaultDNSBLLists = []string{
	"zen.spamhaus.org",
	"b.barracudacentral.org",
}

// DNSResolver is an interface for DNS lookups, allowing test injection.
type DNSResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// defaultResolver wraps net.DefaultResolver to satisfy DNSResolver.
type defaultResolver struct{}

func (d *defaultResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// DefaultResolver returns the production DNS resolver.
func DefaultResolver() DNSResolver {
	return &defaultResolver{}
}

// CheckDNSBL queries each DNS blocklist for the given IP.
// Returns the total score and the list of blocklists that matched.
// Each match adds 4.5 to the score.
func CheckDNSBL(ctx context.Context, ip net.IP, lists []string) (float64, []string) {
	return CheckDNSBLWithResolver(ctx, ip, lists, DefaultResolver())
}

// CheckDNSBLWithResolver is like CheckDNSBL but accepts a custom resolver.
func CheckDNSBLWithResolver(ctx context.Context, ip net.IP, lists []string, resolver DNSResolver) (float64, []string) {
	reversed := reverseIP(ip)
	if reversed == "" {
		return 0, nil
	}

	var score float64
	var matched []string

	for _, bl := range lists {
		query := fmt.Sprintf("%s.%s", reversed, bl)
		dnsCtx, dnsCancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := resolver.LookupHost(dnsCtx, query)
		dnsCancel()
		if err != nil {
			continue
		}
		// A non-empty response means the IP is listed.
		if len(addrs) > 0 {
			score += 4.5
			matched = append(matched, bl)
		}
	}

	return score, matched
}

// reverseIP reverses an IP address for DNSBL queries.
// IPv4: 192.168.1.2 becomes 2.1.168.192
// IPv6: each nibble reversed per RFC 5782 §2.4.
func reverseIP(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 != nil {
		parts := strings.Split(ip4.String(), ".")
		if len(parts) != 4 {
			return ""
		}
		return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
	}

	// IPv6: expand to 16 bytes then reverse nibble order per RFC 5782 §2.4.
	ip6 := ip.To16()
	if ip6 == nil {
		return ""
	}
	nibbles := make([]string, 32)
	for i := 15; i >= 0; i-- {
		idx := (15 - i) * 2
		nibbles[idx] = fmt.Sprintf("%x", ip6[i]&0x0f)
		nibbles[idx+1] = fmt.Sprintf("%x", ip6[i]>>4)
	}
	return strings.Join(nibbles, ".")
}

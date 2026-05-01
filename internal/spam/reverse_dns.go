package spam

import (
	"context"
	"net"
	"strings"
	"time"
)

// ReverseDNSResolver is an interface for reverse DNS lookups.
type ReverseDNSResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// defaultReverseDNSResolver wraps net.DefaultResolver.
type defaultReverseDNSResolver struct{}

func (d *defaultReverseDNSResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

func (d *defaultReverseDNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// DefaultReverseDNSResolver returns the production reverse DNS resolver.
func DefaultReverseDNSResolver() ReverseDNSResolver {
	return &defaultReverseDNSResolver{}
}

// CheckReverseDNS verifies forward-confirmed reverse DNS (FCrDNS) for the
// connecting IP and compares it against the HELO/EHLO hostname.
// Returns 0 for valid FCrDNS, 1.5 for no reverse DNS or mismatch.
func CheckReverseDNS(ctx context.Context, ip net.IP, helo string) float64 {
	return CheckReverseDNSWithResolver(ctx, ip, helo, DefaultReverseDNSResolver())
}

// CheckReverseDNSWithResolver is like CheckReverseDNS but accepts a custom resolver.
func CheckReverseDNSWithResolver(ctx context.Context, ip net.IP, helo string, resolver ReverseDNSResolver) float64 {
	if ip == nil {
		return 1.5
	}

	// Reverse lookup: IP -> hostnames.
	revCtx, revCancel := context.WithTimeout(ctx, 5*time.Second)
	names, err := resolver.LookupAddr(revCtx, ip.String())
	revCancel()
	if err != nil || len(names) == 0 {
		return 1.5 // No reverse DNS
	}

	// Forward-confirmed reverse DNS: for each PTR name, resolve it back and
	// check that the IP matches.
	ipStr := ip.String()
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		fwdCtx, fwdCancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := resolver.LookupHost(fwdCtx, name)
		fwdCancel()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr == ipStr {
				// FCrDNS confirmed — valid.
				return 0
			}
		}
	}

	// PTR exists but forward lookup doesn't match — mismatch.
	return 1.5
}

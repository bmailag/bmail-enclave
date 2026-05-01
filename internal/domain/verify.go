package domain

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// dnsResolver is the DNS resolver used by verification functions.
// It defaults to net.DefaultResolver and can be replaced in tests.
var dnsResolver = net.DefaultResolver

// VerificationResult holds the verification status for each DNS record type.
type VerificationResult struct {
	MX        bool
	SPF       bool
	DKIM      bool
	DMARC     bool
	MTASTS    bool
	Ownership bool
	Errors    []string
}

// VerifyDNS checks all required DNS records for the given domain.
func VerifyDNS(ctx context.Context, domain string) (*VerificationResult, error) {
	r := &VerificationResult{}

	// MX
	mxRecords, err := dnsResolver.LookupMX(ctx, domain)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("MX lookup failed: %v", err))
	} else if len(mxRecords) > 0 {
		r.MX = true
	} else {
		r.Errors = append(r.Errors, "no MX records found")
	}

	// SPF
	txtRecords, err := dnsResolver.LookupTXT(ctx, domain)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("SPF TXT lookup failed: %v", err))
	} else {
		for _, txt := range txtRecords {
			if strings.HasPrefix(txt, "v=spf1") {
				r.SPF = true
				break
			}
		}
		if !r.SPF {
			r.Errors = append(r.Errors, "no SPF record found")
		}
	}

	// DKIM — check for _domainkey subdomain TXT records.
	// We can't check a specific selector without knowing it, so we just verify
	// that the domain has at least set up a DKIM key. The caller should pass
	// the selector if a more specific check is needed.
	// For now, we do a generic check by looking up the domain's _domainkey.
	dkimTxt, err := dnsResolver.LookupTXT(ctx, "_domainkey."+domain)
	if err != nil {
		// Not finding a base _domainkey record is common; selector-specific
		// records are more typical. Mark as not verified but don't treat
		// lookup errors as fatal.
		r.Errors = append(r.Errors, "DKIM: no _domainkey base record (may still have selector-specific records)")
	} else {
		for _, txt := range dkimTxt {
			if strings.Contains(txt, "v=DKIM1") {
				r.DKIM = true
				break
			}
		}
		if !r.DKIM {
			r.Errors = append(r.Errors, "DKIM: _domainkey record found but missing v=DKIM1")
		}
	}

	// DMARC
	dmarcTxt, err := dnsResolver.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("DMARC lookup failed: %v", err))
	} else {
		for _, txt := range dmarcTxt {
			if strings.HasPrefix(txt, "v=DMARC1") {
				r.DMARC = true
				break
			}
		}
		if !r.DMARC {
			r.Errors = append(r.Errors, "no DMARC record found")
		}
	}

	// MTA-STS
	mtastsTxt, err := dnsResolver.LookupTXT(ctx, "_mta-sts."+domain)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("MTA-STS lookup failed: %v", err))
	} else {
		for _, txt := range mtastsTxt {
			if strings.HasPrefix(txt, "v=STSv1") {
				r.MTASTS = true
				break
			}
		}
		if !r.MTASTS {
			r.Errors = append(r.Errors, "no MTA-STS record found")
		}
	}

	return r, nil
}

// VerifyOwnershipTXT checks for a TXT record at _bmail-verify.{domain} containing
// the expected challenge token. This proves DNS control (domain ownership).
func VerifyOwnershipTXT(ctx context.Context, domain, expectedToken string) (bool, error) {
	fqdn := "_bmail-verify." + domain
	txtRecords, err := dnsResolver.LookupTXT(ctx, fqdn)
	if err != nil {
		return false, nil // DNS error = not verified, not an error
	}
	for _, txt := range txtRecords {
		if strings.TrimSpace(txt) == "bmail-verify="+expectedToken {
			return true, nil
		}
	}
	return false, nil
}

// VerifyDKIMSelector checks a specific DKIM selector for the domain.
func VerifyDKIMSelector(ctx context.Context, domain, selector string) (bool, error) {
	fqdn := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	txtRecords, err := dnsResolver.LookupTXT(ctx, fqdn)
	if err != nil {
		return false, fmt.Errorf("DKIM selector lookup for %s: %w", fqdn, err)
	}
	for _, txt := range txtRecords {
		if strings.Contains(txt, "v=DKIM1") {
			return true, nil
		}
	}
	return false, nil
}

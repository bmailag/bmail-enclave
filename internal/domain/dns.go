package domain

import (
	"fmt"
	"os"
)

// DNSRecord represents a DNS record that must be configured for a domain.
type DNSRecord struct {
	Type     string
	Name     string
	Value    string
	Priority string
}

// GenerateDNSRecords returns the full set of DNS records required for a domain
// to send and receive mail through Bmail.
func GenerateDNSRecords(domain, dkimPubKey, dkimSelector, mxHost string) []DNSRecord {
	records := []DNSRecord{
		{
			Type:     "MX",
			Name:     domain,
			Value:    mxHost,
			Priority: "10",
		},
		{
			Type:  "TXT",
			Name:  domain,
			Value: spfRecord(),
		},
		{
			Type:  "TXT",
			Name:  fmt.Sprintf("%s._domainkey.%s", dkimSelector, domain),
			Value: fmt.Sprintf("v=DKIM1; k=ed25519; p=%s", dkimPubKey),
		},
		{
			Type:  "TXT",
			Name:  fmt.Sprintf("_dmarc.%s", domain),
			Value: fmt.Sprintf("v=DMARC1; p=reject; rua=mailto:dmarc@%s", domain),
		},
		{
			Type:  "TXT",
			Name:  fmt.Sprintf("_mta-sts.%s", domain),
			Value: "v=STSv1; id=20260101",
		},
	}
	return records
}

// spfRecord returns the SPF TXT record value, including the outbound IP if configured.
func spfRecord() string {
	if ip := os.Getenv("OUTBOUND_IP"); ip != "" {
		return fmt.Sprintf("v=spf1 mx ip4:%s -all", ip)
	}
	return "v=spf1 mx -all"
}

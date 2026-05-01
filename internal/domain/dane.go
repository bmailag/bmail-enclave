package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// GenerateTLSARecord generates a DANE TLSA record that binds an enclave's
// TLS certificate to a domain's MX endpoint (port 25). The record uses:
//   - Usage 3 (DANE-EE): certificate usage — domain-issued end entity
//   - Selector 1: match on SubjectPublicKeyInfo (DER-encoded SPKI)
//   - Matching type 1: SHA-256 hash
//
// The spkiDER parameter must be the DER-encoded SubjectPublicKeyInfo from the
// TLS certificate (cert.RawSubjectPublicKeyInfo), NOT raw public key bytes.
// This matches RFC 6698 §2.1.1 and standard DANE validators.
//
// Output format: _25._tcp.mx.{domain}. IN TLSA 3 1 1 <sha256hex>
func GenerateTLSARecord(domain string, spkiDER []byte) string {
	hash := sha256.Sum256(spkiDER)
	hexHash := hex.EncodeToString(hash[:])
	return fmt.Sprintf("_25._tcp.mx.%s. IN TLSA 3 1 1 %s", domain, hexHash)
}

// GenerateHTTPSTLSARecord generates a DANE TLSA record that binds an
// enclave's TLS certificate to a domain's HTTPS endpoint (port 443).
// Same TLSA parameters as the SMTP variant.
//
// The spkiDER parameter must be the DER-encoded SubjectPublicKeyInfo from the
// TLS certificate (cert.RawSubjectPublicKeyInfo), NOT raw public key bytes.
//
// Output format: _443._tcp.api.{domain}. IN TLSA 3 1 1 <sha256hex>
func GenerateHTTPSTLSARecord(domain string, spkiDER []byte) string {
	hash := sha256.Sum256(spkiDER)
	hexHash := hex.EncodeToString(hash[:])
	return fmt.Sprintf("_443._tcp.api.%s. IN TLSA 3 1 1 %s", domain, hexHash)
}

// ParseTLSARecord parses a DANE TLSA record string and extracts its components.
// Expected format: _25._tcp.mx.{domain}. IN TLSA <usage> <selector> <matchType> <hex>
func ParseTLSARecord(record string) (usage, selector, matchType int, hash []byte, err error) {
	parts := strings.Fields(record)

	// Find "TLSA" keyword to locate the parameters.
	tlsaIdx := -1
	for i, p := range parts {
		if strings.EqualFold(p, "TLSA") {
			tlsaIdx = i
			break
		}
	}
	if tlsaIdx < 0 || tlsaIdx+4 > len(parts) {
		return 0, 0, 0, nil, fmt.Errorf("invalid TLSA record format: TLSA keyword not found or insufficient fields")
	}

	usage, err = strconv.Atoi(parts[tlsaIdx+1])
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("parse usage: %w", err)
	}

	selector, err = strconv.Atoi(parts[tlsaIdx+2])
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("parse selector: %w", err)
	}

	matchType, err = strconv.Atoi(parts[tlsaIdx+3])
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("parse match type: %w", err)
	}

	// Validate field values per RFC 6698.
	if usage < 0 || usage > 3 {
		return 0, 0, 0, nil, fmt.Errorf("invalid TLSA usage %d (must be 0-3)", usage)
	}
	if selector < 0 || selector > 1 {
		return 0, 0, 0, nil, fmt.Errorf("invalid TLSA selector %d (must be 0-1)", selector)
	}
	if matchType < 0 || matchType > 2 {
		return 0, 0, 0, nil, fmt.Errorf("invalid TLSA match type %d (must be 0-2)", matchType)
	}

	hash, err = hex.DecodeString(parts[tlsaIdx+4])
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("parse hash: %w", err)
	}

	return usage, selector, matchType, hash, nil
}

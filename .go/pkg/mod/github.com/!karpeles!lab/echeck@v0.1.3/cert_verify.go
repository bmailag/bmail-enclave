package echeck

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
)

// Intel SGX Root CA certificate embedded in the library
const intelSGXRootCA = `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`

// SGXAuthData represents the authentication data structure in quote signatures
type SGXAuthData struct {
	AuthDataSize uint16   // Size of auth data (typically 0x0020)
	AuthData     [32]byte // 32 bytes of auth data
	CertType     uint16   // Certificate type (typically 0x0005)
	CertDataSize uint32   // Size of certificate data (4 bytes)
	CertData     []byte   // Certificate data (PEM formatted PCK certs)
}

// PCKCertChain represents the extracted PCK certificate chain from a quote
type PCKCertChain struct {
	PCKCert          *x509.Certificate // Leaf PCK certificate
	IntermediateCert *x509.Certificate // Intermediate certificate (optional)
	Certificates     []*x509.Certificate // All certificates in the chain
}

// GetIntelSGXCertPool returns a certificate pool pre-initialized with Intel's SGX Root CA
func GetIntelSGXCertPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	
	// Parse the Intel SGX Root CA certificate
	block, _ := pem.Decode([]byte(intelSGXRootCA))
	if block == nil {
		return nil, errors.New("failed to decode Intel SGX Root CA certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type: %s (expected CERTIFICATE)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Intel SGX Root CA certificate: %v", err)
	}
	
	pool.AddCert(cert)
	return pool, nil
}

// ExtractPCKCertChain extracts the PCK certificate chain from an SGX quote's signature data
func (q *Quote) ExtractPCKCertChain() (*PCKCertChain, error) {
	// Only supported for ECDSA Quote v3
	if q.Quote.Version != 3 {
		return nil, fmt.Errorf("PCK certificate chain extraction only supported for ECDSA Quote v3, got version %d", q.Quote.Version)
	}
	
	// Parse the signature data to find the authentication data
	authData, err := q.parseAuthData()
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication data: %v", err)
	}
	
	// Extract certificates from the PEM data
	certs, err := parsePEMCertificates(authData.CertData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PEM certificates: %v", err)
	}
	
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in authentication data")
	}
	
	chain := &PCKCertChain{
		Certificates: certs,
		PCKCert:      certs[0], // First certificate is the leaf (PCK) certificate
	}
	
	// Second certificate is the intermediate certificate (if present)
	if len(certs) > 1 {
		chain.IntermediateCert = certs[1]
	}
	
	return chain, nil
}

// parseAuthData parses the authentication data from the quote signature
func (q *Quote) parseAuthData() (*SGXAuthData, error) {
	sigData := q.Quote.SignatureData
	
	// Navigate to the authentication data section
	// Structure: 64 bytes sig + 64 bytes attest_pub_key + 384 bytes qe_report + 64 bytes qe_report_sig
	authDataOffset := 64 + 64 + 384 + 64
	
	if len(sigData) < authDataOffset+6 { // Need at least 6 bytes for the header
		return nil, fmt.Errorf("signature data too short for authentication data: %d bytes", len(sigData))
	}
	
	authData := &SGXAuthData{}
	offset := authDataOffset
	
	// Parse auth data header
	authData.AuthDataSize = binary.LittleEndian.Uint16(sigData[offset : offset+2])
	offset += 2
	
	if authData.AuthDataSize != 0x20 {
		return nil, fmt.Errorf("unexpected auth data size: 0x%04x (expected 0x0020)", authData.AuthDataSize)
	}
	
	// Skip auth data bytes
	if len(sigData) < offset+32 {
		return nil, errors.New("signature data too short for auth data")
	}
	copy(authData.AuthData[:], sigData[offset:offset+32])
	offset += 32
	
	// Parse certificate type and size
	if len(sigData) < offset+6 {
		return nil, errors.New("signature data too short for cert type and size")
	}

	authData.CertType = binary.LittleEndian.Uint16(sigData[offset : offset+2])
	offset += 2

	authData.CertDataSize = binary.LittleEndian.Uint32(sigData[offset : offset+4])
	offset += 4

	// Validate certificate data size to prevent memory exhaustion DoS
	// 64KB is more than enough for PEM certificate chains
	const maxCertDataSize = 64 * 1024
	if authData.CertDataSize > maxCertDataSize {
		return nil, fmt.Errorf("certificate data size too large: %d (max %d)", authData.CertDataSize, maxCertDataSize)
	}

	if authData.CertType != 0x0005 {
		return nil, fmt.Errorf("unexpected certificate type: 0x%04x (expected 0x0005)", authData.CertType)
	}

	// Extract certificate data
	// Use subtraction to avoid integer overflow on 32-bit systems
	if int(authData.CertDataSize) > len(sigData)-offset {
		return nil, fmt.Errorf("signature data too short for certificate data: need %d bytes, have %d",
			authData.CertDataSize, len(sigData)-offset)
	}
	
	authData.CertData = make([]byte, authData.CertDataSize)
	copy(authData.CertData, sigData[offset:offset+int(authData.CertDataSize)])
	
	return authData, nil
}

// parsePEMCertificates parses multiple PEM certificates from data
func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	// Limit certificate chain depth to prevent resource exhaustion
	// SGX chains are typically: PCK -> Intermediate -> Root (3 certs)
	const maxCertChainLength = 10

	var certs []*x509.Certificate
	remaining := data

	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			remaining = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}

		certs = append(certs, cert)
		remaining = rest

		// Enforce chain depth limit
		if len(certs) >= maxCertChainLength {
			break
		}
	}

	return certs, nil
}

// VerifyCertificateChain verifies the PCK certificate chain against trusted Intel CAs
func (chain *PCKCertChain) VerifyCertificateChain(trustedCAs *x509.CertPool) error {
	if chain.PCKCert == nil {
		return errors.New("no PCK certificate to verify")
	}
	
	if trustedCAs == nil {
		return errors.New("no trusted CA certificate pool provided")
	}
	
	// Create intermediate certificate pool if we have intermediate certificates
	intermediates := x509.NewCertPool()
	if chain.IntermediateCert != nil {
		intermediates.AddCert(chain.IntermediateCert)
	}
	
	// Add any additional intermediate certificates
	for i, cert := range chain.Certificates {
		if i > 0 && i < len(chain.Certificates)-1 { // Skip leaf (index 0) and potential root (last)
			intermediates.AddCert(cert)
		}
	}
	
	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         trustedCAs,
		Intermediates: intermediates,
	}
	
	_, err := chain.PCKCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("PCK certificate chain verification failed: %v", err)
	}
	
	return nil
}

// VerifyWithIntelCAs verifies the PCK certificate chain against Intel's trusted CAs
func (chain *PCKCertChain) VerifyWithIntelCAs() error {
	pool, err := GetIntelSGXCertPool()
	if err != nil {
		return fmt.Errorf("failed to get Intel SGX certificate pool: %v", err)
	}
	
	return chain.VerifyCertificateChain(pool)
}
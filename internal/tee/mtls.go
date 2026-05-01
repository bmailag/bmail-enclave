package tee

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// InternalCA manages a TEE-generated certificate authority for service-to-service
// mTLS. The CA key is sealed inside the enclave.
type InternalCA struct {
	caCert      *x509.Certificate
	caKey       ed25519.PrivateKey
	certPool    *x509.CertPool
	caCertPEM   []byte
	mu          sync.Mutex                   // protects issuedCerts
	issuedCerts map[string]*tls.Certificate  // cache by service name
}

// NewInternalCA creates or loads an internal CA from TEE-sealed storage.
func NewInternalCA(runtime TEERuntime, sealPath string) (*InternalCA, error) {
	// Load or generate CA key.
	keyBytes, err := LoadOrSealBytes(runtime, sealPath, func() ([]byte, error) {
		_, priv, err := runtime.GenerateKey("ed25519")
		return priv, err
	})
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}

	caKey := ed25519.PrivateKey(keyBytes)
	caPub := caKey.Public().(ed25519.PublicKey)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "bmail-internal-ca", Organization: []string{"Bmail"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, template, template, caPub, caKey)
	if err != nil {
		return nil, fmt.Errorf("ca cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	return &InternalCA{
		caCert:      caCert,
		caKey:       caKey,
		certPool:    certPool,
		caCertPEM:   caCertPEM,
		issuedCerts: make(map[string]*tls.Certificate),
	}, nil
}

// IssueCert creates a client/server certificate signed by the internal CA.
// Returns a cached certificate if one was already issued for this service name.
// Thread-safe via mutex protecting the issuedCerts cache.
func (ca *InternalCA) IssueCert(serviceName string, runtime TEERuntime) (*tls.Certificate, error) {
	ca.mu.Lock()
	if cert, ok := ca.issuedCerts[serviceName]; ok {
		ca.mu.Unlock()
		return cert, nil
	}
	ca.mu.Unlock()

	_, privBytes, err := runtime.GenerateKey("ed25519")
	if err != nil {
		return nil, fmt.Errorf("service key: %w", err)
	}

	privKey := ed25519.PrivateKey(privBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("service serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serviceName, Organization: []string{"Bmail"}},
		DNSNames:     []string{serviceName, serviceName + ".vpmail.svc.cluster.local"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, pubKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("service cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	pkcs8Bytes, err := marshalPKCS8(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("service tls: %w", err)
	}

	ca.mu.Lock()
	ca.issuedCerts[serviceName] = &tlsCert
	ca.mu.Unlock()
	return &tlsCert, nil
}

// ServerTLSConfig returns a TLS config for a service that requires client certs
// signed by this CA.
func (ca *InternalCA) ServerTLSConfig(serviceCert *tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*serviceCert},
		ClientCAs:    ca.certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLSConfig returns a TLS config for an HTTP client that presents a
// client cert and verifies the server's cert against the internal CA.
func (ca *InternalCA) ClientTLSConfig(clientCert *tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		RootCAs:      ca.certPool,
		MinVersion:   tls.VersionTLS13,
	}
}

// NewMTLSClient creates an http.Client configured with mTLS using the internal CA.
func (ca *InternalCA) NewMTLSClient(clientCert *tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: ca.ClientTLSConfig(clientCert),
		},
		Timeout: 30 * time.Second,
	}
}

// CACertPEM returns the CA certificate in PEM format for distribution.
func (ca *InternalCA) CACertPEM() []byte {
	return ca.caCertPEM
}

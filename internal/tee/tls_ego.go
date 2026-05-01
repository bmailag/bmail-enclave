//go:build ego

package tee

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/edgelesssys/ego/enclave"
)

// GenerateServerTLSConfig creates a TLS config with an SGX attestation
// certificate when running inside an enclave. The TLS cert embeds the SGX
// quote as an X.509 extension (OID 1.3.6.1.4.1.311.105.1), allowing clients
// to verify enclave identity on every TLS handshake using echeck.
//
// The private key is sealed and persisted at sealPath so that the SPKI hash
// remains stable across enclave restarts, enabling DANE/TLSA pinning. The
// attestation certificate itself is regenerated on each boot (fresh SGX quote),
// but the underlying key — and therefore the SPKI — stays the same.
func GenerateServerTLSConfig(runtime TEERuntime, hostname string, sealPath string) (*tls.Config, []byte, error) {
	keyDER, err := LoadOrSealBytes(runtime, sealPath, func() ([]byte, error) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ecdsa key: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("marshal ecdsa key: %w", err)
		}
		return der, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tls key: %w", err)
	}
	return buildAttestationTLSConfig(hostname, keyDER)
}

// GenerateServerTLSConfigUnique is the MRENCLAVE-seal variant of
// GenerateServerTLSConfig. The sealed TLS key is recoverable ONLY by
// an enclave running the exact same MRENCLAVE that sealed it — every
// code change loses the cached key, a fresh key is generated, and the
// cert/SPKI rotate accordingly. Callers using this MUST have an
// auto-publish path for the new SPKI (e.g. peer.Manager.daneUpdate
// for DANE TLSA, or autocert + a public CA with no rate limit).
//
// Used by smtp-inbound: its peer.Manager publishes the new SPKI to the
// _25._tcp.smtp.<host>. TLSA record on every boot, so MRENCLAVE-flip
// just causes a brief delivery-deferral window during DNS TTL before
// the new cert chain takes hold.
func GenerateServerTLSConfigUnique(runtime TEERuntime, hostname string, sealPath string) (*tls.Config, []byte, error) {
	keyDER, err := LoadOrSealUniqueBytes(runtime, sealPath, func() ([]byte, error) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ecdsa key: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("marshal ecdsa key: %w", err)
		}
		return der, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tls key: %w", err)
	}
	return buildAttestationTLSConfig(hostname, keyDER)
}

// buildAttestationTLSConfig constructs the SGX attestation TLS config
// from a parsed ECDSA P-256 key. Shared by GenerateServerTLSConfig and
// GenerateServerTLSConfigUnique; the only difference between the two
// is which seal helper produced the keyDER.
func buildAttestationTLSConfig(hostname string, keyDER []byte) (*tls.Config, []byte, error) {
	priv, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse sealed ecdsa key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := enclave.CreateAttestationCertificate(template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create attestation cert: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse attestation cert: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
		Leaf:        parsedCert,
	}

	if leCertPath := os.Getenv("LETSENCRYPT_CERT_PATH"); leCertPath != "" {
		if leCert, err := loadLECert(leCertPath, priv); err != nil {
			slog.Warn("failed to load LE cert, using attestation cert", "path", leCertPath, "error", err)
		} else {
			tlsCert = *leCert
			slog.Info("using Let's Encrypt certificate", "path", leCertPath)
		}
	} else {
		slog.Info("using SGX attestation certificate (LETSENCRYPT_CERT_PATH not set)")
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}
	if tlsCert.Leaf == nil {
		parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("parse served cert for SPKI: %w", err)
		}
		tlsCert.Leaf = parsed
		cfg.Certificates[0].Leaf = parsed
	}
	return cfg, tlsCert.Leaf.RawSubjectPublicKeyInfo, nil
}

// GenerateAndSealNewTLSKey unconditionally generates a fresh TLS key,
// seals it under the enclave identity, atomically writes the sealed
// bytes to outPath, and returns the SHA-256 hash of the SPKI for TLSA
// pre-publication. EGo build uses ECDSA P-256 (matches GenerateServerTLSConfig).
func GenerateAndSealNewTLSKey(runtime TEERuntime, outPath string) ([32]byte, error) {
	return GenerateAndSealNewTLSKeyECDSA(runtime, outPath)
}

// GenerateCSR creates a Certificate Signing Request using the sealed private key.
func GenerateCSR(runtime TEERuntime, hostname string, sealPath string) ([]byte, error) {
	keyDER, err := LoadOrSealBytes(runtime, sealPath, func() ([]byte, error) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ecdsa key: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("marshal ecdsa key: %w", err)
		}
		return der, nil
	})
	if err != nil {
		return nil, fmt.Errorf("load sealed key for CSR: %w", err)
	}

	priv, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("parse sealed ecdsa key for CSR: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: hostname},
		DNSNames: []string{hostname},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

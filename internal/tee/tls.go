package tee

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// GenerateTLSConfig creates a TLS config with an in-memory self-signed
// certificate using an Ed25519 key generated (and optionally sealed) by the
// TEE. The private key never touches the filesystem.
//
// The returned config uses TLS 1.3 minimum. The DER-encoded
// SubjectPublicKeyInfo (SPKI) bytes are also returned for use in attestation
// and DANE/TLSA records (TLSA selector=1 requires SPKI DER,
// not raw key bytes).
func GenerateTLSConfig(runtime TEERuntime, hostname string, sealPath string) (*tls.Config, []byte, error) {
	// Load or generate key via TEE seal/unseal.
	keyBytes, err := LoadOrSealBytes(runtime, sealPath, func() ([]byte, error) {
		_, priv, err := runtime.GenerateKey("ed25519")
		return priv, err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tls key: %w", err)
	}

	privKey := ed25519.PrivateKey(keyBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Create self-signed certificate.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("tls serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("tls cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	pkcs8Bytes, err := marshalPKCS8(privKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("tls keypair: %w", err)
	}

	// Check for Let's Encrypt certificate to replace the self-signed cert.
	if leCertPath := os.Getenv("LETSENCRYPT_CERT_PATH"); leCertPath != "" {
		if leCert, err := loadLECert(leCertPath, privKey); err != nil {
			slog.Warn("failed to load LE cert, using self-signed cert", "path", leCertPath, "error", err)
		} else {
			tlsCert = *leCert
			slog.Info("using Let's Encrypt certificate", "path", leCertPath)
		}
	} else {
		slog.Info("using self-signed certificate (LETSENCRYPT_CERT_PATH not set)")
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	// Return the SPKI of the cert ACTUALLY being served. With the loadLECert
	// pubkey-match check, this equals the sealed key's SPKI either way (LE
	// cert path or self-signed fallback) — but reading from tlsCert.Leaf
	// makes the contract explicit and survives future refactors.
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

func marshalPKCS8(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return der, nil
}

// loadLECert reads a PEM certificate chain from certPath and pairs it with
// the enclave-sealed private key. The cert MUST have been issued for the
// sealed pubkey — this is verified by comparing the leaf cert's
// SubjectPublicKeyInfo DER bytes against the sealed key's marshalled pubkey.
// A mismatch returns an error so the caller falls back to the self-signed
// attestation cert (preserving the DANE chain: published TLSA always matches
// the sealed pubkey, never a privkey-on-disk Box 2 leftover).
//
// No privkey.pem is read from disk — the sealed privkey is the only TLS
// private key used. This is what makes the chain verifiable: the binary
// running outside the enclave cannot serve a cert that matches DANE TLSA
// without unsealing the sealed key, and unsealing requires the same MRSIGNER.
func loadLECert(certPath string, priv crypto.PrivateKey) (*tls.Certificate, error) {
	if priv == nil {
		return nil, fmt.Errorf("sealed private key is nil")
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("sealed private key does not implement crypto.Signer")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read LE cert: %w", err)
	}

	var chain [][]byte
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in %s", certPath)
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}

	sealedSPKI, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal sealed pubkey: %w", err)
	}
	if !bytes.Equal(sealedSPKI, leaf.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("LE cert pubkey does not match sealed key — cert was issued for a different keypair (regenerate via GENERATE_CSR=true and reissue)")
	}

	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}

// GenerateCSRSim creates a Certificate Signing Request using the sealed
// private key in simulation mode (Ed25519). This is the !ego build variant.
func GenerateCSRSim(runtime TEERuntime, hostname string, sealPath string) ([]byte, error) {
	keyBytes, err := LoadOrSealBytes(runtime, sealPath, func() ([]byte, error) {
		_, priv, err := runtime.GenerateKey("ed25519")
		return priv, err
	})
	if err != nil {
		return nil, fmt.Errorf("load sealed key for CSR: %w", err)
	}

	privKey := ed25519.PrivateKey(keyBytes)

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: hostname},
		DNSNames: []string{hostname},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// GenerateAndSealNewTLSKeyECDSA unconditionally generates a fresh ECDSA
// P-256 keypair, seals the private key under the enclave identity, and
// atomically writes the sealed bytes to outPath (write-tmp+rename). It
// returns the SHA-256 hash of the SubjectPublicKeyInfo (SPKI) DER, which
// is what gets published as a DANE TLSA `3 1 1` record.
//
// Used by the GENERATE_KEY=true pre-stage step in the enclave rotation
// pipeline: CI runs this on the target host BEFORE deploying the new
// MRENCLAVE binary, captures the SPKI hash, pre-publishes the new TLSA
// alongside the old one, waits for DNS propagation, then atomically
// promotes the staged sealed file + binary into place.
//
// Unlike LoadOrSealBytes, this never reads-or-uses an existing file —
// it always generates a fresh key. The sealed file written here is the
// future TLS key for the next enclave version, NOT the currently-serving
// key. The caller is responsible for orchestrating the cutover.
func GenerateAndSealNewTLSKeyECDSA(runtime TEERuntime, outPath string) ([32]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return [32]byte{}, fmt.Errorf("generate ecdsa key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal ecdsa key: %w", err)
	}
	return sealAndWriteKey(runtime, keyDER, &priv.PublicKey, outPath)
}

// GenerateAndSealNewTLSKeyEd25519 is the simulation-mode counterpart that
// generates an Ed25519 key (matches the sim path's GenerateTLSConfig key
// type) and writes it to outPath. The SPKI hash format is identical, so
// the same TLSA wire format applies.
func GenerateAndSealNewTLSKeyEd25519(runtime TEERuntime, outPath string) ([32]byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return [32]byte{}, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return sealAndWriteKey(runtime, []byte(priv), pub, outPath)
}

// sealAndWriteKey is the shared seal+atomic-write+SPKI-hash core for the
// GenerateAndSealNewTLSKey* variants.
func sealAndWriteKey(runtime TEERuntime, keyBytes []byte, pub crypto.PublicKey, outPath string) ([32]byte, error) {
	sealed, err := runtime.Seal(keyBytes)
	if err != nil {
		return [32]byte{}, fmt.Errorf("seal key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return [32]byte{}, fmt.Errorf("mkdir seal dir: %w", err)
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return [32]byte{}, fmt.Errorf("write tmp sealed file: %w", err)
	}
	if err := os.Rename(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		return [32]byte{}, fmt.Errorf("rename sealed file: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal SPKI: %w", err)
	}
	return sha256.Sum256(spki), nil
}

// GenerateCSRECDSA creates a Certificate Signing Request using an ECDSA P-256
// sealed private key. This can be used when the sealed key is ECDSA (e.g.,
// smtp-inbound in simulation mode that needs to match the ego key type).
func GenerateCSRECDSA(runtime TEERuntime, hostname string, sealPath string) ([]byte, error) {
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

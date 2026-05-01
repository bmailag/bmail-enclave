package domain

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// DefaultDKIMSelector is the prefix used when constructing a fresh DKIM
// selector at provisioning or rotation time. Selectors are formatted as
// "{DefaultDKIMSelector}-{unix-timestamp}" so a key rotation produces a
// new selector value without colliding with the prior one.
const DefaultDKIMSelector = "vp1"

// GenerateDKIMKeyPair generates a new Ed25519 key pair for DKIM signing.
// It returns the private key, the base64-encoded public key suitable for a DNS
// TXT record, and any error.
func GenerateDKIMKeyPair() (ed25519.PrivateKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	// DNS record needs the raw 32-byte public key, base64-encoded.
	pubKeyDNS := base64.StdEncoding.EncodeToString(pub)
	return priv, pubKeyDNS, nil
}

// GenerateRSADKIMKeyPair generates an RSA-2048 key pair for DKIM signing.
// Returns the private key bytes (PKCS8 DER), the base64-encoded public key
// (SubjectPublicKeyInfo DER) for the DNS TXT record, and any error.
func GenerateRSADKIMKeyPair() ([]byte, string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("generate rsa key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshal public key: %w", err)
	}
	pubKeyDNS := base64.StdEncoding.EncodeToString(pubDER)
	return privDER, pubKeyDNS, nil
}

// SignMessage DKIM-signs a raw RFC 5322 message and returns the signed message
// (original message with a prepended DKIM-Signature header).
func SignMessage(privateKey ed25519.PrivateKey, domain, selector string, message []byte) ([]byte, error) {
	return signMessageWithKey(privateKey, domain, selector, message)
}

// SignMessageRSA DKIM-signs a raw RFC 5322 message with an RSA private key.
func SignMessageRSA(privateKey *rsa.PrivateKey, domain, selector string, message []byte) ([]byte, error) {
	return signMessageWithKey(privateKey, domain, selector, message)
}

func signMessageWithKey(signer crypto.Signer, domain, selector string, message []byte) ([]byte, error) {
	opts := &dkim.SignOptions{
		Domain:   domain,
		Selector: selector,
		Signer:   signer,
		HeaderKeys: []string{
			"From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-Id",
			"In-Reply-To", "References",
			"MIME-Version", "Content-Type",
		},
		Expiration:            time.Now().Add(7 * 24 * time.Hour),
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
	}

	var signed bytes.Buffer
	if err := dkim.Sign(&signed, bytes.NewReader(message), opts); err != nil {
		return nil, fmt.Errorf("dkim sign: %w", err)
	}
	return signed.Bytes(), nil
}

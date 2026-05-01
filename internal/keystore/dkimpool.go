package keystore

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// DKIMPoolEntry is the JSON shape stored in the keystore under a
// single role for one DKIM selector. ADR-007 §1: a small handful of
// shared selectors back tenant CNAMEs.
//
// Both algorithms (Ed25519 + RSA) are co-located in one entry so
// smtp-outbound performs one keystore Get per startup — not two —
// and so a future rotation always rotates them as a pair.
//
// On the wire (the keystore.GetResponse.Key bytes), the entry is
// encoded as JSON. Public-key fields are derived from the private
// halves and stored alongside as a convenience for the DNS-publish
// path; smtp-outbound never trusts them blindly — it always
// re-derives from the private key before signing.
type DKIMPoolEntry struct {
	// Selector is the DNS selector this pool key serves, e.g. "s1".
	// The keystore role for this entry is "smtp-outbound-dkim-pool-{selector}".
	Selector string `json:"selector"`

	// Ed25519Seed is the 32-byte Ed25519 seed for the modern DKIM
	// signature. Public half = ed25519.NewKeyFromSeed(seed).Public().
	Ed25519Seed []byte `json:"ed25519_seed"`

	// RSAPKCS8 is the PKCS8-DER-encoded RSA-2048 private key for the
	// universally-supported DKIM signature.
	RSAPKCS8 []byte `json:"rsa_pkcs8"`

	// Ed25519PubB64, RSAPubB64 are the public halves in base64 form
	// suitable for the `p=` field of a DKIM TXT record. Informational
	// — used by the bootstrap tool to print the DNS records the
	// operator needs to publish.
	Ed25519PubB64 string `json:"ed25519_pub_b64"`
	RSAPubB64     string `json:"rsa_pub_b64"`

	// CreatedAt is the unix timestamp when this pool entry was
	// generated. Mostly informational; rotation cadence is policy.
	CreatedAt int64 `json:"created_at"`
}

// DKIMPoolRoleName returns the keystore role name for a given
// selector. Centralized so consumers and operator tools agree on the
// naming scheme without duplicating the format string.
func DKIMPoolRoleName(selector string) Role {
	return Role(fmt.Sprintf("smtp-outbound-dkim-pool-%s", selector))
}

// MarshalDKIMPoolEntry encodes the entry to bytes suitable for
// passing as the Key field of a Provision request. Public halves are
// derived from the provided private halves and embedded so the DNS
// publish step has them available.
func MarshalDKIMPoolEntry(selector string, ed25519Seed []byte, rsaKey *rsa.PrivateKey, createdAt int64) ([]byte, error) {
	if len(ed25519Seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(ed25519Seed))
	}
	if rsaKey == nil {
		return nil, errors.New("rsa key required")
	}
	if rsaKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("rsa key too small (%d bits, need ≥2048)", rsaKey.N.BitLen())
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, fmt.Errorf("marshal rsa pkcs8: %w", err)
	}
	rsaPubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal rsa pubkey: %w", err)
	}
	edPriv := ed25519.NewKeyFromSeed(ed25519Seed)
	edPub, ok := edPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("ed25519 public key derive failed")
	}

	entry := DKIMPoolEntry{
		Selector:      selector,
		Ed25519Seed:   ed25519Seed,
		RSAPKCS8:      rsaDER,
		Ed25519PubB64: base64.StdEncoding.EncodeToString(edPub),
		RSAPubB64:     base64.StdEncoding.EncodeToString(rsaPubDER),
		CreatedAt:     createdAt,
	}
	return json.Marshal(entry)
}

// UnmarshalDKIMPoolEntry decodes the bytes returned by a keystore
// Get back into a structured entry. Smtp-outbound calls this once
// per startup (or on a refresh interval) and caches the parsed
// private keys in RAM for signing.
func UnmarshalDKIMPoolEntry(b []byte) (*DKIMPoolEntry, error) {
	var e DKIMPoolEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("unmarshal dkim pool entry: %w", err)
	}
	if e.Selector == "" {
		return nil, errors.New("dkim pool entry missing selector")
	}
	if len(e.Ed25519Seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("dkim pool entry ed25519 seed wrong size: %d", len(e.Ed25519Seed))
	}
	if len(e.RSAPKCS8) == 0 {
		return nil, errors.New("dkim pool entry missing rsa key")
	}
	return &e, nil
}

// DKIMTXTRecord is the rendered TXT record value for one algorithm's
// public key, in the form receivers expect to find at
// <selector>._domainkey.<domain>.
//
//	v=DKIM1; k=rsa; p=<base64-pub>      (for RSA)
//	v=DKIM1; k=ed25519; p=<base64-pub>  (for Ed25519)
type DKIMTXTRecord struct {
	Name      string // e.g. "s1._domainkey.bmail.ag"
	Value     string // e.g. "v=DKIM1; k=ed25519; p=<base64>"
	Algorithm string // "rsa" or "ed25519"
}

// DKIMPoolDNSRecords returns the TXT record content the operator (or
// future automated daneUpdate-style flow) must publish so receivers
// can verify signatures from this pool key.
//
// One TXT per algorithm; both share the same selector under
// ADR-007's design — receivers fetch by signature header.
func (e *DKIMPoolEntry) DKIMPoolDNSRecords(zoneDomain string) []DKIMTXTRecord {
	name := fmt.Sprintf("%s._domainkey.%s", e.Selector, zoneDomain)
	return []DKIMTXTRecord{
		{
			Name:      name,
			Value:     fmt.Sprintf("v=DKIM1; k=ed25519; p=%s", e.Ed25519PubB64),
			Algorithm: "ed25519",
		},
		{
			Name:      name,
			Value:     fmt.Sprintf("v=DKIM1; k=rsa; p=%s", e.RSAPubB64),
			Algorithm: "rsa",
		},
	}
}

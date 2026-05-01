// Package payment implements blind-signature credential issuance inside the
// SGX enclave. Two flows are live:
//
//   - fakeid_mint:    one-shot blind-signed credential issued per primary
//     subscription, proving the holder is entitled to register a Fake ID
//     (a privacy-preserving alternate mailbox that cannot be linked back
//     to the primary).
//   - fakeid_ratchet: blind-signed credential issued when the primary's
//     subscription is still valid, used to push forward a Fake ID's
//     max_valid_until ceiling.
//
// The legacy paid/pro/business tiers and payment-processor interface remain
// for the Chaumian-payment design (paper 2); they aren't wired up in current
// deployments but are retained so the blind-sig primitives can be exercised.
package payment

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/bmailag/bmail/internal/crypto"
)

// PaymentProcessor verifies a payment and returns the tier granted.
// Used only by the legacy paid/pro/business flows — the Fake ID mint/ratchet
// path authenticates at the backend before calling SignForTier.
type PaymentProcessor interface {
	VerifyPayment(ctx context.Context, proof []byte) (tier string, err error)
}

// Tier names. The first three are legacy. FakeIDMintTier and
// FakeIDRatchetTier are the active Fake ID issuance keys — each has its own
// RSA key so a credential minted for one purpose cannot be used for the other.
const (
	TierFakeIDMint    = "fakeid_mint"
	TierFakeIDRatchet = "fakeid_ratchet"
)

// Tiers defines all supported blind-signing tiers.
var Tiers = []string{"paid", "pro", "business", TierFakeIDMint, TierFakeIDRatchet}

// PaymentService handles blind token signing in exchange for verified payments.
// Each tier has its own RSA signing key so the tier is cryptographically bound
// to the signature — clients cannot forge a higher tier.
type PaymentService struct {
	signingKeys map[string]*rsa.PrivateKey // keyed by tier
	publicKeys  map[string]*rsa.PublicKey  // keyed by tier
	processors  map[string]PaymentProcessor
	batcher     *SigningBatcher // nil = sign immediately (no batching)
}

// NewPaymentService creates a new PaymentService with per-tier signing keys.
func NewPaymentService(keys map[string]*rsa.PrivateKey, processors map[string]PaymentProcessor) *PaymentService {
	pubKeys := make(map[string]*rsa.PublicKey, len(keys))
	for tier, key := range keys {
		pubKeys[tier] = &key.PublicKey
	}
	return &PaymentService{
		signingKeys: keys,
		publicKeys:  pubKeys,
		processors:  processors,
	}
}

// NewPaymentServiceWithBatcher creates a PaymentService that queues blind-signing
// requests into a SigningBatcher, breaking timing correlation between payment
// verification and token issuance.
func NewPaymentServiceWithBatcher(keys map[string]*rsa.PrivateKey, processors map[string]PaymentProcessor, batchInterval time.Duration, opts ...BatcherOption) *PaymentService {
	svc := NewPaymentService(keys, processors)
	svc.batcher = NewSigningBatcher(keys, batchInterval, opts...)
	return svc
}

// Batcher returns the service's SigningBatcher, or nil if batching is disabled.
func (s *PaymentService) Batcher() *SigningBatcher {
	return s.batcher
}

// ProcessPayment verifies a payment through the appropriate processor, then
// blind-signs the provided token with the tier-specific key.
// Payment details are not stored — privacy by design.
func (s *PaymentService) ProcessPayment(ctx context.Context, paymentMethod string, paymentProof []byte, blindedToken *big.Int) (*big.Int, string, error) {
	proc, ok := s.processors[paymentMethod]
	if !ok {
		return nil, "", errors.New("unsupported payment method: " + paymentMethod)
	}

	tier, err := proc.VerifyPayment(ctx, paymentProof)
	if err != nil {
		return nil, "", err
	}

	// If batching is enabled, submit to the batcher to break timing
	// correlation. Otherwise sign immediately (legacy/test path).
	if s.batcher != nil {
		blindSig, err := s.batcher.Submit(ctx, blindedToken, tier)
		if err != nil {
			return nil, "", fmt.Errorf("batched blind sign: %w", err)
		}
		return blindSig, tier, nil
	}

	key, ok := s.signingKeys[tier]
	if !ok {
		return nil, "", fmt.Errorf("no signing key for tier %q", tier)
	}

	blindSig, err := crypto.SignBlinded(blindedToken, key)
	if err != nil {
		return nil, "", fmt.Errorf("blind sign: %w", err)
	}

	return blindSig, tier, nil
}

// VerifyForTier verifies a blind signature against all tier keys and returns
// the matching tier. Returns ("", false) if no key verifies the signature.
func (s *PaymentService) VerifyForTier(token []byte, signature *big.Int) (string, bool) {
	for _, tier := range Tiers {
		pubKey, ok := s.publicKeys[tier]
		if !ok {
			continue
		}
		if crypto.VerifySignature(token, signature, pubKey) {
			return tier, true
		}
	}
	return "", false
}

// GetPublicKey returns the RSA public key for a specific tier.
func (s *PaymentService) GetPublicKey(tier string) *rsa.PublicKey {
	return s.publicKeys[tier]
}

// GetPublicKeys returns all tier public keys.
func (s *PaymentService) GetPublicKeys() map[string]*rsa.PublicKey {
	return s.publicKeys
}

// ErrUnknownTier is returned when SignForTier is called with a tier that has
// no signing key registered.
var ErrUnknownTier = errors.New("unknown signing tier")

// SignForTier blind-signs the given token with the specified tier's key.
// Unlike ProcessPayment, no PaymentProcessor is invoked — callers (e.g., the
// Fake ID mint handler) authenticate the request themselves before asking
// the enclave for a signature. Batching is honored if enabled.
func (s *PaymentService) SignForTier(ctx context.Context, tier string, blindedToken *big.Int) (*big.Int, error) {
	if s.batcher != nil {
		return s.batcher.Submit(ctx, blindedToken, tier)
	}
	key, ok := s.signingKeys[tier]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTier, tier)
	}
	return crypto.SignBlinded(blindedToken, key)
}

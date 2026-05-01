package payment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"
)

// safeIDPattern validates payment processor IDs to prevent URL injection.
var safeIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

// safeHexPattern validates hex-encoded hashes (e.g., Lightning payment hashes: 32-byte / 64 hex chars).
var safeHexPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// TestProcessor always succeeds with the "paid" tier. For testing only.
type TestProcessor struct{}

func (p *TestProcessor) VerifyPayment(_ context.Context, _ []byte) (string, error) {
	return "paid", nil
}

// stripeHTTPClient is an HTTP client with a 30-second timeout to prevent
// slow/malicious Stripe responses from hanging goroutines indefinitely.
var stripeHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	},
}

// StripeProcessor verifies payments via the Stripe API.
type StripeProcessor struct {
	APIKey string
	// BaseURL overrides the Stripe API base URL (for testing).
	BaseURL string
}

// stripeProof is the JSON structure expected in paymentProof.
type stripeProof struct {
	PaymentIntentID string `json:"payment_intent_id"`
}

// stripePaymentIntent is a minimal representation of Stripe's PaymentIntent response.
type stripePaymentIntent struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Amount int64  `json:"amount"` // in cents
}

func (p *StripeProcessor) VerifyPayment(ctx context.Context, paymentProof []byte) (string, error) {
	var proof stripeProof
	if err := json.Unmarshal(paymentProof, &proof); err != nil {
		return "", fmt.Errorf("invalid payment proof: %w", err)
	}
	if proof.PaymentIntentID == "" {
		return "", errors.New("missing payment_intent_id")
	}
	if !safeIDPattern.MatchString(proof.PaymentIntentID) {
		return "", errors.New("invalid payment_intent_id format")
	}

	baseURL := "https://api.stripe.com"
	if p.BaseURL != "" {
		baseURL = p.BaseURL
	}

	url := fmt.Sprintf("%s/v1/payment_intents/%s", baseURL, proof.PaymentIntentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.APIKey)

	resp, err := stripeHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("stripe API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		slog.Error("stripe API error", "status", resp.StatusCode, "body", string(body))
		return "", fmt.Errorf("payment processing failed")
	}

	var pi stripePaymentIntent
	if err := json.Unmarshal(body, &pi); err != nil {
		return "", fmt.Errorf("parse stripe response: %w", err)
	}

	if pi.Status != "succeeded" {
		return "", fmt.Errorf("payment not succeeded (status: %s)", pi.Status)
	}

	return stripeTierFromAmount(pi.Amount), nil
}

// stripeTierFromAmount maps a Stripe amount (in cents) to a tier.
func stripeTierFromAmount(amount int64) string {
	switch {
	case amount >= 1000: // $10+
		return "business"
	case amount >= 500: // $5+
		return "pro"
	default:
		return "paid"
	}
}

// LightningProcessor verifies payments via the Lightning Network (LND REST API).
type LightningProcessor struct {
	NodeURL    string
	Macaroon   string // hex-encoded macaroon
	TLSCertPEM []byte // PEM-encoded TLS certificate for the LND node
	// Client overrides the default HTTP client (for testing).
	Client *http.Client
}

// lightningProof is the JSON structure expected in paymentProof.
type lightningProof struct {
	PaymentHash string `json:"payment_hash"`
}

// lndInvoice is a minimal representation of an LND invoice lookup response.
type lndInvoice struct {
	Settled    bool   `json:"settled"`
	AmtPaidSat json.Number `json:"amt_paid_sat"`
}

func (p *LightningProcessor) VerifyPayment(ctx context.Context, paymentProof []byte) (string, error) {
	var proof lightningProof
	if err := json.Unmarshal(paymentProof, &proof); err != nil {
		return "", fmt.Errorf("invalid payment proof: %w", err)
	}
	if proof.PaymentHash == "" {
		return "", errors.New("missing payment_hash")
	}
	if !safeHexPattern.MatchString(proof.PaymentHash) {
		return "", errors.New("invalid payment_hash format: must be 64 hex characters")
	}

	url := fmt.Sprintf("%s/v1/invoice/%s", p.NodeURL, proof.PaymentHash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Grpc-Metadata-macaroon", p.Macaroon)

	client := p.Client
	if client == nil {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
		if len(p.TLSCertPEM) > 0 {
			// Pin to the LND node's self-signed certificate.
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(p.TLSCertPEM) {
				return "", fmt.Errorf("failed to parse LND TLS certificate")
			}
			tlsConfig.RootCAs = pool
		}
		client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("LND API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		slog.Error("LND API error", "status", resp.StatusCode, "body", string(body))
		return "", fmt.Errorf("payment processing failed")
	}

	var inv lndInvoice
	if err := json.Unmarshal(body, &inv); err != nil {
		return "", fmt.Errorf("parse LND response: %w", err)
	}

	if !inv.Settled {
		return "", errors.New("invoice not settled")
	}

	amtPaid, err := inv.AmtPaidSat.Int64()
	if err != nil {
		return "", fmt.Errorf("parse amt_paid_sat: %w", err)
	}

	return lightningTierFromSats(amtPaid), nil
}

// lightningTierFromSats maps satoshi amount to a tier.
func lightningTierFromSats(sats int64) string {
	switch {
	case sats >= 100000: // 100k sats
		return "business"
	case sats >= 50000: // 50k sats
		return "pro"
	default:
		return "paid"
	}
}

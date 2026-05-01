package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DKIMKeyResult is a single DKIM key pair from the smtp-outbound enclave.
type DKIMKeyResult struct {
	SealedPrivateKey []byte `json:"sealed_private_key"` // TEE-sealed private key (opaque blob)
	PublicKey        string `json:"public_key"`         // Base64-encoded public key for DNS
	Selector         string `json:"selector"`
}

// DKIMGenerateResponse is the response from the smtp-outbound DKIM API.
type DKIMGenerateResponse struct {
	Ed25519 *DKIMKeyResult `json:"ed25519,omitempty"`
	RSA     *DKIMKeyResult `json:"rsa,omitempty"`
}

// DKIMClient calls the smtp-outbound enclave's DKIM key generation API.
type DKIMClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewDKIMClient creates a client that calls the smtp-outbound DKIM API.
func NewDKIMClient(baseURL, apiKey string) *DKIMClient {
	return &DKIMClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// GenerateDKIM requests new Ed25519 + RSA DKIM key pairs from the enclave.
// The private keys are sealed inside the enclave and returned as opaque blobs.
func (c *DKIMClient) GenerateDKIM(ctx context.Context) (*DKIMGenerateResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/dkim/generate", bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("dkim client: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dkim client: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dkim client: unexpected status %d", resp.StatusCode)
	}

	var result DKIMGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("dkim client: decode response: %w", err)
	}
	return &result, nil
}

package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrProcessorNotImplemented is returned by stub processors that have not yet
// been wired to a real payment network. Callers can check errors.Is(err,
// ErrProcessorNotImplemented) and return HTTP 501 to the client.
var ErrProcessorNotImplemented = errors.New("payment processor not implemented")

// ---------------------------------------------------------------------------
// Bitcoin On-Chain Processor (stub)
// ---------------------------------------------------------------------------

// BitcoinOnChainProcessor verifies on-chain BTC payments via a Bitcoin Core
// JSON-RPC node. This is a stub — full implementation will query the node for
// transaction confirmation and output amounts.
type BitcoinOnChainProcessor struct {
	NodeURL               string
	RPCUser               string
	RPCPassword           string
	RequiredConfirmations int
}

// bitcoinOnChainProof is the JSON structure expected in paymentProof.
type bitcoinOnChainProof struct {
	TXID string `json:"txid"`
}

func (p *BitcoinOnChainProcessor) VerifyPayment(_ context.Context, paymentProof []byte) (string, error) {
	var proof bitcoinOnChainProof
	if err := json.Unmarshal(paymentProof, &proof); err != nil {
		return "", fmt.Errorf("invalid payment proof: %w", err)
	}
	if proof.TXID == "" {
		return "", errors.New("missing txid")
	}

	// Stub: callers must check errors.Is(err, ErrProcessorNotImplemented).
	return "", fmt.Errorf("bitcoin on-chain: %w", ErrProcessorNotImplemented)
}

// ---------------------------------------------------------------------------
// Monero Processor (stub)
// ---------------------------------------------------------------------------

// MoneroProcessor verifies Monero payments via the monero-wallet-rpc
// check_tx_proof RPC method. This is a stub.
type MoneroProcessor struct {
	WalletRPCURL string
}

// moneroProof is the JSON structure expected in paymentProof.
type moneroProof struct {
	TXHash  string `json:"tx_hash"`
	TXKey   string `json:"tx_key"`
	Address string `json:"address"`
}

func (p *MoneroProcessor) VerifyPayment(_ context.Context, paymentProof []byte) (string, error) {
	var proof moneroProof
	if err := json.Unmarshal(paymentProof, &proof); err != nil {
		return "", fmt.Errorf("invalid payment proof: %w", err)
	}
	if proof.TXHash == "" {
		return "", errors.New("missing tx_hash")
	}
	if proof.TXKey == "" {
		return "", errors.New("missing tx_key")
	}
	if proof.Address == "" {
		return "", errors.New("missing address")
	}

	// Stub: callers must check errors.Is(err, ErrProcessorNotImplemented).
	return "", fmt.Errorf("monero: %w", ErrProcessorNotImplemented)
}

// ---------------------------------------------------------------------------
// Ethereum Processor (stub)
// ---------------------------------------------------------------------------

// EthereumProcessor verifies ETH or ERC-20 stablecoin payments via an
// Ethereum JSON-RPC endpoint. When ContractAddress is set, it verifies
// ERC-20 token transfers; otherwise it verifies native ETH transfers.
// This is a stub.
type EthereumProcessor struct {
	RPCURL          string
	ContractAddress string // ERC-20 contract address; empty for native ETH
}

// ethereumProof is the JSON structure expected in paymentProof.
type ethereumProof struct {
	TXHash string `json:"tx_hash"`
}

func (p *EthereumProcessor) VerifyPayment(_ context.Context, paymentProof []byte) (string, error) {
	var proof ethereumProof
	if err := json.Unmarshal(paymentProof, &proof); err != nil {
		return "", fmt.Errorf("invalid payment proof: %w", err)
	}
	if proof.TXHash == "" {
		return "", errors.New("missing tx_hash")
	}

	// Stub: callers must check errors.Is(err, ErrProcessorNotImplemented).
	return "", fmt.Errorf("ethereum: %w", ErrProcessorNotImplemented)
}

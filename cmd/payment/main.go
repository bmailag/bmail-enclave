// Package main is the payment SGX enclave entry point.
//
// Live flows:
//
//	POST /payment/fakeid-mint     — issue one-shot Fake ID creation credential
//	POST /payment/fakeid-ratchet  — issue Fake ID max_valid_until ratchet credential
//	GET  /payment/pubkey          — distribute signing public keys (all tiers)
//	GET  /payment/attestation     — SGX quote over all public keys, for gateway echeck
//
// Legacy flows (retained for reference, not wired to production endpoints):
//
//	POST /payment/sign            — blind-sign a token after verifying a payment
//	POST /payment/redeem          — verify a blind signature and mark token spent
//
// All Fake ID flows authenticate via Authorization: Bearer <PAYMENT_API_KEY>
// from the backend. The backend confirms the primary's Stripe subscription
// before calling the enclave; the enclave then blind-signs with the tier key
// corresponding to the requested credential type.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bmailag/bmail/internal/config"
	"github.com/bmailag/bmail/internal/crypto"
	"github.com/bmailag/bmail/internal/gateway"
	"github.com/bmailag/bmail/internal/payment"
	"github.com/bmailag/bmail/internal/storage"
	"github.com/bmailag/bmail/internal/tee"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	// Database connection.
	dbURL := config.Require("DATABASE_URL", "")
	db, err := storage.NewDB(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect to database: %v", err)
	}
	defer db.Close()

	paymentStore := storage.NewPaymentStore(db)

	// TEE runtime (SimRuntime in dev, EGoRuntime with -tags ego).
	runtime := tee.NewRuntime()

	// TLS config: in SGX mode, embeds attestation quote in cert so the
	// gateway can verify payment's enclave identity via echeck on every
	// connection. In dev mode, falls back to internal mTLS.
	paymentTLS, _, err := tee.GenerateServerTLSConfig(runtime, "payment.internal", "/opt/bmail/sealed/sealed_payment_tls_key.bin")
	if err != nil {
		return fmt.Errorf("generate payment TLS config: %v", err)
	}
	slog.Info("TLS initialized", "service", "payment", "enclave_id", runtime.SelfID())

	// Generate or load per-tier RSA signing keys.
	signingKeys := make(map[string]*rsa.PrivateKey)
	for _, tier := range payment.Tiers {
		key, err := loadOrGenerateKey(runtime, tier)
		if err != nil {
			return fmt.Errorf("load/generate signing key for tier %s: %v", tier, err)
		}
		signingKeys[tier] = key
	}

	// Load-or-seal the two new enclave-only secrets that back the atomic
	// Fake ID slot design (migration 089). fakeid_tag_key derives
	// primary_tag; fakeid_attestation_key signs (H(sig) || primary_tag)
	// so the FakeID-side verify path can bind tag to credential without
	// giving bmail operators any way to reverse the tag back to
	// primary_id. Back both up like private.pem — losing them orphans
	// every row in fakeid_pending_slots / fakeid_consumed_slots.
	fakeidTagKey, err := payment.LoadOrSealFakeIDTagKey(runtime)
	if err != nil {
		return fmt.Errorf("load/generate fakeid tag key: %v", err)
	}
	fakeidAttKey, err := payment.LoadOrSealFakeIDAttestationKey(runtime)
	if err != nil {
		return fmt.Errorf("load/generate fakeid attestation key: %v", err)
	}
	slotStore := storage.NewFakeIDSlotStore(db)

	// Payment processors.
	processors := map[string]payment.PaymentProcessor{
		"test": &payment.TestProcessor{},
	}

	// Register Stripe processor if configured.
	if stripeKey := os.Getenv("STRIPE_SECRET_KEY"); stripeKey != "" {
		processors["stripe"] = &payment.StripeProcessor{APIKey: stripeKey}
		slog.Info("registered stripe payment processor")
	}

	// Register Lightning processor if configured.
	if lndURL := os.Getenv("LND_REST_URL"); lndURL != "" {
		macaroon := os.Getenv("LND_MACAROON")
		if macaroon == "" {
			return fmt.Errorf("LND_REST_URL set but LND_MACAROON is missing")
		}
		processors["lightning"] = &payment.LightningProcessor{
			NodeURL:  lndURL,
			Macaroon: macaroon,
		}
		slog.Info("registered lightning payment processor")
	}

	// Crypto payment processors (Bitcoin, Monero, Ethereum) are experimental.
	// Enable with ENABLE_EXPERIMENTAL_CRYPTO=true alongside the RPC URL.
	experimentalCrypto := os.Getenv("ENABLE_EXPERIMENTAL_CRYPTO") == "true"

	if btcURL := os.Getenv("BITCOIN_RPC_URL"); btcURL != "" {
		if experimentalCrypto {
			processors["bitcoin"] = &payment.BitcoinOnChainProcessor{
				NodeURL:               btcURL,
				RPCUser:               os.Getenv("BITCOIN_RPC_USER"),
				RPCPassword:           os.Getenv("BITCOIN_RPC_PASSWORD"),
				RequiredConfirmations: 6,
			}
			slog.Warn("registered EXPERIMENTAL bitcoin on-chain payment processor")
		} else {
			slog.Info("BITCOIN_RPC_URL set but ENABLE_EXPERIMENTAL_CRYPTO not enabled, skipping")
		}
	}

	if xmrURL := os.Getenv("MONERO_WALLET_RPC_URL"); xmrURL != "" {
		if experimentalCrypto {
			processors["monero"] = &payment.MoneroProcessor{
				WalletRPCURL: xmrURL,
			}
			slog.Warn("registered EXPERIMENTAL monero payment processor")
		} else {
			slog.Info("MONERO_WALLET_RPC_URL set but ENABLE_EXPERIMENTAL_CRYPTO not enabled, skipping")
		}
	}

	if ethURL := os.Getenv("ETHEREUM_RPC_URL"); ethURL != "" {
		if experimentalCrypto {
			processors["ethereum"] = &payment.EthereumProcessor{
				RPCURL:          ethURL,
				ContractAddress: os.Getenv("ETHEREUM_CONTRACT_ADDRESS"),
			}
			slog.Warn("registered EXPERIMENTAL ethereum payment processor")
		} else {
			slog.Info("ETHEREUM_RPC_URL set but ENABLE_EXPERIMENTAL_CRYPTO not enabled, skipping")
		}
	}

	// Batch signing breaks timing correlation between payment and token issuance.
	// Set BATCH_SIGNING_INTERVAL (e.g. "5s") to enable; leave empty to disable.
	var svc *payment.PaymentService
	batchIntervalStr := os.Getenv("BATCH_SIGNING_INTERVAL")
	if batchIntervalStr != "" {
		batchInterval, err := time.ParseDuration(batchIntervalStr)
		if err != nil {
			return fmt.Errorf("invalid BATCH_SIGNING_INTERVAL %q: %v", batchIntervalStr, err)
		}
		svc = payment.NewPaymentServiceWithBatcher(signingKeys, processors, batchInterval)
		svc.Batcher().Start()
		defer svc.Batcher().Stop()
		slog.Info("batch signing enabled", "interval", batchInterval)
	} else {
		svc = payment.NewPaymentService(signingKeys, processors)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", gateway.HealthHandler())
	rc := gateway.NewReadinessChecker()
	rc.Add("postgres", func(ctx context.Context) error { return db.Pool.Ping(ctx) })
	mux.HandleFunc("GET /readyz", rc.Handler())
	registerRoutes(mux, svc, paymentStore, runtime, fakeidSlotDeps{
		svc:          svc,
		paymentStore: paymentStore,
		slotStore:    slotStore,
		tagKey:       fakeidTagKey,
		attKey:       fakeidAttKey,
	})

	addr := os.Getenv("PAYMENT_ADDR")
	if addr == "" {
		addr = ":8085"
	}

	// Durability snapshots of payment's sealed key files. See
	// docs/runbooks/key-backup-and-recovery.md. Files are MRSIGNER-
	// sealed, so any payment binary signed by the same private.pem
	// can unseal them — bytes-to-R2 is sufficient for full recovery.
	if snapper, err := buildPaymentSnapshotter(); err != nil {
		return fmt.Errorf("build payment snapshotter: %v", err)
	} else if snapper != nil {
		snapFiles := paymentSnapshotFiles()
		snapCtx, snapCancel := context.WithCancel(ctx)
		defer snapCancel()
		go payment.RunDailySnapshotter(snapCtx, snapper, snapFiles, slog.Default())
		slog.Info("payment snapshot pipeline armed",
			"files", len(snapFiles))
	} else if os.Getenv("VP_ENV") == "production" {
		return fmt.Errorf("PAYMENT_SNAPSHOT_S3_* or PAYMENT_SNAPSHOT_LOCAL_DIR must be set in production (key-backup runbook)")
	}

	// Limit request bodies to 1MB to prevent DoS.
	handler := http.MaxBytesHandler(mux, 1<<20)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         paymentTLS,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	done := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
		}
		close(done)
	}()

	// Use mTLS unless PAYMENT_PLAINHTTP=true (dev mode).
	if os.Getenv("PAYMENT_PLAINHTTP") == "true" {
		srv.TLSConfig = nil
		slog.Warn("starting payment service WITHOUT mTLS (dev mode)")
		slog.Info("payment service listening", "addr", addr, "mtls", false)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("listen: %v", err)
		}
	} else {
		slog.Info("payment service listening", "addr", addr, "mtls", true)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("listen: %v", err)
		}
	}
	<-done
	slog.Info("payment service stopped")
	return nil
}

func loadOrGenerateKey(runtime tee.TEERuntime, tier string) (*rsa.PrivateKey, error) {
	sealedPath := fmt.Sprintf("/opt/bmail/sealed/sealed_payment_key_%s.bin", tier)
	keyBytes, err := tee.LoadOrSealBytes(runtime, sealedPath, func() ([]byte, error) {
		key, err := crypto.GenerateBlindSigningKey(3072)
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKCS1PrivateKey(key), nil
	})
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(keyBytes)
}

// --- HTTP types ---

type signRequest struct {
	PaymentMethod string `json:"payment_method"`
	PaymentProof  string `json:"payment_proof"`  // base64
	BlindedToken  string `json:"blinded_token"`   // hex
}

type signResponse struct {
	BlindSignature string `json:"blind_signature"` // hex
	Tier           string `json:"tier"`
}

type redeemRequest struct {
	Token     string `json:"token"`     // hex
	Signature string `json:"signature"` // hex
}

type redeemResponse struct {
	Tier string `json:"tier"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// --- Rate limiter (bounded) ---

const maxRateLimitEntries = 10000

type ipRateLimiter struct {
	mu      sync.Mutex
	clients map[string]*rateBucket
	rate    int           // max requests per window
	window  time.Duration // window duration
}

type rateBucket struct {
	count    int
	windowAt time.Time
}

func newIPRateLimiter(rate int, window time.Duration) *ipRateLimiter {
	rl := &ipRateLimiter{
		clients: make(map[string]*rateBucket),
		rate:    rate,
		window:  window,
	}
	// Evict stale entries every 2x the window to bound memory.
	go func() {
		ticker := time.NewTicker(2 * window)
		defer ticker.Stop()
		for range ticker.C {
			rl.evictStale()
		}
	}()
	return rl
}

func (rl *ipRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.clients[ip]
	if !ok || now.Sub(b.windowAt) >= rl.window {
		// Enforce hard cap to prevent memory exhaustion from many unique IPs.
		if !ok && len(rl.clients) >= maxRateLimitEntries {
			return false // reject when at capacity
		}
		rl.clients[ip] = &rateBucket{count: 1, windowAt: now}
		return true
	}
	b.count++
	return b.count <= rl.rate
}

func (rl *ipRateLimiter) evictStale() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, b := range rl.clients {
		if now.Sub(b.windowAt) >= rl.window {
			delete(rl.clients, ip)
		}
	}
}

func extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func rateLimitMiddleware(rl *ipRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !rl.allow(ip) {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "rate limit exceeded"})
			return
		}
		next(w, r)
	}
}

// requireAPIKey checks the Authorization header for a shared internal API key.
// The gateway authenticates the user, then proxies to payment with this key.
func requireAPIKey(apiKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + apiKey
		if auth == "" || subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
			return
		}
		next(w, r)
	}
}

// --- Routes ---

func registerRoutes(mux *http.ServeMux, svc *payment.PaymentService, paymentStore *storage.PaymentStore, runtime tee.TEERuntime, slotDeps fakeidSlotDeps) {
	signLimiter := newIPRateLimiter(10, time.Minute)
	redeemLimiter := newIPRateLimiter(30, time.Minute)

	// PAYMENT_API_KEY: shared secret between gateway and payment service.
	// The gateway authenticates the user, then proxies with this key.
	apiKey := os.Getenv("PAYMENT_API_KEY")

	if apiKey == "" {
		if config.IsProduction() {
			log.Fatal("PAYMENT_API_KEY must be set in production")
		}
		slog.Warn("PAYMENT_API_KEY not set, payment endpoints are unauthenticated")
	}

	sign := handleSign(svc)
	redeem := handleRedeem(svc, paymentStore)
	mintFakeID := handleFakeIDMint(svc, paymentStore)
	ratchetFakeID := handleFakeIDRatchet(svc)
	if apiKey != "" {
		sign = requireAPIKey(apiKey, sign)
		redeem = requireAPIKey(apiKey, redeem)
		mintFakeID = requireAPIKey(apiKey, mintFakeID)
		ratchetFakeID = requireAPIKey(apiKey, ratchetFakeID)
	}
	mux.HandleFunc("POST /payment/sign", rateLimitMiddleware(signLimiter, sign))
	mux.HandleFunc("POST /payment/redeem", rateLimitMiddleware(redeemLimiter, redeem))
	mux.HandleFunc("POST /payment/fakeid-mint", rateLimitMiddleware(signLimiter, mintFakeID))
	mux.HandleFunc("POST /payment/fakeid-ratchet", rateLimitMiddleware(signLimiter, ratchetFakeID))
	mux.HandleFunc("GET /payment/pubkey", handlePubKey(svc))
	mux.HandleFunc("GET /payment/attestation", handleAttestation(svc, runtime))

	// Enclave-authoritative slot handlers (POST /payment/fakeid/*) for
	// the slot-state-in-enclave model. Co-exist with the legacy
	// /payment/fakeid-mint path; the legacy path will be retired once
	// all callers migrate. Shares signLimiter because mint volume is
	// comparable.
	registerFakeIDSlotRoutes(mux, slotDeps, apiKey, signLimiter)
}

// --- Fake ID mint + ratchet handlers ---

type fakeIDMintRequest struct {
	SubscriptionID string `json:"subscription_id"` // e.g. Stripe sub_...
	BlindedToken   string `json:"blinded_token"`   // hex
}

type fakeIDMintResponse struct {
	BlindSignature string `json:"blind_signature"` // hex
}

// handleFakeIDMint atomically marks the subscription as having minted a Fake
// ID, then blind-signs the user's token with the fakeid_mint tier key. If the
// subscription has already minted, returns 409 without signing.
//
// The backend is trusted to verify that the caller's primary Stripe sub is
// still active before calling this endpoint (authenticated via the shared
// PAYMENT_API_KEY). The enclave only enforces the one-per-subscription rule
// and issues the signature.
func handleFakeIDMint(svc *payment.PaymentService, store *storage.PaymentStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req fakeIDMintRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
			return
		}
		if req.SubscriptionID == "" {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "subscription_id is required"})
			return
		}
		blindedBytes, err := hex.DecodeString(req.BlindedToken)
		if err != nil || len(blindedBytes) == 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid hex in blinded_token"})
			return
		}
		blinded := new(big.Int).SetBytes(blindedBytes)

		// Atomic test-and-set: fails with ErrFakeIDAlreadyMinted if the sub
		// already minted one. Done BEFORE signing so a double-submit can't
		// produce two credentials.
		if err := store.MarkFakeIDMinted(r.Context(), req.SubscriptionID); err != nil {
			if errors.Is(err, storage.ErrFakeIDAlreadyMinted) {
				writeJSON(w, http.StatusConflict, errorResponse{Error: "fakeid already minted for this subscription"})
				return
			}
			slog.Error("mark fakeid minted", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
			return
		}

		blindSig, err := svc.SignForTier(r.Context(), payment.TierFakeIDMint, blinded)
		if err != nil {
			slog.Error("fakeid mint sign", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "signing failed"})
			return
		}
		writeJSON(w, http.StatusOK, fakeIDMintResponse{
			BlindSignature: hex.EncodeToString(blindSig.Bytes()),
		})
	}
}

type fakeIDRatchetRequest struct {
	BlindedToken string `json:"blinded_token"` // hex
}

type fakeIDRatchetResponse struct {
	BlindSignature string `json:"blind_signature"` // hex
}

// handleFakeIDRatchet blind-signs a Fake ID ratchet token with the
// fakeid_ratchet tier key. Unlike mint, there's no one-per-subscription
// gate — primaries can request ratchet credentials whenever their Stripe
// sub is valid (verified by the backend before the call). Batched via the
// SigningBatcher so issuance time is decoupled from redemption time.
func handleFakeIDRatchet(svc *payment.PaymentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req fakeIDRatchetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
			return
		}
		blindedBytes, err := hex.DecodeString(req.BlindedToken)
		if err != nil || len(blindedBytes) == 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid hex in blinded_token"})
			return
		}
		blinded := new(big.Int).SetBytes(blindedBytes)

		blindSig, err := svc.SignForTier(r.Context(), payment.TierFakeIDRatchet, blinded)
		if err != nil {
			slog.Error("fakeid ratchet sign", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "signing failed"})
			return
		}
		writeJSON(w, http.StatusOK, fakeIDRatchetResponse{
			BlindSignature: hex.EncodeToString(blindSig.Bytes()),
		})
	}
}

func handleAttestation(svc *payment.PaymentService, runtime tee.TEERuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Build attestation data: all tier public keys concatenated,
		// then SHA-256'd to fit SGX's 64-byte reportData field.
		// (Multiple RSA pubkeys easily exceed the limit; without the
		// hash, EGo rejects the call with "reportData too large".)
		// The /verify page hashes the live blind-sig pubkeys the same
		// way to cross-check the bound measurement.
		var raw []byte
		for _, tier := range payment.Tiers {
			pk := svc.GetPublicKey(tier)
			if pk != nil {
				der := x509.MarshalPKCS1PublicKey(pk)
				raw = append(raw, der...)
			}
		}
		var userData []byte
		if len(raw) > 0 {
			h := sha256.Sum256(raw)
			userData = h[:]
		}
		report, err := runtime.Attest(userData)
		if err != nil {
			slog.Error("payment attestation failed",
				"userdata_bytes", len(userData),
				"raw_pubkey_bytes", len(raw),
				"error", err.Error())
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "attestation failed"})
			return
		}
		// F-02b: expose the concatenated tier-pubkey DER bytes the
		// quote's REPORTDATA is hashed from. The /verify page bases64-
		// decodes this, re-hashes, and compares to REPORTDATA[:32] for
		// an independent bind check — same guarantee as gateway /
		// smtp-inbound / smtp-outbound provide via tls_public_key. The
		// tier pubkeys are public (used by blind-sig clients) so
		// publishing them here doesn't leak anything.
		writeJSON(w, http.StatusOK, map[string]any{
			"attestation_report":  hex.EncodeToString(report),
			"enclave_measurement": runtime.SelfID(),
			"timestamp":           time.Now().UTC().Format(time.RFC3339),
			"tier_pubkeys_der":    base64.StdEncoding.EncodeToString(raw),
		})
	}
}

func handleSign(svc *payment.PaymentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
			return
		}

		blindedBytes, err := hex.DecodeString(req.BlindedToken)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid hex in blinded_token"})
			return
		}
		blinded := new(big.Int).SetBytes(blindedBytes)

		blindSig, tier, err := svc.ProcessPayment(r.Context(), req.PaymentMethod, []byte(req.PaymentProof), blinded)
		if err != nil {
			slog.Error("payment processing failed", "error", err)
			writeJSON(w, http.StatusPaymentRequired, errorResponse{Error: "payment verification failed"})
			return
		}

		writeJSON(w, http.StatusOK, signResponse{
			BlindSignature: hex.EncodeToString(blindSig.Bytes()),
			Tier:           tier,
		})
	}
}

type pubKeyEntry struct {
	Tier      string `json:"tier"`
	PublicKey string `json:"public_key"` // PEM
}

func handlePubKey(svc *payment.PaymentService) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		pubKeys := svc.GetPublicKeys()
		var entries []pubKeyEntry
		for _, tier := range payment.Tiers {
			pk, ok := pubKeys[tier]
			if !ok {
				continue
			}
			der := x509.MarshalPKCS1PublicKey(pk)
			pemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: der,
			})
			entries = append(entries, pubKeyEntry{Tier: tier, PublicKey: string(pemBytes)})
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

func handleRedeem(svc *payment.PaymentService, paymentStore *storage.PaymentStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req redeemRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
			return
		}

		tokenBytes, err := hex.DecodeString(req.Token)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid hex in token"})
			return
		}

		sigBytes, err := hex.DecodeString(req.Signature)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid hex in signature"})
			return
		}
		sig := new(big.Int).SetBytes(sigBytes)

		// Verify blind signature against all tier keys.
		tier, valid := svc.VerifyForTier(tokenBytes, sig)
		if !valid {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid signature"})
			return
		}

		// Atomic insert — prevents double-spend race condition.
		h := sha256.Sum256(tokenBytes)
		tokenHash := h[:]

		if err := paymentStore.InsertSpentToken(r.Context(), tokenHash, tier); err != nil {
			if err == storage.ErrTokenAlreadySpent {
				writeJSON(w, http.StatusConflict, errorResponse{Error: "token already redeemed"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
			return
		}

		writeJSON(w, http.StatusOK, redeemResponse{Tier: tier})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// paymentSnapshotFiles returns the list of sealed paths to back up
// per the runbook. Override with PAYMENT_SNAPSHOT_FILES (comma-
// separated absolute paths) if the operator wants a custom set.
func paymentSnapshotFiles() []string {
	if csv := os.Getenv("PAYMENT_SNAPSHOT_FILES"); csv != "" {
		var out []string
		for _, p := range strings.Split(csv, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	base := []string{
		"sealed_payment_key_business.bin",
		"sealed_payment_key_paid.bin",
		"sealed_payment_key_pro.bin",
		"sealed_payment_key_fakeid_mint.bin",
		"sealed_payment_key_fakeid_ratchet.bin",
		"sealed_fakeid_attestation_key.bin",
		"sealed_fakeid_tag_key.bin",
		"sealed_payment_tls_key.bin",
	}
	out := make([]string, 0, len(base))
	for _, b := range base {
		out = append(out, "/opt/bmail/sealed/"+b)
	}
	return out
}

// buildPaymentSnapshotter inspects PAYMENT_SNAPSHOT_* env vars and
// returns a Snapshotter. Returns (nil, nil) if no backup target is
// configured (caller decides whether that's fatal — production runs
// reject this).
//
// Precedence: S3 endpoint configured → S3Snapshotter; else local
// dir configured → LocalFSSnapshotter; else nil.
func buildPaymentSnapshotter() (payment.Snapshotter, error) {
	endpoint := os.Getenv("PAYMENT_SNAPSHOT_S3_ENDPOINT")
	bucket := os.Getenv("PAYMENT_SNAPSHOT_S3_BUCKET")
	if endpoint != "" || bucket != "" {
		if endpoint == "" || bucket == "" {
			return nil, fmt.Errorf("PAYMENT_SNAPSHOT_S3_ENDPOINT and PAYMENT_SNAPSHOT_S3_BUCKET must both be set")
		}
		prefix := os.Getenv("PAYMENT_SNAPSHOT_S3_PREFIX")
		if prefix == "" {
			prefix = "payment-snapshots/"
		}
		return payment.NewS3Snapshotter(
			endpoint,
			os.Getenv("PAYMENT_SNAPSHOT_S3_ACCESS_KEY"),
			os.Getenv("PAYMENT_SNAPSHOT_S3_SECRET_KEY"),
			bucket,
			prefix,
			os.Getenv("PAYMENT_SNAPSHOT_S3_INSECURE") != "1",
			slog.Default(),
		)
	}
	if dir := os.Getenv("PAYMENT_SNAPSHOT_LOCAL_DIR"); dir != "" {
		return &payment.LocalFSSnapshotter{Dir: dir, Logger: slog.Default()}, nil
	}
	return nil, nil
}

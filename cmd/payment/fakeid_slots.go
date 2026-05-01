package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"github.com/bmailag/bmail/internal/crypto"
	"github.com/bmailag/bmail/internal/payment"
	"github.com/bmailag/bmail/internal/storage"
)

// Fakeid handlers for the enclave-authoritative slot model (migration
// 089). These replace a legacy fakeid-mint path whose slot state lived
// on users.has_fakeid; they co-exist during the rollout window so the
// backend can cut over tier-by-tier.
//
// Endpoints:
//
//	POST /payment/fakeid/mint              — blind-sign + attest (no state write)
//	POST /payment/fakeid/verify-credential — atomic InsertConsumed + spent_tokens
//	GET  /payment/fakeid/slot-status       — free | consumed
//	POST /payment/fakeid/admin/seed-consumed — backfill helper for migrating users
//
// Slot state is single-table: fakeid_consumed_slots, keyed by
// primary_tag = HMAC(fakeid_tag_key, primary_id). Mint issues a fresh
// credential on every call — no pending reservation — and the
// 1-per-primary invariant is enforced by the unique primary_tag at
// verify time. Abandoning a mint is a no-op; any credential the user
// kept would hit 409 at verify if another credential from the same
// primary already registered. The earlier pending_slots table is
// retained by migration 089 but unused; a follow-up migration drops it.

// fakeidSlotDeps bundles the sealed secrets + data stores the v2 handlers
// need. Passed to registerFakeIDSlotRoutes once at startup.
type fakeidSlotDeps struct {
	svc          *payment.PaymentService
	paymentStore *storage.PaymentStore
	slotStore    *storage.FakeIDSlotStore
	tagKey       payment.FakeIDTagKey
	attKey       payment.FakeIDAttestationKey
}

// --- POST /payment/fakeid/mint ---

type fakeidMintV2Request struct {
	PrimaryID    string `json:"primary_id"`    // UUID, sent by the backend after Stripe check
	BlindedToken string `json:"blinded_token"` // hex, as blinded by the client
}

type fakeidMintV2Response struct {
	BlindSignature  string `json:"blind_signature"`  // hex; RSA blind sig over the token (unblinded at client)
	PrimaryTag      string `json:"primary_tag"`      // hex, 32 bytes
	TagAttestation  string `json:"tag_attestation"`  // hex, ed25519 sig over H(sig)||primary_tag
	AttestationAlgo string `json:"attestation_algo"` // "ed25519", for forward-compat
}

// handleFakeIDMintV2 short-circuits when the primary already has a
// consumed row (don't waste a blind-sig computation on someone who
// can't register anyway), then blind-signs, signs a tag-attestation,
// and hands back the credential. Crucially it doesn't write any
// enclave state — a primary can call mint repeatedly, each call
// returns a fresh credential, and 1-per-primary is enforced later at
// verify-credential via the unique primary_tag on consumed_slots.
//
// This is what makes abandoned mints free: no slot was ever claimed,
// so closing the /fakeid/register window is purely a client-side event.
func handleFakeIDMintV2(deps fakeidSlotDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req fakeidMintV2Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
			return
		}
		if req.PrimaryID == "" {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "primary_id is required"})
			return
		}
		blindedBytes, err := hex.DecodeString(req.BlindedToken)
		if err != nil || len(blindedBytes) == 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid hex in blinded_token"})
			return
		}

		primaryTag := payment.DerivePrimaryTag(deps.tagKey, req.PrimaryID)

		// Short-circuit: if this primary already has a Fake ID there's
		// no point burning CPU on a blind-sig they can't use. Cheap PG
		// lookup, keyed on the primary-key index.
		status, err := deps.slotStore.StatusForTag(r.Context(), primaryTag)
		if err != nil {
			slog.Error("fakeid v2 mint: status lookup", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
			return
		}
		if status.State == storage.SlotConsumed {
			writeJSON(w, http.StatusConflict, errorResponse{Error: "fakeid already exists for this primary"})
			return
		}

		blinded := new(big.Int).SetBytes(blindedBytes)
		blindSig, err := deps.svc.SignForTier(r.Context(), payment.TierFakeIDMint, blinded)
		if err != nil {
			slog.Error("fakeid v2 mint: blind sign", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "signing failed"})
			return
		}

		// Attestation signs primary_tag itself — proof that this tag was
		// derived by the enclave (and not forged by a client presenting
		// random bytes). Not bound to the credential; see the comment
		// on SignTagAttestation for why.
		attSig := deps.attKey.SignTagAttestation(primaryTag)

		writeJSON(w, http.StatusOK, fakeidMintV2Response{
			BlindSignature:  hex.EncodeToString(blindSig.Bytes()),
			PrimaryTag:      hex.EncodeToString(primaryTag),
			TagAttestation:  hex.EncodeToString(attSig),
			AttestationAlgo: "ed25519",
		})
	}
}

// --- POST /payment/fakeid/verify-credential ---

type verifyCredRequest struct {
	Token          string `json:"token"`           // hex, the unblinded token bytes
	Signature      string `json:"signature"`       // hex, RSA blind-sig after unblinding
	PrimaryTag     string `json:"primary_tag"`     // hex, 32 bytes from the mint response
	TagAttestation string `json:"tag_attestation"` // hex, ed25519 sig over H(sig)||primary_tag
}

type verifyCredResponse struct {
	OK bool `json:"ok"`
}

// handleFakeIDVerifyCredential is the atomicity hinge of the whole
// redesign. The FakeID-side register handler forwards the full
// credential here; we verify every piece and — in two ordered inserts
// fenced by PG's unique-key constraints — mark the token spent AND
// insert the consumed row. A conflict on either side means the
// credential (or the primary) already registered; the FakeID-side
// register surfaces that as 409.
//
// Order matters: spent_tokens first, then consumed_slots. If two
// concurrent verifies race from the same primary, both insert the
// same primary_tag into consumed_slots, and the primary-key conflict
// on the second is what blocks the double-register.
//
// Unlinkability: primary_tag is opaque to the FakeID-side backend (it
// just forwards bytes), and the enclave never logs primary_id. Tags in
// PG stay HMAC-obscured.
func handleFakeIDVerifyCredential(deps fakeidSlotDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req verifyCredRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
			return
		}
		tokenBytes, err := hex.DecodeString(req.Token)
		if err != nil || len(tokenBytes) == 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid hex in token"})
			return
		}
		sigBytes, err := hex.DecodeString(req.Signature)
		if err != nil || len(sigBytes) == 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid hex in signature"})
			return
		}
		primaryTag, err := hex.DecodeString(req.PrimaryTag)
		if err != nil || len(primaryTag) != 32 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid primary_tag"})
			return
		}
		attSig, err := hex.DecodeString(req.TagAttestation)
		if err != nil || len(attSig) == 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid hex in tag_attestation"})
			return
		}

		// 1) Blind-sig verifies on token under the mint tier's public key.
		pub := deps.svc.GetPublicKey(payment.TierFakeIDMint)
		if pub == nil {
			slog.Error("fakeid v2 verify: mint pubkey missing")
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "pubkey unavailable"})
			return
		}
		sig := new(big.Int).SetBytes(sigBytes)
		if !crypto.VerifySignature(tokenBytes, sig, pub) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid blind signature"})
			return
		}

		// 2) Tag attestation verifies on primary_tag. Proves the tag
		// came from the enclave — a client can't forge a tag because
		// the attestation key stays sealed inside.
		if !deps.attKey.VerifyTagAttestation(primaryTag, attSig) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid tag attestation"})
			return
		}

		// 3) Atomic consume: spent_tokens first (per-credential replay
		// protection), then consumed_slots (per-primary uniqueness).
		// Both are ON CONFLICT DO NOTHING so racing verifies from the
		// same primary see a clean "someone else won" 409 without any
		// partially-applied state.
		tokenHashArr := sha256.Sum256(tokenBytes)
		if err := deps.paymentStore.InsertSpentToken(r.Context(), tokenHashArr[:], payment.TierFakeIDMint); err != nil {
			if errors.Is(err, storage.ErrTokenAlreadySpent) {
				writeJSON(w, http.StatusConflict, errorResponse{Error: "credential already used"})
				return
			}
			slog.Error("fakeid v2 verify: insert spent token", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "spent-token check failed"})
			return
		}
		if err := deps.slotStore.InsertConsumed(r.Context(), primaryTag); err != nil {
			if errors.Is(err, storage.ErrSlotAlreadyTaken) {
				// Another credential from the same primary registered
				// first. Token is already burned from step (3a); the
				// FakeID-side will see 409 and stop.
				writeJSON(w, http.StatusConflict, errorResponse{Error: "primary already has a fakeid"})
				return
			}
			slog.Error("fakeid v2 verify: insert consumed", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "slot insert failed"})
			return
		}

		writeJSON(w, http.StatusOK, verifyCredResponse{OK: true})
	}
}

// --- GET /payment/fakeid/slot-status ---

type slotStatusResponse struct {
	State string `json:"state"` // "free" | "consumed"
}

// handleFakeIDSlotStatus lets the primary's mint-status UI ask the
// enclave whether the current primary can mint. The enclave derives the
// tag (never leaves its address space) and answers with one of three
// states. Primary_id is passed as a query param — it's only visible to
// the backend-to-enclave mTLS path, never to end-users.
func handleFakeIDSlotStatus(deps fakeidSlotDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		primaryID := r.URL.Query().Get("primary_id")
		if primaryID == "" {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "primary_id query param required"})
			return
		}
		primaryTag := payment.DerivePrimaryTag(deps.tagKey, primaryID)
		status, err := deps.slotStore.StatusForTag(r.Context(), primaryTag)
		if err != nil {
			slog.Error("fakeid v2 status: query", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "status query failed"})
			return
		}
		resp := slotStatusResponse{State: "free"}
		if status.State == storage.SlotConsumed {
			resp.State = "consumed"
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// --- POST /payment/fakeid/admin/seed-consumed ---

type seedConsumedRequest struct {
	PrimaryID  string `json:"primary_id"`
	ConsumedAt string `json:"consumed_at"` // RFC3339, mirrors users.fakeid_minted_at
}

// handleFakeIDSeedConsumed is the enclave side of the slot-state
// backfill. A worker calls this once per has_fakeid=TRUE user with
// their user_id + original minted_at. The enclave derives primary_tag
// and inserts the consumed row. Idempotent by primary-key so it's safe
// to re-run.
//
// Gated behind PAYMENT_API_KEY like every other mutation — the backfill
// worker sets the same Authorization header.
func handleFakeIDSeedConsumed(deps fakeidSlotDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req seedConsumedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
			return
		}
		if req.PrimaryID == "" {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "primary_id required"})
			return
		}
		consumedAt := time.Now().UTC()
		if req.ConsumedAt != "" {
			t, err := time.Parse(time.RFC3339, req.ConsumedAt)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid consumed_at"})
				return
			}
			consumedAt = t
		}
		primaryTag := payment.DerivePrimaryTag(deps.tagKey, req.PrimaryID)
		if err := deps.slotStore.SeedConsumed(r.Context(), primaryTag, consumedAt); err != nil {
			slog.Error("fakeid v2 seed-consumed", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "seed failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// registerFakeIDSlotRoutes mounts all four v2 endpoints behind the same
// API-key + rate-limiter discipline as the legacy fakeid-mint/ratchet
// paths. Called from registerRoutes during startup.
func registerFakeIDSlotRoutes(mux *http.ServeMux, deps fakeidSlotDeps, apiKey string, rl *ipRateLimiter) {
	mint := handleFakeIDMintV2(deps)
	verify := handleFakeIDVerifyCredential(deps)
	status := handleFakeIDSlotStatus(deps)
	seed := handleFakeIDSeedConsumed(deps)
	if apiKey != "" {
		mint = requireAPIKey(apiKey, mint)
		verify = requireAPIKey(apiKey, verify)
		status = requireAPIKey(apiKey, status)
		seed = requireAPIKey(apiKey, seed)
	}
	mux.HandleFunc("POST /payment/fakeid/mint", rateLimitMiddleware(rl, mint))
	mux.HandleFunc("POST /payment/fakeid/verify-credential", rateLimitMiddleware(rl, verify))
	mux.HandleFunc("GET /payment/fakeid/slot-status", rateLimitMiddleware(rl, status))
	mux.HandleFunc("POST /payment/fakeid/admin/seed-consumed", rateLimitMiddleware(rl, seed))
}

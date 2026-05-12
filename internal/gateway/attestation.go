package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/bmailag/bmail/internal/tee"
)

// AttestationResponse is the JSON structure returned by the attestation
// endpoint. The shape supports two binding models:
//
//   - Direct (smtp-inbound, smtp-outbound, backend, keystore): the quote's
//     REPORTDATA is sha256(tls_public_key). The TLS key is enclave-
//     generated + sealed (tee.GenerateServerTLSConfigUnique) so it's
//     stable across cert renewals. identity_public_key is empty.
//
//   - Indirect (gateway): the quote's REPORTDATA is
//     sha256(identity_public_key). Identity is an enclave-sealed Ed25519
//     keypair, stable across cert renewals AND code changes (identity
//     pubkey is sealed under MRENCLAVE; bumping MRENCLAVE rotates it,
//     which is fine — verifiers re-fetch /verify after deploys). The
//     gateway's TLS key is autocert-managed (CA-signed for browser trust)
//     and rotates outside our control. tls_public_key carries the
//     current cert SPKI for the browser to cross-check against the cert
//     it actually got.
//
// Verifiers (web /verify page) extract REPORTDATA bytes 32-64 from
// attestation_report and compare:
//   - if identity_public_key is present → must equal sha256(decoded)
//   - else → must equal sha256(decoded tls_public_key)
type AttestationResponse struct {
	AttestationReport string `json:"attestation_report"`
	// Bound into REPORTDATA when set (gateway's Plan-B path). Stable
	// across cert rotations; sealed under MRENCLAVE so the key rotates
	// when code does and verifiers can pin per-build.
	IdentityPublicKey string `json:"identity_public_key,omitempty"`
	// Current TLS public key the enclave presents to clients. For
	// non-gateway services this is also the REPORTDATA-bound key
	// (sha256 of this is in the quote). For the gateway, autocert
	// rotates this independently — not in REPORTDATA, included so
	// auditors can cross-check against the cert their browser/MX got.
	TLSPublicKey       string `json:"tls_public_key,omitempty"`
	EnclaveMeasurement string `json:"enclave_measurement"`
	Timestamp          string `json:"timestamp"`
}

// AttestationHandler — the direct-binding form. REPORTDATA = sha256(tlsPubKey).
// Used by smtp-inbound, smtp-outbound, backend, keystore.
func AttestationHandler(teeRuntime tee.TEERuntime, tlsPubKey []byte) http.HandlerFunc {
	return attestationHandlerCore(teeRuntime, tlsPubKey, tlsPubKey, nil)
}

// AttestationHandlerWithIdentity — the indirect-binding form for the
// gateway (Plan B). REPORTDATA = sha256(identityPubKey). The
// tlsPubKeyFn closure is evaluated per request so the response always
// carries the CURRENT autocert TLS pubkey (it rotates ~60-day with
// autocert renewals); pass a fixed []byte when you don't care or
// don't have a live source.
func AttestationHandlerWithIdentity(teeRuntime tee.TEERuntime, identityPubKey []byte, tlsPubKeyFn func() []byte) http.HandlerFunc {
	return attestationHandlerCoreFn(teeRuntime, identityPubKey, tlsPubKeyFn, identityPubKey)
}

func attestationHandlerCore(teeRuntime tee.TEERuntime, boundKey, tlsKey, identityKey []byte) http.HandlerFunc {
	return attestationHandlerCoreFn(teeRuntime, boundKey, func() []byte { return tlsKey }, identityKey)
}

func attestationHandlerCoreFn(teeRuntime tee.TEERuntime, boundKey []byte, tlsKeyFn func() []byte, identityKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// SGX reportData is fixed at 64 bytes. EGo rejects anything
		// larger with "reportData too large", so hash the pubkey first
		// and bind the 32-byte digest. EGo's GetRemoteReport panics on
		// nil userData, so always pass a non-nil buffer — sha256.Sum256
		// of nil gives the well-known empty digest, fine for paths
		// that legitimately don't have a bound key (legacy).
		h := sha256.Sum256(boundKey)
		userData := h[:]

		report, err := teeRuntime.Attest(userData)
		if err != nil {
			slog.Error("attestation failed",
				"path", r.URL.Path,
				"userdata_bytes", len(userData),
				"bound_bytes", len(boundKey),
				"error", err.Error())
			http.Error(w, "attestation failed", http.StatusInternalServerError)
			return
		}

		var tlsKey []byte
		if tlsKeyFn != nil {
			tlsKey = tlsKeyFn()
		}

		resp := AttestationResponse{
			AttestationReport:  base64.StdEncoding.EncodeToString(report),
			EnclaveMeasurement: teeRuntime.SelfID(),
			Timestamp:          time.Now().UTC().Format(time.RFC3339),
		}
		if len(tlsKey) > 0 {
			resp.TLSPublicKey = base64.StdEncoding.EncodeToString(tlsKey)
		}
		if len(identityKey) > 0 {
			resp.IdentityPublicKey = base64.StdEncoding.EncodeToString(identityKey)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

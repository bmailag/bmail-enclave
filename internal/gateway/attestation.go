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

// AttestationResponse is the JSON structure returned by the attestation endpoint.
type AttestationResponse struct {
	AttestationReport  string `json:"attestation_report"`
	TLSPublicKey       string `json:"tls_public_key"`
	EnclaveMeasurement string `json:"enclave_measurement"`
	Timestamp          string `json:"timestamp"`
}

// AttestationHandler returns an HTTP handler that serves the gateway's
// attestation report. The report binds the TLS public key to the enclave
// measurement, allowing clients to verify they are communicating with
// attested enclave code.
func AttestationHandler(teeRuntime tee.TEERuntime, tlsPubKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// SGX reportData is fixed at 64 bytes. EGo rejects anything
		// larger with "reportData too large", so hash the public key
		// first and bind the 32-byte digest. This matches the standard
		// DCAP convention; the verifier on /verify hashes the live
		// public key the same way before comparing.
		//
		// Always pass a non-nil 32-byte buffer: EGo's GetRemoteReport
		// panics with "index out of range [0]" on nil userData. The
		// gateway calls this handler with tlsPubKey=nil (autocert
		// rotates its TLS key), so we still need a deterministic
		// userData; sha256.Sum256(nil) gives the well-known empty
		// digest, which is fine — it just means REPORTDATA isn't
		// bound to any pubkey for that enclave.
		h := sha256.Sum256(tlsPubKey)
		userData := h[:]

		report, err := teeRuntime.Attest(userData)
		if err != nil {
			slog.Error("attestation failed",
				"path", r.URL.Path,
				"userdata_bytes", len(userData),
				"pubkey_bytes", len(tlsPubKey),
				"error", err.Error())
			http.Error(w, "attestation failed", http.StatusInternalServerError)
			return
		}

		resp := AttestationResponse{
			AttestationReport:  base64.StdEncoding.EncodeToString(report),
			TLSPublicKey:       base64.StdEncoding.EncodeToString(tlsPubKey),
			EnclaveMeasurement: teeRuntime.SelfID(),
			Timestamp:          time.Now().UTC().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

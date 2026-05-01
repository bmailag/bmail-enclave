package keystore

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/bmailag/bmail/internal/tee"
)

// Config configures the keystore server.
type Config struct {
	Runtime tee.TEERuntime

	// SealedDir is the directory holding sealed disk state. Layout:
	//   <SealedDir>/keys/<role-hash>.bin   — per-role sealed key
	//   <SealedDir>/allowlist.bin          — sealed per-role MRENCLAVE allowlist
	//   <SealedDir>/audit.bin              — sealed hash-chained audit log
	SealedDir string

	// Listen is the address to bind the HTTPS API. Internal-only;
	// don't expose to the public internet.
	Listen string

	// ServerTLS is the keystore's own attestation TLS config (server
	// cert with embedded SGX quote). Built by the caller via
	// tee.GenerateServerTLSConfig.
	ServerTLS *tls.Config

	// ExpectedClientMRSIGNER is the hex-encoded MRSIGNER every inbound
	// client cert must match. Empty disables MRSIGNER check (sim/dev
	// only — production MUST set this).
	ExpectedClientMRSIGNER string

	// OperatorPubKeyHex is the Ed25519 public key (64-char hex) for
	// break-glass operations. Empty disables break-glass — production
	// MUST set this.
	OperatorPubKeyHex string

	// Snapshotter, if set, receives a fresh snapshot of SealedDir
	// after every mutating operation (Provision, Delegate, Revoke)
	// plus a daily cron sweep + a startup snapshot. Failure to write
	// a snapshot is LOGGED, not fatal — durability is best-effort and
	// the operator's monitoring catches missed snapshots out-of-band.
	// Nil disables snapshotting (acceptable for sim/dev only).
	Snapshotter Snapshotter

	// Logger receives audit + diagnostic messages.
	Logger *slog.Logger
}

// Server is the keystore HTTP API.
type Server struct {
	cfg        Config
	keys       *keyStore
	allowlist  *allowlist
	audit      *auditLog
	breakGlass *breakGlass
	peers      *peerStore
	srv        *http.Server

	// Single global mutex for write-side operations (Provision,
	// Delegate, Revoke). Reads (Get) bypass — they only need the
	// allowlist read-lock + sealed-file read.
	writeMu sync.Mutex
}

// New constructs a Server but doesn't start it. Loads sealed state from
// disk (returns ErrCorruptedState if integrity checks fail).
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SealedDir == "" {
		return nil, errors.New("keystore: SealedDir is required")
	}
	if cfg.Listen == "" {
		return nil, errors.New("keystore: Listen is required")
	}
	if cfg.ServerTLS == nil {
		return nil, errors.New("keystore: ServerTLS is required")
	}

	keys, err := newKeyStore(cfg.Runtime, filepath.Join(cfg.SealedDir, "keys"))
	if err != nil {
		return nil, err
	}
	allow, err := loadAllowlist(cfg.Runtime, filepath.Join(cfg.SealedDir, "allowlist.bin"))
	if err != nil {
		return nil, err
	}
	audit, err := loadAuditLog(cfg.Runtime, filepath.Join(cfg.SealedDir, "audit.bin"))
	if err != nil {
		return nil, err
	}
	bg, err := newBreakGlass(cfg.OperatorPubKeyHex)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:        cfg,
		keys:       keys,
		allowlist:  allow,
		audit:      audit,
		breakGlass: bg,
		peers:      newPeerStore(),
	}

	// Configure mTLS: require client cert with our SGX-quote validator.
	tlsCfg := cfg.ServerTLS.Clone()
	tlsCfg.ClientAuth = tls.RequireAnyClientCert
	tlsCfg.VerifyPeerCertificate = makeVerifyPeerCertificate(s.peers, cfg.ExpectedClientMRSIGNER)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /keystore/get", s.handleGet)
	mux.HandleFunc("POST /keystore/delegate", s.handleDelegate)
	mux.HandleFunc("POST /keystore/provision", s.handleProvision)
	mux.HandleFunc("POST /keystore/revoke", s.handleRevoke)
	mux.HandleFunc("POST /keystore/list", s.handleList)

	s.srv = &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       makeConnContext(s.peers),
	}
	return s, nil
}

// Start blocks serving HTTPS until the listener errors or context is
// canceled.
func (s *Server) Start(ctx context.Context) error {
	_, err := s.audit.Append("startup", "", "keystore", "")
	if err != nil {
		return fmt.Errorf("write startup audit entry: %w", err)
	}
	s.cfg.Logger.Info("keystore listening", "addr", s.cfg.Listen, "audit_entries", s.audit.Len(), "roles", len(s.allowlist.Snapshot()))

	if s.cfg.Snapshotter != nil {
		go runDailySnapshotter(ctx, s.cfg.Snapshotter, s.cfg.SealedDir, s.cfg.Logger)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = s.audit.Append("shutdown", "", "keystore", "graceful")
		_ = s.srv.Shutdown(shutdownCtx)
	}()
	return s.srv.ListenAndServeTLS("", "") // certs are in TLSConfig
}

// snapshotAfterWrite fires a best-effort snapshot after a successful
// mutating operation. Failures log but don't fail the request — the
// keystore is still consistent on disk; durability degrades but the
// next mutation (or the daily cron) will catch up.
func (s *Server) snapshotAfterWrite(ctx context.Context, label string) {
	if s.cfg.Snapshotter == nil {
		return
	}
	if _, err := s.cfg.Snapshotter.Save(ctx, s.cfg.SealedDir, label); err != nil {
		s.cfg.Logger.Warn("keystore snapshot after write failed", "label", label, "err", err)
	}
}

// ── Handlers ───────────────────────────────────────────────────────────

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	peer := peerFromContext(r.Context())
	if peer == nil {
		writeErr(w, http.StatusUnauthorized, "no peer attestation")
		return
	}
	var req GetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := req.Role.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.allowlist.Allowed(req.Role, peer.MRENCLAVE) {
		callerMRE := encodeMRENCLAVEHex(peer.MRENCLAVE)
		_, _ = s.audit.Append("get-denied", req.Role, callerMRE, "")
		// Log the caller's MRENCLAVE + the role's currently-allowed
		// list so an operator debugging "why is consumer X getting
		// 403?" can compare them at a glance.
		allowed := s.allowlist.Get(req.Role)
		allowedHex := make([]string, len(allowed))
		for i, m := range allowed {
			allowedHex[i] = encodeMRENCLAVEHex(m)
		}
		s.cfg.Logger.Warn("keystore: get denied — caller MRENCLAVE not on role allowlist",
			"role", req.Role, "caller_mrenclave", callerMRE, "allowed", allowedHex)
		writeErr(w, http.StatusForbidden, ErrNotAllowed.Error())
		return
	}
	entry, err := s.keys.Get(req.Role)
	if errors.Is(err, ErrRoleNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		s.cfg.Logger.Error("keystore: get failed", "role", req.Role, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_, _ = s.audit.Append("get", req.Role, encodeMRENCLAVEHex(peer.MRENCLAVE), "")
	writeJSON(w, http.StatusOK, GetResponse{
		Key:       entry.Key,
		KeyType:   entry.KeyType,
		CreatedAt: entry.CreatedAt,
	})
}

func (s *Server) handleDelegate(w http.ResponseWriter, r *http.Request) {
	peer := peerFromContext(r.Context())
	if peer == nil {
		writeErr(w, http.StatusUnauthorized, "no peer attestation")
		return
	}
	var req DelegateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := req.Role.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Authorization: caller must be (a) on the role's allowlist
	// already (chained delegation), or (b) provide a valid break-glass
	// proof for action="delegate-add" with payload=new_mrenclave.
	authorizedBy := ""
	switch {
	case req.BreakGlass != nil:
		if err := s.breakGlass.Verify(*req.BreakGlass, "delegate-add", req.Role, req.NewMRENCLAVE[:]); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
		authorizedBy = "operator-break-glass:" + req.BreakGlass.OperatorPubKeyHex
	case s.allowlist.Allowed(req.Role, peer.MRENCLAVE):
		authorizedBy = encodeMRENCLAVEHex(peer.MRENCLAVE)
	default:
		writeErr(w, http.StatusForbidden, "delegation requires either current allowlist membership or break-glass proof")
		return
	}

	newAllow, err := s.allowlist.Add(req.Role, req.NewMRENCLAVE)
	if err != nil {
		s.cfg.Logger.Error("keystore: allowlist add failed", "role", req.Role, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := time.Now().Unix()
	_, _ = s.audit.Append("delegate", req.Role, authorizedBy, "added "+encodeMRENCLAVEHex(req.NewMRENCLAVE))
	s.snapshotAfterWrite(r.Context(), "post-delegate")
	writeJSON(w, http.StatusOK, DelegateResponse{
		Role:             req.Role,
		AllowedMRENCLAVE: newAllow,
		DelegatedAt:      now,
	})
}

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := req.Role.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Key) == 0 {
		writeErr(w, http.StatusBadRequest, "key is required")
		return
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Provision is break-glass-only by design — only the offline
	// operator can install initial keys. Once provisioned, future key
	// rotation will use a separate Rotate API (TBD, ADR-006 §migration
	// step 4 once flow is fleshed out).
	if err := s.breakGlass.Verify(req.BreakGlass, "provision", req.Role, req.Key); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}

	if err := s.keys.Provision(req.Role, req.Key, req.KeyType); err != nil {
		if errors.Is(err, ErrAlreadyProvisioned) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		s.cfg.Logger.Error("keystore: provision failed", "role", req.Role, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := time.Now().Unix()
	actor := "operator-break-glass:" + req.BreakGlass.OperatorPubKeyHex
	_, _ = s.audit.Append("provision", req.Role, actor, "type="+req.KeyType)
	s.snapshotAfterWrite(r.Context(), "post-provision")
	writeJSON(w, http.StatusOK, ProvisionResponse{Role: req.Role, ProvisionedAt: now})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := req.Role.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Revoke is break-glass-only — consumers can't self-revoke (footgun)
	// and can't revoke peers (privilege-escalation risk).
	if err := s.breakGlass.Verify(req.BreakGlass, "revoke", req.Role, req.OldMRENCLAVE[:]); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}

	if err := s.allowlist.Remove(req.Role, req.OldMRENCLAVE); err != nil {
		s.cfg.Logger.Error("keystore: revoke failed", "role", req.Role, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	actor := "operator-break-glass:" + req.BreakGlass.OperatorPubKeyHex
	_, _ = s.audit.Append("revoke", req.Role, actor, "removed "+encodeMRENCLAVEHex(req.OldMRENCLAVE))
	s.snapshotAfterWrite(r.Context(), "post-revoke")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	var req ListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := s.breakGlass.Verify(req.BreakGlass, "list", "", nil); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}

	roles, err := s.keys.ListRoles()
	if err != nil {
		s.cfg.Logger.Error("keystore: list roles failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	allowSnap := s.allowlist.Snapshot()
	out := ListResponse{Roles: make([]RoleInfo, 0, len(roles))}
	for _, r := range roles {
		info := RoleInfo{Role: r, AllowedMRENCLAVE: allowSnap[r]}
		entry, err := s.keys.Get(r)
		if err == nil {
			info.KeyType = entry.KeyType
			info.CreatedAt = entry.CreatedAt
		}
		out.Roles = append(out.Roles, info)
	}
	if req.AuditTailSize > 0 {
		out.AuditLog = s.audit.Tail(req.AuditTailSize)
	}
	writeJSON(w, http.StatusOK, out)
}

// ── small helpers ───────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}


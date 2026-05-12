// Package main is the bmail Keystore enclave entry point.
//
// The keystore is a small SGX enclave that holds long-lived secrets on
// behalf of consumer enclaves (gateway, smtp-inbound, smtp-outbound,
// payment). Per ADR-006, the keystore is designed to never change: its
// MRENCLAVE is the platform's root of trust for key custody. Consumer
// enclaves can update freely; key material lives here.
//
// Configuration via env vars:
//
//	KEYSTORE_LISTEN                — RPC mTLS bind address, e.g. ":8095" (default :8094)
//	KEYSTORE_HEALTH_LISTEN         — plain-HTTP bind for /attestation, e.g. ":8096" (default :8096)
//	KEYSTORE_HOSTNAME              — TLS cert CN, e.g. "keystore.internal"
//	KEYSTORE_SEALED_DIR            — sealed-state directory (default /opt/bmail/keystore-sealed)
//	KEYSTORE_TLS_KEY_PATH          — sealed-on-disk path for keystore's own TLS key
//	KEYSTORE_EXPECTED_CLIENT_MRSIGNER — hex MRSIGNER required on inbound mTLS
//	KEYSTORE_BREAK_GLASS_PUBKEY_HEX  — hex Ed25519 pubkey for operator break-glass
//
// Snapshot pipeline (ADR-007 durability floor) — fires after every
// Provision/Delegate/Revoke and once daily. If neither S3 nor local
// is configured, snapshots are disabled (sim/dev only).
//
//	KEYSTORE_SNAPSHOT_S3_ENDPOINT  — S3-compat host (e.g. R2 endpoint)
//	KEYSTORE_SNAPSHOT_S3_BUCKET    — bucket name
//	KEYSTORE_SNAPSHOT_S3_PREFIX    — key prefix (default "keystore-snapshots/")
//	KEYSTORE_SNAPSHOT_S3_ACCESS_KEY / KEYSTORE_SNAPSHOT_S3_SECRET_KEY — creds
//	KEYSTORE_SNAPSHOT_S3_INSECURE  — set to "1" to disable TLS (dev only)
//	KEYSTORE_SNAPSHOT_LOCAL_DIR    — fallback / additional local backup dir
//
// In sim/dev mode, the MRSIGNER + break-glass env vars MAY be empty —
// auth degrades to "any client cert + no break-glass". Production MUST
// set both; main() errors out if VP_ENV=production without them.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bmailag/bmail/internal/gateway"
	"github.com/bmailag/bmail/internal/keystore"
	"github.com/bmailag/bmail/internal/tee"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	runtime := tee.NewRuntime()
	slog.Info("TEE runtime initialized", "enclave_id", runtime.SelfID())

	listen := envOr("KEYSTORE_LISTEN", ":8094")
	healthListen := envOr("KEYSTORE_HEALTH_LISTEN", ":8096")
	hostname := envOr("KEYSTORE_HOSTNAME", "keystore.internal")
	sealedDir := envOr("KEYSTORE_SEALED_DIR", "/opt/bmail/keystore-sealed")
	tlsKeyPath := envOr("KEYSTORE_TLS_KEY_PATH", "/opt/bmail/sealed/sealed_keystore_tls_key.bin")
	expectedClientMRSIGNER := os.Getenv("KEYSTORE_EXPECTED_CLIENT_MRSIGNER")
	operatorPubHex := os.Getenv("KEYSTORE_BREAK_GLASS_PUBKEY_HEX")

	// Production safety: both auth gates must be configured.
	if os.Getenv("VP_ENV") == "production" {
		if expectedClientMRSIGNER == "" {
			return fmt.Errorf("KEYSTORE_EXPECTED_CLIENT_MRSIGNER must be set in production")
		}
		if operatorPubHex == "" {
			return fmt.Errorf("KEYSTORE_BREAK_GLASS_PUBKEY_HEX must be set in production")
		}
	}

	tlsCfg, _, err := tee.GenerateServerTLSConfig(runtime, hostname, tlsKeyPath)
	if err != nil {
		return fmt.Errorf("generate keystore TLS config: %w", err)
	}

	snapper, err := buildSnapshotter()
	if err != nil {
		return fmt.Errorf("build snapshotter: %w", err)
	}
	if snapper == nil && os.Getenv("VP_ENV") == "production" {
		return fmt.Errorf("KEYSTORE_SNAPSHOT_S3_* or KEYSTORE_SNAPSHOT_LOCAL_DIR must be set in production (ADR-007 durability floor)")
	}

	srv, err := keystore.New(keystore.Config{
		Runtime:                runtime,
		SealedDir:              sealedDir,
		Listen:                 listen,
		ServerTLS:              tlsCfg,
		ExpectedClientMRSIGNER: expectedClientMRSIGNER,
		OperatorPubKeyHex:      operatorPubHex,
		Snapshotter:            snapper,
		Logger:                 slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("init keystore: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Spin up a separate plain-HTTP listener for /attestation so external
	// observers (the /verify page via gateway's sgx-quotes proxy) can
	// fetch the keystore's SGX quote without needing a client cert.
	// The quote is public material — signed by Intel — so plaintext is
	// fine. The mTLS listener stays for the actual key-fetching RPCs.
	healthMux := http.NewServeMux()
	// F-02b: keystore TLS-bind is DEFERRED until a planned MRENCLAVE
	// migration. Reason: the keystore seals all its state (audit log,
	// allowlist, key blobs) under MRENCLAVE-Unique via SealUnique /
	// UnsealUnique. Any source change here drifts MRENCLAVE, which
	// means the new binary can no longer unseal the data the old one
	// wrote — restart and the keystore is a brick (DKIM keys gone,
	// audit chain broken, allowlist empty). Until we ship a key
	// export/import migration tool, leave attestation un-bound (nil)
	// so the source MRENCLAVE matches what's already running and
	// holding the sealed data. The /verify page's bind row will read
	// "no signed public key" for keystore, which is correct.
	healthMux.HandleFunc("GET /attestation", gateway.AttestationHandler(runtime, nil))
	healthSrv := &http.Server{
		Addr:              healthListen,
		Handler:           healthMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		slog.Info("keystore health/attestation listening", "addr", healthListen)
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("keystore health server", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = healthSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("keystore starting", "listen", listen, "hostname", hostname, "sealed_dir", sealedDir)
	return srv.Start(ctx)
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// buildSnapshotter inspects KEYSTORE_SNAPSHOT_* env vars and constructs
// the appropriate Snapshotter. Returns nil if neither S3 nor local
// backup is configured (sim/dev). Returns an error if the
// configuration is partially specified or a client init fails.
//
// Precedence:
//  1. S3 endpoint configured → S3Snapshotter (production path).
//  2. Otherwise, local dir configured → LocalFSSnapshotter.
//  3. Otherwise, nil (no snapshots — main() rejects this in production).
func buildSnapshotter() (keystore.Snapshotter, error) {
	endpoint := os.Getenv("KEYSTORE_SNAPSHOT_S3_ENDPOINT")
	bucket := os.Getenv("KEYSTORE_SNAPSHOT_S3_BUCKET")
	if endpoint != "" || bucket != "" {
		if endpoint == "" || bucket == "" {
			return nil, fmt.Errorf("KEYSTORE_SNAPSHOT_S3_ENDPOINT and KEYSTORE_SNAPSHOT_S3_BUCKET must both be set")
		}
		return keystore.NewS3Snapshotter(
			endpoint,
			os.Getenv("KEYSTORE_SNAPSHOT_S3_ACCESS_KEY"),
			os.Getenv("KEYSTORE_SNAPSHOT_S3_SECRET_KEY"),
			bucket,
			envOr("KEYSTORE_SNAPSHOT_S3_PREFIX", "keystore-snapshots/"),
			os.Getenv("KEYSTORE_SNAPSHOT_S3_INSECURE") != "1",
			slog.Default(),
		)
	}
	if dir := os.Getenv("KEYSTORE_SNAPSHOT_LOCAL_DIR"); dir != "" {
		return &keystore.LocalFSSnapshotter{Dir: dir, Logger: slog.Default()}, nil
	}
	return nil, nil
}

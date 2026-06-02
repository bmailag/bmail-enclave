package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"net/http"

	"github.com/redis/go-redis/v9"

	"github.com/bmailag/bmail/internal/config"
	"github.com/bmailag/bmail/internal/crypto"
	"github.com/bmailag/bmail/internal/gateway"
	"github.com/bmailag/bmail/internal/peer"
	"github.com/bmailag/bmail/internal/queue"
	"github.com/bmailag/bmail/internal/smtp"
	"github.com/bmailag/bmail/internal/spam"
	"github.com/bmailag/bmail/internal/storage"
	"github.com/bmailag/bmail/internal/tee"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	// CSR generation mode: output a PEM CSR to stdout and exit.
	if os.Getenv("GENERATE_CSR") == "true" {
		if err := generateCSR(); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Pre-stage key generation mode for the rotation pipeline. CI runs
	// this on the target host BEFORE deploying a new MRENCLAVE binary;
	// it generates a fresh sealed TLS key at OUTPUT_SEAL_PATH and prints
	// the SPKI hash so CI can pre-publish a TLSA `3 1 1 <hash>` record
	// alongside the existing one. After DNS propagation, the staged
	// sealed file is moved into place and the new binary takes over.
	if os.Getenv("GENERATE_KEY") == "true" {
		if err := generateNewKey(); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func generateCSR() error {
	runtime := tee.NewRuntime()

	hostname := os.Getenv("SMTP_HOSTNAME")
	if hostname == "" {
		hostname = "smtp.bmail.ag"
	}

	sealPath := os.Getenv("SMTP_TLS_SEAL_PATH")
	if sealPath == "" {
		sealPath = "/opt/bmail/sealed/sealed_smtp_tls_key.bin"
	}

	csrPEM, err := tee.GenerateCSR(runtime, hostname, sealPath)
	if err != nil {
		return fmt.Errorf("generate CSR: %v", err)
	}

	_, err = os.Stdout.Write(csrPEM)
	return err
}

// generateNewKey is the GENERATE_KEY=true entry point. Generates a fresh
// TLS keypair, seals it under the enclave identity, atomically writes
// the sealed bytes to OUTPUT_SEAL_PATH (default: <SMTP_TLS_SEAL_PATH>.next),
// and prints the SPKI SHA-256 hash to stdout in `key=value` lines for
// easy CI parsing.
func generateNewKey() error {
	runtime := tee.NewRuntime()

	defaultSeal := os.Getenv("SMTP_TLS_SEAL_PATH")
	if defaultSeal == "" {
		defaultSeal = "/opt/bmail/sealed/sealed_smtp_tls_key.bin"
	}
	outPath := os.Getenv("OUTPUT_SEAL_PATH")
	if outPath == "" {
		outPath = defaultSeal + ".next"
	}

	spkiHash, err := tee.GenerateAndSealNewTLSKey(runtime, outPath)
	if err != nil {
		return fmt.Errorf("generate new key: %v", err)
	}

	fmt.Printf("output_seal_path=%s\n", outPath)
	fmt.Printf("spki_sha256=%x\n", spkiHash[:])
	fmt.Printf("mrenclave=%s\n", runtime.SelfID())
	return nil
}

func run() error {
	ctx := context.Background()

	// --- TEE Runtime ---
	// SimRuntime in dev, EGoRuntime with -tags ego.
	runtime := tee.NewRuntime()
	slog.Info("TEE runtime initialized", "enclave_id", runtime.SelfID())

	// --- TLS config via TEE (sealed key, in-memory cert) ---
	smtpHostname := os.Getenv("SMTP_HOSTNAME")
	if smtpHostname == "" {
		smtpHostname = "mx.bmail.ag"
	}
	// MRENCLAVE-bound seal: a malicious enclave with the same MRSIGNER
	// can't unseal this key. peer.Manager.daneUpdate publishes the new
	// SPKI to DNS on every fresh-key boot, so MRENCLAVE flips just
	// trigger a brief delivery-deferral window during the TLSA TTL.
	smtpTLSConfig, tlsPub, err := tee.GenerateServerTLSConfigUnique(runtime, smtpHostname, "/opt/bmail/sealed/sealed_smtp_tls_key.bin")
	if err != nil {
		return fmt.Errorf("generate SMTP TLS config: %v", err)
	}
	// TLS 1.3 minimum: eliminates CBC mode ciphers and ensures forward secrecy.
	// Senders unable to negotiate TLS 1.3 fall back to plaintext delivery, which
	// the enclave encrypts immediately. Override with SMTP_MIN_TLS_VERSION=1.2.
	smtpTLSConfig.MinVersion = tls.VersionTLS13
	if os.Getenv("SMTP_MIN_TLS_VERSION") == "1.2" {
		smtpTLSConfig.MinVersion = tls.VersionTLS12
		// Restrict TLS 1.2 to AEAD-only cipher suites.
		// CBC mode suites are excluded to prevent padding oracle attacks (POODLE, Lucky13).
		smtpTLSConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
		slog.Warn("SMTP using TLS 1.2 minimum with AEAD-only cipher suites (override via SMTP_MIN_TLS_VERSION)")
	}
	slog.Info("SMTP TLS ready", "hostname", smtpHostname, "pubkey_bytes", len(tlsPub))

	// --- Receipt signing key via TEE (seal/unseal for persistence) ---
	signingKey, err := loadOrSealSigningKey(runtime)
	if err != nil {
		return err
	}
	signingPub, ok := signingKey.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("signing key public key is not ed25519.PublicKey")
	}
	slog.Info("receipt signing key ready", "pub_prefix", fmt.Sprintf("%x", signingPub[:8]))

	// --- Initialize sender hash secret ---
	// Derive a stable secret from TEE sealing so sender hashes in enclave
	// receipts can't be brute-forced without access to the enclave.
	senderLabel := []byte("bmail-sender-hash-secret-v1")
	sealedSender, err := runtime.Seal(senderLabel)
	if err != nil {
		return fmt.Errorf("derive sender secret: %v", err)
	}
	crypto.InitSenderSecret(sealedSender[:32])

	// --- Database connection ---
	dbURL := config.Require("DATABASE_URL", "")

	db, err := storage.NewDB(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect to database: %v", err)
	}
	defer db.Close()

	authStore := storage.NewAuthStore(db)
	billingStore := storage.NewBillingStore(db)
	driveStore := storage.NewDriveStore(db)
	adminStore := storage.NewAdminStore(db)
	defaultDomainStore := storage.NewDefaultDomainStore(db)

	// Blind index secret for encrypted-at-rest sender addresses on
	// inbound messages. Loaded from BLIND_INDEX_SECRET (32 bytes hex).
	// Generates an ephemeral key in dev — but warn loudly because
	// existing rows would be unrecoverable across restarts.
	if biHex := config.RequireInProduction("BLIND_INDEX_SECRET"); biHex != "" {
		biKey, err := hex.DecodeString(biHex)
		if err != nil {
			return fmt.Errorf("invalid BLIND_INDEX_SECRET hex: %v", err)
		}
		if len(biKey) != 32 {
			return fmt.Errorf("BLIND_INDEX_SECRET must be 32 bytes, got %d", len(biKey))
		}
		storage.InitBlindIndexSecret(biKey)
	} else {
		biKey := make([]byte, 32)
		if _, err := rand.Read(biKey); err != nil {
			return fmt.Errorf("generate ephemeral blind index secret: %v", err)
		}
		storage.InitBlindIndexSecret(biKey)
		slog.Warn("BLIND_INDEX_SECRET not set; using ephemeral key (encrypted addresses written here will be unreachable across restarts)")
	}

	// --- NATS connection ---
	natsURL := config.Require("NATS_URL", "")
	// Load shared HMAC key for cross-instance message verification.
	var natsHMACKey []byte
	if natsKeyHex := config.RequireInProduction("NATS_HMAC_KEY"); natsKeyHex != "" {
		natsHMACKey, err = hex.DecodeString(natsKeyHex)
		if err != nil {
			return fmt.Errorf("invalid NATS_HMAC_KEY hex: %v", err)
		}
		if len(natsHMACKey) != 32 {
			return fmt.Errorf("NATS_HMAC_KEY must be 32 bytes (64 hex chars), got %d", len(natsHMACKey))
		}
	} else {
		slog.Warn("NATS_HMAC_KEY not set; using random key (messages won't be verifiable across instances)")
	}
	queueClient, err := queue.NewQueueClient(natsURL, natsHMACKey)
	if err != nil {
		return fmt.Errorf("connect to NATS: %v", err)
	}
	defer queueClient.Close()

	// Watchdog: heartbeat over core NATS every 30s; three consecutive
	// missed round-trips triggers exit(1) and systemd restart. Catches
	// "process is up but NATS pipeline is broken" cases.
	if werr := queueClient.StartWatchdog(ctx, queue.WatchdogConfig{
		Label: "smtp-inbound",
		OnFail: func(reason string) {
			slog.Error("watchdog tripped — exiting for restart", "reason", reason)
			os.Exit(1)
		},
	}); werr != nil {
		slog.Warn("watchdog setup failed; continuing without health-loop", "error", werr)
	}

	// --- Spam filter (runs inside the enclave in production) ---
	spamFilter := spam.NewSpamFilter()
	slog.Info("spam filter initialized", "mode", "enclave-native")

	// --- Create pipeline with spam filter ---
	enclaveID := runtime.SelfID()
	pipeline := smtp.NewPipeline(authStore, queueClient, signingKey, enclaveID)
	pipeline.SetSpamFilter(spamFilter)

	// Mark pipeline as TLS-active for receipt generation.
	pipeline.SetTLSActive(true)

	// Wire the per-recipient post-receive stores so the pipeline runs
	// block check, auto-add, rule eval, and auto-reply inside SGX.
	// Without these the pipeline silently skips that work.
	pipeline.SetPostReceiveStores(
		storage.NewBlockStore(db),
		storage.NewContactsStore(db),
		storage.NewRuleStore(db),
		storage.NewMailStore(db),
		storage.NewFolderStore(db),
		storage.NewLabelStore(db),
		storage.NewAutoReplyStore(db),
		storage.NewAutoReplyDedupStore(db),
	)

	// Wire calendar store so inbound ICS METHOD:REPLY and METHOD:CANCEL
	// attachments automatically update the recipient's calendar events.
	pipeline.SetCalendarStore(storage.NewCalendarStore(db))

	// E2E private group delivery (ADR-012): the pipeline encrypts to the group
	// key + fans to members; the receiver accepts group addresses at RCPT.
	groupStore := storage.NewGroupStore(db)
	pipeline.SetGroupStore(groupStore)

	// Optional Redis for publishing calendar_event_updated SSE events
	// when an inbound ICS REPLY changes an attendee's status — lets
	// every attendee's calendar refresh in real time. Best-effort:
	// pipeline no-ops if Redis isn't reachable.
	if redisAddr := os.Getenv("REDIS_ADDR"); redisAddr != "" {
		rdb := redis.NewClient(&redis.Options{
			Addr:     redisAddr,
			Password: os.Getenv("REDIS_PASSWORD"),
		})
		pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := rdb.Ping(pingCtx).Err(); err != nil {
			slog.Warn("redis ping failed; calendar SSE notifications disabled", "error", err)
			_ = rdb.Close()
		} else {
			pipeline.SetRedis(rdb)
			defer rdb.Close()
		}
		cancel()
	}

	// --- Create and start SMTP receiver ---
	receiver := smtp.NewSMTPReceiver(authStore, pipeline, smtpTLSConfig,
		smtp.WithBillingStore(billingStore),
		smtp.WithDriveStore(driveStore),
		smtp.WithAdminStore(adminStore),
		smtp.WithDefaultDomainStore(defaultDomainStore),
		smtp.WithGroupStore(groupStore),
	)

	addr := os.Getenv("SMTP_ADDR")
	if addr == "" {
		addr = ":2525"
	}

	// Peer discovery and certificate synchronization.
	peerPort := os.Getenv("PEER_PORT")
	if peerPort == "" {
		peerPort = "8092" // same as health port
	}
	// PEER_AUTH_SECRET is a hex-encoded shared secret used to HMAC-sign
	// /peer/key requests. Every sibling enclave must have the same value
	// (set via systemd EnvironmentFile on each host). Empty disables the
	// key-sharing endpoint — fail-closed is fine, we'd rather miss a cert
	// sync than leak a TLS private key.
	var peerAuthSecret []byte
	if hexSecret := os.Getenv("PEER_AUTH_SECRET"); hexSecret != "" {
		if decoded, err := hex.DecodeString(hexSecret); err == nil && len(decoded) >= 32 {
			peerAuthSecret = decoded
		} else {
			slog.Warn("PEER_AUTH_SECRET invalid or too short (need >=32 bytes hex); peer key sharing disabled")
		}
	}
	peerMgr := peer.NewManager(peer.Config{
		Hostname:      smtpHostname,
		PeerPort:      peerPort,
		TEERuntime:    runtime,
		TLSKeyPath:    "/opt/bmail/sealed/sealed_smtp_tls_key.bin",
		CertDir:       "/opt/bmail/certs",
		DANEUpdateURL: os.Getenv("DANE_UPDATE_URL"),
		AuthSecret:    peerAuthSecret,
	})
	// Extract raw key bytes from the TLS config for peer sharing.
	var tlsKeyBytes []byte
	if len(smtpTLSConfig.Certificates) > 0 {
		tlsKeyBytes, _ = tee.LoadOrSealBytes(runtime, "/opt/bmail/sealed/sealed_smtp_tls_key.bin", nil)
	}
	if err := peerMgr.Start(ctx, &smtpTLSConfig.Certificates[0], tlsKeyBytes, tlsPub); err != nil {
		slog.Warn("peer manager start failed", "error", err)
	}
	// Update TLS config if peer sync provided a better cert.
	if peerCert := peerMgr.TLSCert(); peerCert != nil {
		smtpTLSConfig.Certificates = []tls.Certificate{*peerCert}
	}

	// Health check HTTP server for Kubernetes probes.
	healthPort := os.Getenv("HEALTH_PORT")
	if healthPort == "" {
		healthPort = "8092"
	}
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", gateway.HealthHandler())
	rc := gateway.NewReadinessChecker()
	rc.Add("postgres", func(hctx context.Context) error { return db.Pool.Ping(hctx) })
	rc.Add("queue", func(hctx context.Context) error {
		if !queueClient.IsConnected() {
			return fmt.Errorf("nats disconnected")
		}
		return nil
	})
	healthMux.HandleFunc("GET /readyz", rc.Handler())
	// Attestation: returns the SGX quote with REPORTDATA bound to the
	// SMTP TLS public key. The /verify page on bmail.ag fetches this
	// (proxied by the gateway as /.well-known/sgx-quotes/smtp-inbound)
	// and cross-checks it against the published TLSA record at
	// _25._tcp.smtp.bmail.ag plus the checked-in expected MRENCLAVE.
	healthMux.HandleFunc("GET /attestation", gateway.AttestationHandler(runtime, tlsPub))
	peerMgr.RegisterHandlers(healthMux)
	healthSrv := &http.Server{
		Addr:              ":" + healthPort,
		Handler:           healthMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("health server error", "error", err)
		}
	}()
	slog.Info("health server listening", "addr", ":"+healthPort)

	// Handle shutdown signals with timeout.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down SMTP server", "signal", sig)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Shut down health server so load balancers stop routing to us.
		if err := healthSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("health server shutdown failed", "error", err)
		}

		if err := receiver.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful SMTP shutdown failed, forcing close", "error", err)
			receiver.Close()
		} else {
			slog.Info("SMTP server closed gracefully")
		}
	}()

	slog.Info("smtp-inbound starting", "addr", addr)
	if err := receiver.ListenAndServe(addr); err != nil {
		return fmt.Errorf("SMTP server error: %v", err)
	}

	return nil
}

// loadOrSealSigningKey loads a persistent Ed25519 signing key, using the
// shared TEE seal/unseal helper. Falls back to hex-encoded env override.
func loadOrSealSigningKey(runtime tee.TEERuntime) (ed25519.PrivateKey, error) {
	// Check for hex-encoded key in environment (legacy/override).
	if keyHex := os.Getenv("SMTP_SIGNING_KEY"); keyHex != "" {
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("decode SMTP_SIGNING_KEY: %v", err)
		}
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("SMTP_SIGNING_KEY must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
		}
		return ed25519.PrivateKey(key), nil
	}

	sealedPath := os.Getenv("SEALED_SIGNING_KEY_PATH")
	if sealedPath == "" {
		sealedPath = "/opt/bmail/sealed/sealed_signing_key.bin"
	}

	keyBytes, err := tee.LoadOrSealBytes(runtime, sealedPath, func() ([]byte, error) {
		_, priv, err := runtime.GenerateKey("ed25519")
		return priv, err
	})
	if err != nil {
		return nil, fmt.Errorf("load/generate signing key: %v", err)
	}

	return ed25519.PrivateKey(keyBytes), nil
}

// Package queue provides authenticated and encrypted NATS JetStream messaging.
//
// All messages are HMAC-authenticated and XChaCha20-Poly1305 encrypted using a
// shared 32-byte key. In multi-instance deployments, this key MUST be shared
// across all publishers and subscribers on the same NATS subjects. Recommended
// distribution methods:
//   - Production (SGX): derive from a TEE-sealed master secret via HKDF
//   - Kubernetes: distribute via Sealed Secrets or HashiCorp Vault
//   - Single-process: auto-generated random key (default when nil is passed)
//
// The HMAC key is further derived via HKDF-SHA256 to produce a separate
// encryption key, ensuring cryptographic key separation.
package queue

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Stream definitions.
var streamConfigs = []jetstream.StreamConfig{
	{
		Name:     "MAIL_INBOUND",
		Subjects: []string{"mail.inbound.>"},
	},
	{
		Name:     "MAIL_OUTBOUND",
		Subjects: []string{"mail.outbound.>"},
	},
}

// QueueClient wraps a NATS JetStream connection for mail queue operations.
// Messages are encrypted with XChaCha20-Poly1305 and authenticated with
// HMAC-SHA256 to prevent both eavesdropping and injection (audit fix F-6).
type QueueClient struct {
	conn    *nats.Conn
	js      jetstream.JetStream
	hmacKey []byte // 32-byte HMAC key for message authentication
	encKey  []byte // 32-byte XChaCha20-Poly1305 key derived from hmacKey
}

// NewQueueClient connects to NATS and ensures the required streams exist.
// hmacKey must be exactly 32 bytes. If nil, a random key is generated
// (suitable for single-process deployments; multi-process must share a key).
// IsConnected returns true if the NATS connection is active.
func (q *QueueClient) IsConnected() bool {
	return q.conn.IsConnected()
}

func NewQueueClient(url string, hmacKey ...[]byte) (*QueueClient, error) {
	var nc *nats.Conn
	var err error
	const maxRetries = 5
	for attempt := 0; attempt <= maxRetries; attempt++ {
		nc, err = nats.Connect(url,
			nats.RetryOnFailedConnect(true),
			nats.MaxReconnects(-1),
			nats.ReconnectWait(2*time.Second),
		)
		if err == nil {
			break
		}
		if attempt < maxRetries {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			slog.Warn("NATS connect failed, retrying", "attempt", attempt+1, "backoff", backoff, "error", err)
			time.Sleep(backoff)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("connect to nats after %d attempts: %w", maxRetries+1, err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("create jetstream context: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, cfg := range streamConfigs {
		_, err := js.CreateOrUpdateStream(ctx, cfg)
		if err != nil {
			nc.Close()
			return nil, fmt.Errorf("ensure stream %s: %w", cfg.Name, err)
		}
	}

	var key []byte
	if len(hmacKey) > 0 && len(hmacKey[0]) == 32 {
		key = hmacKey[0]
	} else {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			nc.Close()
			return nil, fmt.Errorf("generate HMAC key: %w", err)
		}
	}

	// Derive a separate encryption key from the HMAC key using HKDF
	// to maintain key separation between authentication and encryption.
	encKey, err := deriveQueueEncKey(key)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}

	return &QueueClient{conn: nc, js: js, hmacKey: key, encKey: encKey}, nil
}

// deriveQueueEncKey derives a 32-byte encryption key from the HMAC key
// using HKDF-SHA256 with domain separation.
// F-7 fix: Uses a fixed application-specific salt instead of nil. Per RFC 5869 §2.2,
// nil salt defaults to a zero-filled string which is fine for high-entropy IKM,
// but an explicit salt provides additional defense-in-depth.
var queueHKDFSalt = []byte("bmail-queue-hkdf-salt-v1")

func deriveQueueEncKey(hmacKey []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, hmacKey, queueHKDFSalt, []byte("bmail-queue-encryption-v1"))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}
	return key, nil
}

// Publish sends data to the given subject via JetStream.
// The message is prefixed with a 32-byte HMAC-SHA256 tag.
func (q *QueueClient) Publish(ctx context.Context, subject string, data []byte) error {
	signed, err := q.signMessage(data, subject)
	if err != nil {
		return fmt.Errorf("sign message: %w", err)
	}
	_, err = q.js.Publish(ctx, subject, signed)
	if err != nil {
		return fmt.Errorf("publish to %s: %w", subject, err)
	}
	return nil
}

const hmacTagSize = 32

const timestampSize = 8

// maxMessageAge is the maximum age of a message before it is rejected.
// F-16: The 60-second window is acceptable because:
//   - NATS JetStream provides exactly-once delivery via consumer deduplication,
//     so replayed messages are at most reprocessed (idempotent handlers).
//   - AEAD encryption prevents message modification within the window.
//   - HMAC freshness check prevents acceptance of messages from outside the window.
//   - Reducing below 60s risks false rejections due to clock skew in distributed
//     deployments. NTP typically maintains <10ms accuracy, but container/VM
//     clock drift can reach seconds during high load.
const maxMessageAge = 60 * time.Second

// signMessage encrypts data with XChaCha20-Poly1305, then prepends
// HMAC-SHA256(key, timestamp || ciphertext) for freshness verification.
// Wire format: [32-byte HMAC tag] [8-byte unix timestamp] [24-byte nonce] [ciphertext+tag]
//
// Encryption prevents metadata leakage on the NATS bus (audit fix F-6).
// HMAC over the ciphertext provides timestamp-based replay protection.
// The NATS subject is bound as AEAD additional authenticated data (AAD)
// to prevent cross-subject message redirection (audit fix F-A2).
func (q *QueueClient) signMessage(data []byte, subject string) ([]byte, error) {
	// Encrypt the payload with subject as AAD to prevent cross-subject redirection.
	aead, err := chacha20poly1305.NewX(q.encKey)
	if err != nil {
		return nil, fmt.Errorf("create XChaCha20-Poly1305: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, data, []byte(subject))

	// Build the encrypted payload: nonce || ciphertext
	encPayload := make([]byte, len(nonce)+len(ciphertext))
	copy(encPayload, nonce)
	copy(encPayload[len(nonce):], ciphertext)

	// HMAC over timestamp and encrypted payload for freshness.
	now := time.Now().Unix()
	tsBuf := make([]byte, timestampSize)
	binary.BigEndian.PutUint64(tsBuf, uint64(now))

	mac := hmac.New(sha256.New, q.hmacKey)
	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(len(encPayload)))
	mac.Write(tsBuf)
	mac.Write(lenBuf)
	mac.Write(encPayload)
	tag := mac.Sum(nil)

	out := make([]byte, hmacTagSize+timestampSize+len(encPayload))
	copy(out, tag)
	copy(out[hmacTagSize:], tsBuf)
	copy(out[hmacTagSize+timestampSize:], encPayload)
	return out, nil
}

// verifyMessage checks HMAC tag and timestamp freshness, then decrypts
// the payload. The subject must match what was passed to signMessage;
// mismatched subjects cause AEAD authentication failure (F-A2 fix).
func (q *QueueClient) verifyMessage(signed []byte, subject string) ([]byte, error) {
	if len(signed) < hmacTagSize+timestampSize+chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("message too short for verification")
	}
	tag := signed[:hmacTagSize]
	tsBuf := signed[hmacTagSize : hmacTagSize+timestampSize]
	encPayload := signed[hmacTagSize+timestampSize:]

	// Verify HMAC.
	mac := hmac.New(sha256.New, q.hmacKey)
	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(len(encPayload)))
	mac.Write(tsBuf)
	mac.Write(lenBuf)
	mac.Write(encPayload)
	expected := mac.Sum(nil)

	if !hmac.Equal(tag, expected) {
		return nil, fmt.Errorf("HMAC verification failed: message rejected")
	}

	// Verify timestamp freshness to prevent replay attacks.
	msgTime := int64(binary.BigEndian.Uint64(tsBuf))
	now := time.Now().Unix()
	age := now - msgTime
	const maxClockSkew = 30 // seconds into the future allowed
	if age < -maxClockSkew {
		return nil, fmt.Errorf("message from future (%ds ahead), possible clock skew or replay", -age)
	}
	if age > int64(maxMessageAge.Seconds()) {
		return nil, fmt.Errorf("message too old (%ds), possible replay attack", age)
	}

	// Decrypt the payload.
	if len(encPayload) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("encrypted payload too short")
	}
	nonce := encPayload[:chacha20poly1305.NonceSizeX]
	ciphertext := encPayload[chacha20poly1305.NonceSizeX:]

	aead, err := chacha20poly1305.NewX(q.encKey)
	if err != nil {
		return nil, fmt.Errorf("create XChaCha20-Poly1305: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(subject))
	if err != nil {
		return nil, fmt.Errorf("decrypt queue message: %w", err)
	}

	return plaintext, nil
}

// Subscribe creates a durable consumer on the given subject and calls handler for each message.
func (q *QueueClient) Subscribe(subject string, handler func(msg []byte) error) error {
	// Determine which stream this subject belongs to.
	streamName := ""
	for _, cfg := range streamConfigs {
		for _, s := range cfg.Subjects {
			// Simple prefix match: "mail.inbound.>" matches "mail.inbound.*"
			prefix := s[:len(s)-1] // strip ">"
			if len(subject) >= len(prefix) && subject[:len(prefix)] == prefix {
				streamName = cfg.Name
				break
			}
		}
		if streamName != "" {
			break
		}
	}
	if streamName == "" {
		return fmt.Errorf("no stream found for subject: %s", subject)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sanitized := strings.NewReplacer(".", "_", ">", "all", "*", "any").Replace(subject)
	consumerName := streamName + "_" + sanitized

	// Self-heal stale durable state. JetStream durables persist their
	// "last delivered" stream sequence across process restarts, but the
	// stream itself can be rebuilt independently (manual recovery, disk
	// repair, file-store corruption, our own dev-time wipe). When that
	// happens the consumer's delivered.stream_seq sits above the
	// stream's current last_seq, so the broker silently drops every
	// new message — the consumer is "ahead" of the stream and won't
	// rewind on its own. CreateOrUpdateConsumer would happily reuse
	// that bad state. Detect it here and delete first so the
	// CreateOrUpdate below makes a fresh consumer at seq 0.
	if existing, gerr := q.js.Consumer(ctx, streamName, consumerName); gerr == nil {
		consumerInfo, cerr := existing.Info(ctx)
		streamRef, srefErr := q.js.Stream(ctx, streamName)
		if cerr == nil && srefErr == nil {
			streamInfo, sinfoErr := streamRef.Info(ctx)
			if sinfoErr == nil && consumerInfo != nil && streamInfo != nil &&
				consumerInfo.Delivered.Stream > streamInfo.State.LastSeq {
				slog.Warn("stale jetstream consumer detected — deleting to self-heal",
					"stream", streamName,
					"consumer", consumerName,
					"consumer_delivered_seq", consumerInfo.Delivered.Stream,
					"stream_last_seq", streamInfo.State.LastSeq,
				)
				if derr := q.js.DeleteConsumer(ctx, streamName, consumerName); derr != nil {
					// Continue — CreateOrUpdate may still succeed; if not
					// the surrounding error is the one to surface.
					slog.Warn("delete stale consumer failed",
						"consumer", consumerName, "error", derr)
				}
			}
		}
	}

	cons, err := q.js.CreateOrUpdateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		Durable:       consumerName,
		FilterSubject: subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create consumer for %s: %w", subject, err)
	}

	_, err = cons.Consume(func(msg jetstream.Msg) {
		data, verifyErr := q.verifyMessage(msg.Data(), msg.Subject())
		if verifyErr != nil {
			// Reject unauthenticated messages permanently.
			_ = msg.Term()
			return
		}
		if err := handler(data); err != nil {
			_ = msg.Nak()
			return
		}
		_ = msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("consume %s: %w", subject, err)
	}

	return nil
}

// Drain initiates a graceful drain of the NATS connection, allowing inflight
// messages to be processed before closing. Blocks until drain completes or
// the context is cancelled.
func (q *QueueClient) Drain(ctx context.Context) error {
	if err := q.conn.Drain(); err != nil {
		return fmt.Errorf("drain: %w", err)
	}
	// Wait for drain to complete or context to expire.
	select {
	case <-ctx.Done():
		q.conn.Close()
		return ctx.Err()
	case <-func() chan struct{} {
		ch := make(chan struct{})
		go func() {
			q.conn.FlushTimeout(30 * time.Second)
			for q.conn.IsDraining() {
				time.Sleep(50 * time.Millisecond)
			}
			close(ch)
		}()
		return ch
	}():
		return nil
	}
}

// Close closes the NATS connection.
func (q *QueueClient) Close() {
	q.conn.Close()
}

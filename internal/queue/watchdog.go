package queue

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// healthSubjectPrefix is the core-NATS subject namespace for watchdog
// pings. Pub/sub only — no JetStream persistence — so heartbeat traffic
// doesn't compete with real mail or pile up on disk.
const healthSubjectPrefix = "_bmail.health"

// WatchdogConfig configures StartWatchdog.
type WatchdogConfig struct {
	// Label distinguishes this service's heartbeats from others on the
	// same NATS instance (e.g. "worker", "smtp-inbound"). Required.
	Label string
	// Interval is how often a heartbeat is published. Pick something
	// short enough that 3 misses still recovers within ~minutes.
	// Default 30s.
	Interval time.Duration
	// GracePeriod is how long after publish we wait for the loopback
	// receipt before counting it as a miss. Default 10s.
	GracePeriod time.Duration
	// MaxConsecutiveMisses before OnFail fires. Default 3.
	MaxConsecutiveMisses int
	// OnFail is invoked when MaxConsecutiveMisses misses pile up. The
	// canonical implementation is `slog.Error + os.Exit(1)` so systemd
	// (Restart=always) brings the service back fresh. Required.
	OnFail func(reason string)
}

// StartWatchdog runs a background heartbeat loop on this QueueClient's
// NATS connection. The loop publishes a small message to
// _bmail.health.<label>.<random> every Interval and verifies it
// arrives back via a loopback subscription on _bmail.health.<label>.>.
// MaxConsecutiveMisses consecutive round-trip failures triggers
// OnFail (typically slog.Error + os.Exit(1) so systemd Restart=always
// brings the service back fresh).
//
// Uses core NATS pub/sub (not JetStream) so the watchdog itself
// doesn't depend on the same machinery it's checking — a JetStream
// hang is still detected because the real mail subscription dies, and
// the watchdog roundtrip continues working over plain pub/sub.
//
// ctx cancellation shuts the loop down cleanly.
func (q *QueueClient) StartWatchdog(ctx context.Context, cfg WatchdogConfig) error {
	if cfg.Label == "" {
		return fmt.Errorf("watchdog label required")
	}
	if cfg.OnFail == nil {
		return fmt.Errorf("watchdog OnFail required")
	}
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.GracePeriod == 0 {
		cfg.GracePeriod = 10 * time.Second
	}
	if cfg.MaxConsecutiveMisses == 0 {
		cfg.MaxConsecutiveMisses = 3
	}

	subSubject := fmt.Sprintf("%s.%s.>", healthSubjectPrefix, cfg.Label)

	pending := &watchdogPending{seen: make(map[string]struct{})}

	sub, err := q.conn.Subscribe(subSubject, func(msg *nats.Msg) {
		// The last subject token after the prefix is the ping ID. Mark
		// it seen so the publish goroutine knows the round-trip closed.
		// The body is unused — it's just timestamp+nonce so Subscribe()
		// doesn't reject on size.
		id := lastSubjectToken(msg.Subject)
		if id != "" {
			pending.markSeen(id)
		}
	})
	if err != nil {
		return fmt.Errorf("watchdog subscribe: %w", err)
	}

	go func() {
		defer func() { _ = sub.Unsubscribe() }()
		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()
		consecutiveMisses := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			pingID, body, perr := newPingPayload()
			if perr != nil {
				slog.Warn("watchdog: payload generation failed", "label", cfg.Label, "error", perr)
				continue
			}
			pending.expect(pingID)
			pubSubject := fmt.Sprintf("%s.%s.%s", healthSubjectPrefix, cfg.Label, pingID)
			if pubErr := q.conn.Publish(pubSubject, body); pubErr != nil {
				slog.Warn("watchdog: publish failed", "label", cfg.Label, "error", pubErr)
				// Treat unpublishable as a miss too — the broker is
				// definitionally unreachable.
				consecutiveMisses++
			} else {
				select {
				case <-time.After(cfg.GracePeriod):
				case <-ctx.Done():
					return
				}
				if pending.consume(pingID) {
					consecutiveMisses++
					slog.Warn("watchdog: heartbeat missed",
						"label", cfg.Label,
						"ping_id", pingID,
						"consecutive_misses", consecutiveMisses)
				} else {
					consecutiveMisses = 0
				}
			}

			if consecutiveMisses >= cfg.MaxConsecutiveMisses {
				cfg.OnFail(fmt.Sprintf("watchdog: %d consecutive missed heartbeats on %s",
					consecutiveMisses, cfg.Label))
				return
			}
		}
	}()
	return nil
}

// watchdogPending tracks in-flight ping IDs. The publish goroutine
// expect()s each ID; the subscribe callback markSeen()s it; consume()
// returns whether the ID was still pending (i.e. NOT received) and
// removes it.
type watchdogPending struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func (p *watchdogPending) expect(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// expect == "we will mark this present once seen". We track absence
	// of the key as "still pending"; presence as "received".
	delete(p.seen, id)
}

func (p *watchdogPending) markSeen(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen[id] = struct{}{}
}

// consume returns true if the ping was missed (never seen). Removes the
// entry either way so the map doesn't grow unboundedly.
func (p *watchdogPending) consume(id string) (missed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[id]; ok {
		delete(p.seen, id)
		return false
	}
	return true
}

// newPingPayload returns (id, body, err). The body is timestamp+nonce —
// 16 bytes total — which is ignored by the receiver but keeps the
// payload non-empty.
func newPingPayload() (string, []byte, error) {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(time.Now().UnixNano()))
	if _, err := rand.Read(buf[8:]); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(buf[8:]), buf[:], nil
}

// lastSubjectToken returns the substring after the final '.' in s, or
// "" if there is no '.'.
func lastSubjectToken(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return s[i+1:]
		}
	}
	return ""
}

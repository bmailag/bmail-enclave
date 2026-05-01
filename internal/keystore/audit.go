package keystore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bmailag/bmail/internal/tee"
)

// auditLog is an append-only, hash-chained record of every state-changing
// operation in the keystore. Persisted as a single MRENCLAVE-sealed file
// on disk; rewritten in full on every append (atomic write-tmp + rename).
//
// Hash chain: each AuditEntry.PrevHash = SHA-256(canonical-JSON of the
// preceding entry, including ITS PrevHash). The first entry's PrevHash
// is the constant string "GENESIS" hex-encoded. Tampering with any past
// entry breaks the chain at every later entry.
//
// We intentionally rewrite the whole file rather than appending in place
// because:
//   - SealUnique encrypts the entire blob, so partial appends aren't a
//     thing without a streaming format we'd have to design
//   - For keystore-scale logs (~hundreds of entries/day at most) the
//     rewrite cost is negligible
//   - Atomic write-tmp + fsync + rename is simpler to reason about than
//     append-with-recovery
type auditLog struct {
	mu       sync.Mutex
	runtime  tee.TEERuntime
	path     string
	entries  []AuditEntry
}

// genesisHash is the PrevHash of the very first audit entry. Constant.
const genesisHash = "47454e45534953" // "GENESIS" in hex

// loadAuditLog reads + decrypts + verifies the audit log from disk.
// First-boot returns an empty log (file doesn't exist yet); the next
// append creates the file. On any chain-integrity failure, returns
// ErrCorruptedState — caller MUST treat this as fatal.
func loadAuditLog(runtime tee.TEERuntime, path string) (*auditLog, error) {
	a := &auditLog{runtime: runtime, path: path}
	sealed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil // empty, fresh keystore
	}
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	plaintext, err := runtime.UnsealUnique(sealed)
	if err != nil {
		return nil, fmt.Errorf("unseal audit log (MRENCLAVE seal mismatch?): %w", err)
	}
	if err := json.Unmarshal(plaintext, &a.entries); err != nil {
		return nil, fmt.Errorf("%w: parse audit log: %v", ErrCorruptedState, err)
	}
	if err := a.verifyChain(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptedState, err)
	}
	return a, nil
}

// Append records a new entry, computes its PrevHash from the previous
// entry, persists the full log atomically, and returns the new entry's
// sequence number. Concurrency-safe.
func (a *auditLog) Append(action string, role Role, actor, detail string) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var prevHash string
	var seq uint64
	if len(a.entries) == 0 {
		prevHash = genesisHash
		seq = 1
	} else {
		last := a.entries[len(a.entries)-1]
		h, err := canonicalHash(last)
		if err != nil {
			return 0, fmt.Errorf("hash previous entry: %w", err)
		}
		prevHash = h
		seq = last.Sequence + 1
	}

	entry := AuditEntry{
		Sequence:  seq,
		Timestamp: time.Now().UTC(),
		Action:    action,
		Role:      role,
		Actor:     actor,
		Detail:    detail,
		PrevHash:  prevHash,
	}
	a.entries = append(a.entries, entry)

	if err := a.persistLocked(); err != nil {
		// Roll back the in-memory append on persist failure so we
		// don't return a sequence number that didn't make it to disk.
		a.entries = a.entries[:len(a.entries)-1]
		return 0, err
	}
	return seq, nil
}

// Tail returns the most recent N entries (or all if fewer). Returns a
// copy so the caller can't mutate internal state.
func (a *auditLog) Tail(n int) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n <= 0 || n > len(a.entries) {
		n = len(a.entries)
	}
	out := make([]AuditEntry, n)
	copy(out, a.entries[len(a.entries)-n:])
	return out
}

// Len returns the current entry count.
func (a *auditLog) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

// verifyChain walks the chain from genesis to the latest entry and
// verifies every PrevHash matches canonicalHash(previous entry). Called
// at startup; any failure means the on-disk state has been tampered or
// corrupted.
func (a *auditLog) verifyChain() error {
	expectedPrev := genesisHash
	for i, e := range a.entries {
		if e.PrevHash != expectedPrev {
			return fmt.Errorf("audit chain broken at sequence %d (entry %d): PrevHash=%s, expected=%s",
				e.Sequence, i, e.PrevHash, expectedPrev)
		}
		if e.Sequence != uint64(i+1) {
			return fmt.Errorf("audit sequence gap: entry %d has sequence %d, expected %d",
				i, e.Sequence, i+1)
		}
		h, err := canonicalHash(e)
		if err != nil {
			return fmt.Errorf("hash entry %d: %w", i, err)
		}
		expectedPrev = h
	}
	return nil
}

// persistLocked serializes the in-memory log, seals it under MRENCLAVE,
// writes to a temporary file, fsync's it, then atomically renames into
// place. Caller MUST hold a.mu.
func (a *auditLog) persistLocked() error {
	plain, err := json.Marshal(a.entries)
	if err != nil {
		return fmt.Errorf("marshal audit entries: %w", err)
	}
	sealed, err := a.runtime.SealUnique(plain)
	if err != nil {
		return fmt.Errorf("seal audit log: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return fmt.Errorf("mkdir audit dir: %w", err)
	}
	tmp := a.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open tmp audit file: %w", err)
	}
	if _, err := f.Write(sealed); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write tmp audit file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync tmp audit file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp audit file: %w", err)
	}
	if err := os.Rename(tmp, a.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename tmp audit file: %w", err)
	}
	return nil
}

// canonicalHash returns hex-encoded SHA-256 of the JSON-canonical form
// of the entry. Canonical = json.Marshal output (Go's stable field
// ordering by struct definition order). For audit-log purposes we need
// deterministic hashing of struct contents; the canonical form is
// whatever a vanilla json.Marshal produces from our struct.
func canonicalHash(e AuditEntry) (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

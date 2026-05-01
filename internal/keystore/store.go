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

// keyEntry is the on-disk record for a single role's key. Sealed under
// MRENCLAVE; one file per role at <store-dir>/<role-hash>.bin.
//
// Why role-hash instead of role-as-filename: roles can contain dots
// (e.g. `smtp-outbound-dkim-bmail.ag`) which interact awkwardly with
// some filesystems. SHA-256(role) is unambiguous and never escapes the
// directory.
type keyEntry struct {
	Role      Role   `json:"role"`
	Key       []byte `json:"key"`
	KeyType   string `json:"key_type"`
	CreatedAt int64  `json:"created_at"` // unix seconds
}

// keyStore manages per-role sealed key files. Concurrency-safe; writes
// are atomic (write tmp + fsync + rename); reads are unsealed on every
// fetch (no in-memory caching of plaintext key bytes — this is a
// deliberate design choice so that a malicious enclave that somehow
// bypasses HTTP auth still has to call SealUnique-Unseal to extract,
// which logs an audit entry).
type keyStore struct {
	mu      sync.Mutex // single-writer; reads can race with writes via the FS rename atomicity
	runtime tee.TEERuntime
	dir     string
}

// newKeyStore initializes the store rooted at dir. Creates the directory
// if needed. Doesn't read or load any keys — Load/Provision are explicit.
func newKeyStore(runtime tee.TEERuntime, dir string) (*keyStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir keystore dir: %w", err)
	}
	return &keyStore{runtime: runtime, dir: dir}, nil
}

// Has reports whether a role has stored key material on disk. Doesn't
// unseal — purely a filesystem check. Used by Provision to enforce
// one-shot semantics.
func (s *keyStore) Has(role Role) bool {
	_, err := os.Stat(s.path(role))
	return err == nil
}

// Get reads, unseals, and returns the stored key for the role. The
// returned []byte is a fresh allocation (caller may keep or zero).
func (s *keyStore) Get(role Role) (*keyEntry, error) {
	sealed, err := os.ReadFile(s.path(role))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrRoleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read role %q: %w", role, err)
	}
	plain, err := s.runtime.UnsealUnique(sealed)
	if err != nil {
		return nil, fmt.Errorf("unseal role %q (MRENCLAVE seal mismatch?): %w", role, err)
	}
	var entry keyEntry
	if err := json.Unmarshal(plain, &entry); err != nil {
		return nil, fmt.Errorf("%w: parse role %q: %v", ErrCorruptedState, role, err)
	}
	if entry.Role != role {
		// Defense in depth: file content's role mismatches filename's
		// role-hash. This shouldn't happen with our write path, but
		// catching it here means an attacker can't smuggle a different
		// key by manipulating the disk.
		return nil, fmt.Errorf("%w: role mismatch in stored entry: file=%q content=%q",
			ErrCorruptedState, role, entry.Role)
	}
	return &entry, nil
}

// Provision installs the FIRST key for a role. Returns ErrAlreadyProvisioned
// if the role already has stored material; in that case the existing key
// is untouched.
func (s *keyStore) Provision(role Role, key []byte, keyType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Has(role) {
		return ErrAlreadyProvisioned
	}
	entry := keyEntry{
		Role:      role,
		Key:       key,
		KeyType:   keyType,
		CreatedAt: time.Now().Unix(),
	}
	return s.writeAtomic(entry)
}

// writeAtomic seals + writes one role's entry to disk. Caller holds s.mu.
func (s *keyStore) writeAtomic(entry keyEntry) error {
	plain, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	sealed, err := s.runtime.SealUnique(plain)
	if err != nil {
		return fmt.Errorf("seal entry: %w", err)
	}
	finalPath := s.path(entry.Role)
	tmp := finalPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open tmp role file: %w", err)
	}
	if _, err := f.Write(sealed); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write tmp role file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync tmp role file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp role file: %w", err)
	}
	if err := os.Rename(tmp, finalPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename role file: %w", err)
	}
	return nil
}

// path returns the canonical on-disk path for a role's sealed key.
func (s *keyStore) path(role Role) string {
	sum := sha256.Sum256([]byte(role))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".bin")
}

// ListRoles returns the role of every stored key. Reads each file's
// header (decrypts to get the .Role field). Used for ListResponse.
// O(n) with small n.
func (s *keyStore) ListRoles() ([]Role, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read keystore dir: %w", err)
	}
	out := make([]Role, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !hasSuffix(e.Name(), ".bin") {
			continue
		}
		// We don't know the role from the filename alone (it's a hash);
		// decrypt to read it. Skip on per-file errors so one corrupt
		// file doesn't blind the whole list.
		sealed, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		plain, err := s.runtime.UnsealUnique(sealed)
		if err != nil {
			continue
		}
		var entry keyEntry
		if err := json.Unmarshal(plain, &entry); err != nil {
			continue
		}
		out = append(out, entry.Role)
	}
	return out, nil
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

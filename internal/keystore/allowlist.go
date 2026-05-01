package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/bmailag/bmail/internal/tee"
)

// allowlist holds the per-role set of MRENCLAVEs authorized to fetch
// keys. Persisted as a single MRENCLAVE-sealed JSON blob; rewritten in
// full on every change. Concurrency-safe.
//
// Single-writer invariant is enforced by the surrounding Keystore
// service (the HTTP handlers serialize Delegate/Revoke calls via
// allowlist.mu); multiple concurrent readers are fine.
type allowlist struct {
	mu      sync.RWMutex
	runtime tee.TEERuntime
	path    string

	// roles is the canonical map: role -> list of allowed MRENCLAVEs.
	// We store as slices (not sets) for deterministic JSON ordering on
	// disk; duplicates are prevented by Add (idempotent).
	roles map[Role][][32]byte
}

// loadAllowlist reads the sealed allowlist from disk, decrypts under
// MRENCLAVE, and validates structure. Missing file = empty allowlist
// (first boot).
func loadAllowlist(runtime tee.TEERuntime, path string) (*allowlist, error) {
	a := &allowlist{
		runtime: runtime,
		path:    path,
		roles:   map[Role][][32]byte{},
	}
	sealed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	plain, err := runtime.UnsealUnique(sealed)
	if err != nil {
		return nil, fmt.Errorf("unseal allowlist (MRENCLAVE seal mismatch?): %w", err)
	}
	// On-disk shape: {"role": ["<32-byte mrenclave hex>", ...], ...}
	var onDisk map[string][]string
	if err := json.Unmarshal(plain, &onDisk); err != nil {
		return nil, fmt.Errorf("%w: parse allowlist: %v", ErrCorruptedState, err)
	}
	for k, v := range onDisk {
		role := Role(k)
		if err := role.Validate(); err != nil {
			return nil, fmt.Errorf("%w: invalid role %q in allowlist", ErrCorruptedState, k)
		}
		mrencs := make([][32]byte, 0, len(v))
		for _, hexStr := range v {
			m, err := decodeMRENCLAVEHex(hexStr)
			if err != nil {
				return nil, fmt.Errorf("%w: bad mrenclave %q for role %q: %v", ErrCorruptedState, hexStr, k, err)
			}
			mrencs = append(mrencs, m)
		}
		a.roles[role] = mrencs
	}
	return a, nil
}

// Allowed reports whether the given MRENCLAVE is on the allowlist for
// the role. No allocation in the read path.
func (a *allowlist) Allowed(role Role, mrenclave [32]byte) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, m := range a.roles[role] {
		if m == mrenclave {
			return true
		}
	}
	return false
}

// Get returns a copy of the allowlist slice for a role (or nil if
// no entry). The returned slice is safe to mutate by the caller.
func (a *allowlist) Get(role Role) [][32]byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	src := a.roles[role]
	if len(src) == 0 {
		return nil
	}
	out := make([][32]byte, len(src))
	copy(out, src)
	return out
}

// Add appends an MRENCLAVE to the role's allowlist (idempotent: duplicates
// are silently ignored). Persists the change atomically. Returns the new
// full allowlist for the role on success.
func (a *allowlist) Add(role Role, mrenclave [32]byte) ([][32]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, m := range a.roles[role] {
		if m == mrenclave {
			// Already present; return current allowlist as a copy.
			out := make([][32]byte, len(a.roles[role]))
			copy(out, a.roles[role])
			return out, nil
		}
	}
	a.roles[role] = append(a.roles[role], mrenclave)
	if err := a.persistLocked(); err != nil {
		// Roll back the in-memory mutation so allowlist on disk and
		// in memory stay in sync.
		a.roles[role] = a.roles[role][:len(a.roles[role])-1]
		return nil, err
	}
	out := make([][32]byte, len(a.roles[role]))
	copy(out, a.roles[role])
	return out, nil
}

// Remove deletes an MRENCLAVE from the role's allowlist. No-op if not
// present. Persists atomically.
func (a *allowlist) Remove(role Role, mrenclave [32]byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	cur := a.roles[role]
	idx := -1
	for i, m := range cur {
		if m == mrenclave {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil // not present, nothing to do
	}

	// Snapshot for rollback on persist failure.
	snapshot := make([][32]byte, len(cur))
	copy(snapshot, cur)

	a.roles[role] = append(cur[:idx], cur[idx+1:]...)
	if err := a.persistLocked(); err != nil {
		a.roles[role] = snapshot
		return err
	}
	return nil
}

// Snapshot returns a copy of the entire allowlist. Used by ListResponse.
func (a *allowlist) Snapshot() map[Role][][32]byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make(map[Role][][32]byte, len(a.roles))
	for k, v := range a.roles {
		copied := make([][32]byte, len(v))
		copy(copied, v)
		out[k] = copied
	}
	return out
}

// persistLocked serializes the allowlist, seals it under MRENCLAVE, and
// atomically writes to disk. Caller MUST hold a.mu (write).
func (a *allowlist) persistLocked() error {
	onDisk := make(map[string][]string, len(a.roles))
	for role, mrencs := range a.roles {
		hexes := make([]string, len(mrencs))
		for i, m := range mrencs {
			hexes[i] = encodeMRENCLAVEHex(m)
		}
		onDisk[string(role)] = hexes
	}
	plain, err := json.Marshal(onDisk)
	if err != nil {
		return fmt.Errorf("marshal allowlist: %w", err)
	}
	sealed, err := a.runtime.SealUnique(plain)
	if err != nil {
		return fmt.Errorf("seal allowlist: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return fmt.Errorf("mkdir allowlist dir: %w", err)
	}
	tmp := a.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open tmp allowlist: %w", err)
	}
	if _, err := f.Write(sealed); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write tmp allowlist: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync tmp allowlist: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp allowlist: %w", err)
	}
	if err := os.Rename(tmp, a.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename allowlist: %w", err)
	}
	return nil
}

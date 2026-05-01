// Package gateway: sealed_cache wraps autocert's Cache interface with
// TEE seal/unseal so cached TLS keys + ACME account keys never sit on
// disk in plaintext.
//
// Background: autocert.DirCache (the canonical implementation) writes
// PEM-encoded private keys + cert bundles to a filesystem path. With
// our hostfs mount of /opt/bmail/certs (so the host can serve cached
// LE/GTS challenges + carry keys across enclave restarts), an operator
// with host root could read every TLS private key autocert manages.
// That's a real gap: the verifiable-cert claim ("only the enclave has
// the TLS key") doesn't hold without protecting the on-disk form.
//
// SealedDirCache wraps autocert's existing DirCache: every Put seals
// the bytes under the enclave identity before writing; every Get
// unseals before returning. Autocert sees the same plaintext PEM as
// before; an operator reading the disk sees opaque sealed blobs.
//
// Seal policy: caller passes the seal/unseal funcs. For gateway tonight
// we use MRENCLAVE-bound (`tee.SealUnique` / `tee.UnsealUnique`):
// every gateway code change loses the cached cert, autocert fetches a
// fresh one from GTS. With GTS having no rate limit this is operationally
// free, and it gives the cleanest "operator can't extract the TLS key"
// property — only the exact running gateway code can unseal.
//
// The wrapped cache is byte-for-byte compatible with autocert's
// expectations: errors propagate (ErrCacheMiss is the only one that
// matters; autocert treats any other error as fatal and falls back to
// a fresh issuance).
package gateway

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// SealFunc seals plaintext bytes. Implementations MUST be deterministic
// in failure (same input → same error class) and atomic in success.
type SealFunc func(plaintext []byte) (ciphertext []byte, err error)

// UnsealFunc reverses SealFunc.
type UnsealFunc func(ciphertext []byte) (plaintext []byte, err error)

// SealedDirCache wraps an autocert.Cache with seal/unseal — but only
// for entries that contain TLS private key material. ACME account keys
// and EAB-related state are passed through plaintext.
//
// Why selective: the verifiability claim ("operator cannot extract the
// served TLS key") depends on the TLS key being enclave-bound. ACME
// account keys are operational credentials — if leaked, an attacker
// could mint another cert for bmail's domains, but it'd have a
// different SPKI than the enclave-sealed key, and /verify would
// surface the mismatch. So sealing the account key is unnecessary
// security, while making operational pain real (every gateway code
// flip would invalidate the sealed account key, requiring a fresh
// single-use GTS EAB to re-register — expensive and easily forgotten).
//
// Cache key conventions in autocert:
//   - "<domain>"            cert+key blob (PEM) — SEAL
//   - "<domain>+token"      challenge response — DON'T SEAL (transient)
//   - "<domain>+http-01"    challenge response — DON'T SEAL (transient)
//   - "acme_account+key"    ACME account key (default Manager)
//   - "acme_account.key"    ACME account key (CSR-based renewers)
//   - any "acme_*" prefix   account/registration state — DON'T SEAL
type SealedDirCache struct {
	inner  autocert.Cache
	seal   SealFunc
	unseal UnsealFunc
}

// NewSealedDirCache wraps an inner cache with seal/unseal.
func NewSealedDirCache(inner autocert.Cache, seal SealFunc, unseal UnsealFunc) *SealedDirCache {
	return &SealedDirCache{inner: inner, seal: seal, unseal: unseal}
}

// shouldSeal returns true for cache entries containing TLS private key
// material. Conservative default: anything we're not sure about gets
// sealed. The explicit allowlist of plaintext-OK keys is "acme_*" —
// account keys and challenge state.
func shouldSeal(cacheKey string) bool {
	if strings.HasPrefix(cacheKey, "acme_") {
		// Account keys, challenge tokens, registration state.
		return false
	}
	if strings.Contains(cacheKey, "+token") || strings.Contains(cacheKey, "+http-01") || strings.Contains(cacheKey, "+tls-alpn-01") {
		// Challenge responses — transient, no key material.
		return false
	}
	// Default: assume the entry contains TLS key material (cert+key
	// blob keyed by domain). Seal it.
	return true
}

// Get reads bytes from the inner cache. For TLS-key-bearing entries
// (per shouldSeal), unseals before returning. For other entries
// (account keys, challenge state), passes through plaintext.
//
// If unseal fails on a sealed entry — e.g., MRENCLAVE drift since the
// data was sealed — return ErrCacheMiss so autocert mints a fresh
// cert. That's exactly the desired behavior after an enclave update.
func (c *SealedDirCache) Get(ctx context.Context, key string) ([]byte, error) {
	bytes, err := c.inner.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if !shouldSeal(key) {
		return bytes, nil
	}
	plain, err := c.unseal(bytes)
	if err != nil {
		return nil, autocert.ErrCacheMiss
	}
	return plain, nil
}

// Put seals TLS-key-bearing entries before writing; passes through
// plaintext for account keys and challenge state.
func (c *SealedDirCache) Put(ctx context.Context, key string, data []byte) error {
	if !shouldSeal(key) {
		return c.inner.Put(ctx, key, data)
	}
	sealed, err := c.seal(data)
	if err != nil {
		return fmt.Errorf("seal cache entry %q: %w", key, err)
	}
	return c.inner.Put(ctx, key, sealed)
}

// Delete passes through to the inner cache (sealed bytes are deleted
// the same as plaintext).
func (c *SealedDirCache) Delete(ctx context.Context, key string) error {
	return c.inner.Delete(ctx, key)
}

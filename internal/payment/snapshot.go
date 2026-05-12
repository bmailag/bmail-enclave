package payment

// Snapshot pipeline for payment's sealed key files. Mirrors the
// pattern in internal/keystore/snapshot.go but operates on a
// caller-supplied file allowlist rather than walking a directory —
// payment's sealed files live in /opt/bmail/sealed/ alongside gateway
// and smtp-outbound's TLS keys, which we DON'T want to back up here.
//
// Sealed bytes are MRSIGNER-encrypted by SGX; the snapshot adds no
// security at rest. The pipeline exists for *durability*: surviving a
// disk-loss event without rotating the FakeID mint / blind-signature
// tier keys. Per ADR-007, the durability floor is "regenerate keys +
// re-publish", but that's a customer-visible outage; this avoids it.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// snapshotMetaFile is the magic filename for the in-archive metadata
// header. Streaming restorers read this first and validate the rest
// of the archive against the recorded hash before extracting.
const snapshotMetaFile = "_payment_snapshot.json"

// Snapshotter persists durable backups of payment's sealed key files.
// Implementations: NopSnapshotter (tests), LocalFSSnapshotter
// (dev + fullbox belt-and-suspenders), S3Snapshotter (production).
type Snapshotter interface {
	// Save packs the named files into a single archive and writes it
	// to durable storage. Returns the snapshot ID (opaque
	// implementation-defined string) the operator passes to the
	// restore tool.
	Save(ctx context.Context, files []string, label string) (snapshotID string, err error)
}

// SnapshotMeta is the small JSON header packed first into each
// archive so a restorer can sanity-check the contents.
type SnapshotMeta struct {
	CreatedAt int64    `json:"created_at"`
	Label     string   `json:"label"`
	Files     []string `json:"files"`    // basenames of archived files
	Hash      string   `json:"hash_hex"` // sha256 of sorted (basename, sha256(content)) pairs
	Bytes     int64    `json:"bytes"`    // total uncompressed payload bytes
}

type packEntry struct {
	name  string // basename only — payment sealed files live flat under /opt/bmail/sealed/
	bytes []byte
}

// PackFiles reads each path in files and returns a gzip-compressed
// tar archive plus its metadata. The meta entry is the FIRST tar
// record so a streaming restorer can validate before extracting.
//
// Files are stored by basename only (no directory hierarchy in the
// archive); restoration writes them flat into destDir.
//
// Missing-file behaviour: silently skipped (payment may not yet
// have provisioned every tier key, e.g. before first FakeID mint).
// The meta records exactly which files made it into the archive.
func PackFiles(files []string, label string) ([]byte, *SnapshotMeta, error) {
	var entries []packEntry
	for _, p := range files {
		buf, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, nil, fmt.Errorf("read %s: %w", p, err)
		}
		entries = append(entries, packEntry{
			name:  filepath.Base(p),
			bytes: buf,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].name < entries[j].name
	})

	hasher := sha256.New()
	names := make([]string, 0, len(entries))
	var totalBytes int64
	for _, e := range entries {
		fileSum := sha256.Sum256(e.bytes)
		hasher.Write([]byte(e.name))
		hasher.Write(fileSum[:])
		names = append(names, e.name)
		totalBytes += int64(len(e.bytes))
	}
	meta := &SnapshotMeta{
		CreatedAt: time.Now().Unix(),
		Label:     label,
		Files:     names,
		Hash:      hex.EncodeToString(hasher.Sum(nil)),
		Bytes:     totalBytes,
	}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal snapshot meta: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:    snapshotMetaFile,
		Mode:    0o600,
		Size:    int64(len(metaJSON)),
		ModTime: time.Unix(meta.CreatedAt, 0),
	}); err != nil {
		return nil, nil, fmt.Errorf("write meta header: %w", err)
	}
	if _, err := tw.Write(metaJSON); err != nil {
		return nil, nil, fmt.Errorf("write meta body: %w", err)
	}

	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:    e.name,
			Mode:    0o600,
			Size:    int64(len(e.bytes)),
			ModTime: time.Unix(meta.CreatedAt, 0),
		}); err != nil {
			return nil, nil, fmt.Errorf("write %s header: %w", e.name, err)
		}
		if _, err := tw.Write(e.bytes); err != nil {
			return nil, nil, fmt.Errorf("write %s body: %w", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, nil, fmt.Errorf("close gzip: %w", err)
	}
	return raw.Bytes(), meta, nil
}

// ExtractFiles reverses PackFiles. Writes each archived file flat
// into destDir (basename only, no directory creation). destDir must
// exist; conflicting files are overwritten. Verifies the meta hash
// before returning.
func ExtractFiles(archive []byte, destDir string) (*SnapshotMeta, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var meta *SnapshotMeta
	hasher := sha256.New()

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		if strings.Contains(hdr.Name, "/") || strings.Contains(hdr.Name, "..") {
			return nil, fmt.Errorf("rejecting unsafe path in archive: %q", hdr.Name)
		}
		buf, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read tar body for %s: %w", hdr.Name, err)
		}
		if hdr.Name == snapshotMetaFile {
			var m SnapshotMeta
			if err := json.Unmarshal(buf, &m); err != nil {
				return nil, fmt.Errorf("parse snapshot meta: %w", err)
			}
			meta = &m
			continue
		}
		fileSum := sha256.Sum256(buf)
		hasher.Write([]byte(hdr.Name))
		hasher.Write(fileSum[:])
		full := filepath.Join(destDir, hdr.Name)
		if err := os.WriteFile(full, buf, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", full, err)
		}
	}
	if meta == nil {
		return nil, errors.New("archive missing " + snapshotMetaFile + " header")
	}
	got := hex.EncodeToString(hasher.Sum(nil))
	if got != meta.Hash {
		return nil, fmt.Errorf("integrity mismatch: header hash=%s computed=%s", meta.Hash, got)
	}
	return meta, nil
}

// snapshotID composes a stable, sortable, human-readable ID:
//
//	<RFC3339 with -'s instead of :'s>-<label>-<8 hex random>
//
// The leading timestamp makes lexicographic sort match chronological;
// the random suffix prevents collisions when two snapshots fire in
// the same second (e.g. startup + post-write race).
func snapshotID(label string) string {
	now := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	clean := strings.ReplaceAll(label, "/", "_")
	clean = strings.ReplaceAll(clean, " ", "_")
	return fmt.Sprintf("%s-%s-%s", now, clean, hex.EncodeToString(nonce[:]))
}

// ── Implementations ──────────────────────────────────────────────────

// NopSnapshotter discards snapshots silently. Used in tests and dev
// modes where external storage isn't wired.
type NopSnapshotter struct{}

func (NopSnapshotter) Save(_ context.Context, _ []string, _ string) (string, error) {
	return "nop", nil
}

// LocalFSSnapshotter writes archives to a local directory. Used as a
// belt-and-suspenders backup alongside S3.
type LocalFSSnapshotter struct {
	Dir    string
	Logger *slog.Logger
}

func (l *LocalFSSnapshotter) Save(_ context.Context, files []string, label string) (string, error) {
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir snapshot dir: %w", err)
	}
	archive, meta, err := PackFiles(files, label)
	if err != nil {
		return "", err
	}
	id := snapshotID(label)
	full := filepath.Join(l.Dir, id+".tgz")
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, archive, 0o600); err != nil {
		return "", fmt.Errorf("write snapshot: %w", err)
	}
	if err := os.Rename(tmp, full); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("rename snapshot: %w", err)
	}
	if l.Logger != nil {
		l.Logger.Info("payment snapshot saved (localfs)",
			"id", id, "label", label,
			"files", len(meta.Files), "bytes", meta.Bytes,
			"path", full)
	}
	return id, nil
}

// S3Snapshotter pushes archives to an S3-compatible object store
// (Cloudflare R2 in production). Bucket key layout:
//
//	<prefix>/<snapshotID>.tgz
//
// Retention is operator-configured at the bucket level (R2 lifecycle).
type S3Snapshotter struct {
	Client *minio.Client
	Bucket string
	Prefix string
	Logger *slog.Logger
}

func NewS3Snapshotter(endpoint, accessKey, secretKey, bucket, prefix string, useSSL bool, logger *slog.Logger) (*S3Snapshotter, error) {
	if endpoint == "" {
		return nil, errors.New("s3 endpoint is required")
	}
	if bucket == "" {
		return nil, errors.New("s3 bucket is required")
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       useSSL,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return nil, fmt.Errorf("create minio client: %w", err)
	}
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &S3Snapshotter{
		Client: client,
		Bucket: bucket,
		Prefix: prefix,
		Logger: logger,
	}, nil
}

func (s *S3Snapshotter) Save(ctx context.Context, files []string, label string) (string, error) {
	archive, meta, err := PackFiles(files, label)
	if err != nil {
		return "", err
	}
	id := snapshotID(label)
	key := s.Prefix + id + ".tgz"
	_, err = s.Client.PutObject(ctx, s.Bucket, key, bytes.NewReader(archive), int64(len(archive)),
		minio.PutObjectOptions{ContentType: "application/gzip"})
	if err != nil {
		return "", fmt.Errorf("s3 put %s/%s: %w", s.Bucket, key, err)
	}
	if s.Logger != nil {
		s.Logger.Info("payment snapshot saved (s3)",
			"id", id, "label", label,
			"files", len(meta.Files), "bytes", meta.Bytes,
			"bucket", s.Bucket, "key", key)
	}
	return id, nil
}

// Get downloads a previously-saved snapshot. Used by payment-restore.
func (s *S3Snapshotter) Get(ctx context.Context, id string) ([]byte, error) {
	key := s.Prefix + id + ".tgz"
	obj, err := s.Client.GetObject(ctx, s.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("s3 get %s/%s: %w", s.Bucket, key, err)
	}
	defer obj.Close()
	buf, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("s3 read %s/%s: %w", s.Bucket, key, err)
	}
	return buf, nil
}

// List returns the IDs of all snapshots in the bucket prefix, newest
// first. Used by payment-restore --list.
func (s *S3Snapshotter) List(ctx context.Context) ([]string, error) {
	var ids []string
	for obj := range s.Client.ListObjects(ctx, s.Bucket, minio.ListObjectsOptions{
		Prefix:    s.Prefix,
		Recursive: false,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("s3 list %s: %w", s.Bucket, obj.Err)
		}
		// Strip the prefix and trailing .tgz to recover the bare ID.
		name := strings.TrimPrefix(obj.Key, s.Prefix)
		name = strings.TrimSuffix(name, ".tgz")
		if name == "" {
			continue
		}
		ids = append(ids, name)
	}
	// Reverse-chronological: snapshotID has the timestamp at the front,
	// so a descending sort puts the newest first.
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids, nil
}

// RunDailySnapshotter spawns a goroutine that fires Save once a day
// with label="daily-cron". Cancellation of ctx ends the loop.
//
// Failures are logged but never fatal — durability is best-effort,
// and the operator's monitoring catches missed snapshots out-of-band
// (e.g. an R2 last-modified alert at the bucket level).
func RunDailySnapshotter(ctx context.Context, s Snapshotter, files []string, logger *slog.Logger) {
	if s == nil || len(files) == 0 {
		return
	}
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	// Take one immediately on startup so a freshly-started payment has
	// an off-box copy of whatever it just unsealed.
	if _, err := s.Save(ctx, files, "startup"); err != nil && logger != nil {
		logger.Warn("payment startup snapshot failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Save(ctx, files, "daily-cron"); err != nil && logger != nil {
				logger.Warn("payment daily snapshot failed", "err", err)
			}
		}
	}
}

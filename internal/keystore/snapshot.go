package keystore

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
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Snapshotter persists durable backups of the keystore's sealed dir.
//
// Snapshot contents are MRENCLAVE-sealed bytes already, so the
// snapshotter need not encrypt at rest — but it must be reliable.
// Implementations: NopSnapshotter (tests), LocalFSSnapshotter (dev +
// CI restore tests), S3Snapshotter (production).
type Snapshotter interface {
	// Save packs the sealed dir into a single archive and writes it to
	// durable storage. Returns the snapshot ID assigned (an opaque
	// implementation-defined string the operator can later pass to a
	// restore tool).
	Save(ctx context.Context, sealedDir, label string) (snapshotID string, err error)
}

// SnapshotMeta is the small JSON header packed into each archive so a
// restorer can sanity-check the contents before extracting.
type SnapshotMeta struct {
	CreatedAt int64    `json:"created_at"`
	Label     string   `json:"label"`
	Files     []string `json:"files"`    // relative paths inside the archive (not including the meta file itself)
	Hash      string   `json:"hash_hex"` // sha256 of the concatenated sorted (path, sha256(content)) pairs — quick integrity check
	Bytes     int64    `json:"bytes"`    // total uncompressed payload bytes
}

// PackSealedDir walks sealedDir and returns a gzip-compressed tar
// archive plus the meta header describing it. The meta is the FIRST
// entry in the tar so a streaming restorer can validate it before
// extracting the rest.
//
// label is a short human-readable string ("post-provision",
// "daily-cron", "manual") attached to the meta for forensics.
func PackSealedDir(sealedDir, label string) ([]byte, *SnapshotMeta, error) {
	var files []packEntry
	if err := filepath.WalkDir(sealedDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Skip stray .tmp files left by interrupted writeAtomic calls;
		// the keystore would have ignored them anyway.
		if strings.HasSuffix(path, ".tmp") {
			return nil
		}
		rel, err := filepath.Rel(sealedDir, path)
		if err != nil {
			return err
		}
		buf, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		files = append(files, packEntry{rel: filepath.ToSlash(rel), bytes: buf})
		return nil
	}); err != nil {
		return nil, nil, err
	}

	sortPackEntries(files)

	hasher := sha256.New()
	relList := make([]string, 0, len(files))
	var totalBytes int64
	for _, f := range files {
		fileSum := sha256.Sum256(f.bytes)
		hasher.Write([]byte(f.rel))
		hasher.Write(fileSum[:])
		relList = append(relList, f.rel)
		totalBytes += int64(len(f.bytes))
	}
	meta := &SnapshotMeta{
		CreatedAt: time.Now().Unix(),
		Label:     label,
		Files:     relList,
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
		Name:    "_keystore_snapshot.json",
		Mode:    0o600,
		Size:    int64(len(metaJSON)),
		ModTime: time.Unix(meta.CreatedAt, 0),
	}); err != nil {
		return nil, nil, fmt.Errorf("write meta header: %w", err)
	}
	if _, err := tw.Write(metaJSON); err != nil {
		return nil, nil, fmt.Errorf("write meta body: %w", err)
	}

	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:    f.rel,
			Mode:    0o600,
			Size:    int64(len(f.bytes)),
			ModTime: time.Unix(meta.CreatedAt, 0),
		}); err != nil {
			return nil, nil, fmt.Errorf("write %s header: %w", f.rel, err)
		}
		if _, err := tw.Write(f.bytes); err != nil {
			return nil, nil, fmt.Errorf("write %s body: %w", f.rel, err)
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

// ExtractSealedDir reverses PackSealedDir — extracts archive bytes
// into destDir. Returns the meta header. destDir must exist; existing
// files at conflicting paths are overwritten (intended use is restore
// into a fresh empty dir).
//
// Verifies the meta hash before returning. A corrupt archive returns
// an error and leaves the partial extraction in place (caller should
// wipe and retry).
func ExtractSealedDir(archive []byte, destDir string) (*SnapshotMeta, error) {
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
		if strings.Contains(hdr.Name, "..") || strings.HasPrefix(hdr.Name, "/") {
			return nil, fmt.Errorf("rejecting unsafe path in archive: %q", hdr.Name)
		}

		buf, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read tar body for %s: %w", hdr.Name, err)
		}

		if hdr.Name == "_keystore_snapshot.json" {
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

		full := filepath.Join(destDir, filepath.FromSlash(hdr.Name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return nil, fmt.Errorf("mkdir for %s: %w", hdr.Name, err)
		}
		if err := os.WriteFile(full, buf, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", full, err)
		}
	}

	if meta == nil {
		return nil, errors.New("archive missing _keystore_snapshot.json header")
	}

	got := hex.EncodeToString(hasher.Sum(nil))
	if got != meta.Hash {
		return nil, fmt.Errorf("integrity mismatch: header hash=%s computed=%s", meta.Hash, got)
	}
	return meta, nil
}

// ── Implementations ──────────────────────────────────────────────────

// NopSnapshotter discards snapshots silently. Used in tests and dev
// modes where we don't want to depend on external storage.
type NopSnapshotter struct{}

func (NopSnapshotter) Save(_ context.Context, _, _ string) (string, error) {
	return "nop", nil
}

// LocalFSSnapshotter writes archives to a local directory. Used by CI
// chaos tests and as a poor-man's backup if S3 isn't available.
type LocalFSSnapshotter struct {
	Dir    string
	Logger *slog.Logger
}

func (l *LocalFSSnapshotter) Save(_ context.Context, sealedDir, label string) (string, error) {
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir snapshot dir: %w", err)
	}
	archive, meta, err := PackSealedDir(sealedDir, label)
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
		l.Logger.Info("keystore snapshot saved (localfs)",
			"id", id, "label", label,
			"files", len(meta.Files), "bytes", meta.Bytes,
			"path", full)
	}
	return id, nil
}

// S3Snapshotter pushes archives to an S3-compatible object store
// (Cloudflare R2, MinIO, AWS S3). Production durability tier.
type S3Snapshotter struct {
	Client *minio.Client
	Bucket string
	Prefix string // object key prefix, e.g. "keystore-snapshots/"
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

func (s *S3Snapshotter) Save(ctx context.Context, sealedDir, label string) (string, error) {
	archive, meta, err := PackSealedDir(sealedDir, label)
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
		s.Logger.Info("keystore snapshot saved (s3)",
			"id", id, "label", label,
			"files", len(meta.Files), "bytes", meta.Bytes,
			"bucket", s.Bucket, "key", key)
	}
	return id, nil
}

// Get downloads a previously-saved snapshot archive. Used by the
// restore tool.
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
// first. Tool-facing.
func (s *S3Snapshotter) List(ctx context.Context) ([]string, error) {
	var ids []string
	for obj := range s.Client.ListObjects(ctx, s.Bucket, minio.ListObjectsOptions{
		Prefix:    s.Prefix,
		Recursive: false,
	}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		name := strings.TrimPrefix(obj.Key, s.Prefix)
		name = strings.TrimSuffix(name, ".tgz")
		if name != "" {
			ids = append(ids, name)
		}
	}
	// Newest first — IDs start with RFC3339 timestamps so reverse sort works.
	for i, j := 0, len(ids)-1; i < j; i, j = i+1, j-1 {
		ids[i], ids[j] = ids[j], ids[i]
	}
	return ids, nil
}

// runDailySnapshotter spawns a loop that fires the snapshotter once
// every 24h with label="daily-cron". Cancels with ctx. Used as the
// floor below per-Provision snapshots — protects against quiet days
// where no Provision happens but disk could still rot.
func runDailySnapshotter(ctx context.Context, snapper Snapshotter, sealedDir string, logger *slog.Logger) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	// Fire one immediately on startup so a freshly-restarted keystore
	// produces a baseline snapshot without waiting 24h.
	if _, err := snapper.Save(ctx, sealedDir, "startup"); err != nil && logger != nil {
		logger.Warn("startup snapshot failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := snapper.Save(ctx, sealedDir, "daily-cron"); err != nil && logger != nil {
				logger.Warn("daily snapshot failed", "err", err)
			}
		}
	}
}

// ── Internal helpers ────────────────────────────────────────────────

type packEntry struct {
	rel   string
	bytes []byte
}

func sortPackEntries(es []packEntry) {
	// Insertion sort — entries small (a handful of files), keep deps zero.
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && es[j-1].rel > es[j].rel; j-- {
			es[j], es[j-1] = es[j-1], es[j]
		}
	}
}

// snapshotID returns a unique, sortable ID with the form
// 2026-04-30T16-42-00Z-<label>-<random8>. Sortability matters for
// "show me the latest snapshot" UX.
func snapshotID(label string) string {
	ts := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s-%s", ts, sanitizeLabel(label), hex.EncodeToString(b[:]))
}

func sanitizeLabel(label string) string {
	if label == "" {
		return "snap"
	}
	out := make([]byte, 0, len(label))
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

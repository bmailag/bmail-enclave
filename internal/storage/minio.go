package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"os"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var blobBucket = "bmail"

func init() {
	if b := os.Getenv("MINIO_BUCKET"); b != "" {
		blobBucket = b
	}
}

// NewBlobStoreWithBucket creates a BlobStore pointing at a specific bucket.
func NewBlobStoreWithBucket(endpoint, accessKey, secretKey string, useSSL bool, bucket string) (*BlobStore, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       useSSL,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return nil, fmt.Errorf("create minio client: %w", err)
	}
	return &BlobStore{client: client, bucket: bucket}, nil
}

// BlobStore wraps a MinIO client for encrypted message blob storage.
type BlobStore struct {
	client   *minio.Client
	bucket   string        // per-instance bucket override; empty = use global blobBucket
	fallback *minio.Client // optional read-only secondary source (see SetFallback)
}

// fallbackReadCount counts reads served from the migration fallback across all
// BlobStores in the process. Steady zero means the fallback is no longer needed.
var fallbackReadCount int64

// FallbackHits returns the number of reads served from the migration fallback.
// During an R2 account migration, watch this drop to (and stay at) zero after
// the final delta sync — that's the signal it's safe to remove the fallback.
func FallbackHits() int64 { return atomic.LoadInt64(&fallbackReadCount) }

// SetFallback attaches a secondary, read-only blob source used only when the
// primary returns NoSuchKey. During an R2 account migration the primary points
// at the NEW account and the fallback at the OLD one, so a read for an object
// not yet copied still succeeds (served from the old account) instead of 404ing.
// Writes and deletes never touch the fallback. The fallback reads the SAME
// bucket name as the primary — buckets are mirrored under identical names.
// AttachMigrationFallback reads MINIO_FALLBACK_ENDPOINT / _ACCESS_KEY /
// _SECRET_KEY from the environment and, if all three are present, attaches the
// old account as a read-only fallback on each given store. Bucket names are
// unchanged (mirrored identically), so only the endpoint+creds differ. Returns
// true iff a fallback was configured. nil stores are skipped. When the env is
// unset this is a no-op — so the fallback code stays dormant until cutover.
func AttachMigrationFallback(stores ...*BlobStore) bool {
	ep := os.Getenv("MINIO_FALLBACK_ENDPOINT")
	ak := os.Getenv("MINIO_FALLBACK_ACCESS_KEY")
	sk := os.Getenv("MINIO_FALLBACK_SECRET_KEY")
	if ep == "" || ak == "" || sk == "" {
		return false
	}
	ssl := os.Getenv("MINIO_FALLBACK_USE_SSL") != "false" // default true (R2 is TLS)
	n := 0
	for _, s := range stores {
		if s == nil {
			continue
		}
		if err := s.SetFallback(ep, ak, sk, ssl); err != nil {
			slog.Warn("blob migration fallback unavailable", "error", err)
			continue
		}
		n++
	}
	slog.Info("blob migration fallback enabled", "endpoint", ep, "stores", n)
	return n > 0
}

func (bs *BlobStore) SetFallback(endpoint, accessKey, secretKey string, useSSL bool) error {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       useSSL,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return fmt.Errorf("create fallback minio client: %w", err)
	}
	bs.fallback = client
	return nil
}

// NewBlobStore creates a new BlobStore connected to the given MinIO endpoint.
func NewBlobStore(endpoint, accessKey, secretKey string, useSSL bool) (*BlobStore, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       useSSL,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return nil, fmt.Errorf("create minio client: %w", err)
	}
	return &BlobStore{client: client}, nil
}

func (bs *BlobStore) bucketName() string {
	if bs.bucket != "" {
		return bs.bucket
	}
	return blobBucket
}

// EnsureBucket creates the bucket if it does not already exist.
func (bs *BlobStore) EnsureBucket(ctx context.Context) error {
	exists, err := bs.client.BucketExists(ctx, bs.bucketName())
	if err != nil {
		return fmt.Errorf("check bucket: %w", err)
	}
	if exists {
		return nil
	}
	if err := bs.client.MakeBucket(ctx, bs.bucketName(), minio.MakeBucketOptions{}); err != nil {
		return fmt.Errorf("create bucket: %w", err)
	}
	return nil
}

// Ping checks connectivity to MinIO by verifying the messages bucket exists.
func (bs *BlobStore) Ping(ctx context.Context) error {
	_, err := bs.client.BucketExists(ctx, bs.bucketName())
	if err != nil {
		return fmt.Errorf("blob store ping: %w", err)
	}
	return nil
}

// EnsureBucketWithRetry retries EnsureBucket with exponential backoff.
func (bs *BlobStore) EnsureBucketWithRetry(ctx context.Context, maxRetries int) error {
	var err error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err = bs.EnsureBucket(ctx)
		if err == nil {
			return nil
		}
		if attempt < maxRetries {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			slog.Warn("MinIO EnsureBucket failed, retrying", "attempt", attempt+1, "backoff", backoff, "error", err)
			time.Sleep(backoff)
		}
	}
	return fmt.Errorf("ensure bucket after %d attempts: %w", maxRetries+1, err)
}

// Upload stores encrypted message data in MinIO and returns the blob reference key.
func (bs *BlobStore) Upload(ctx context.Context, tenantID, userID, messageID uuid.UUID, data []byte) (string, error) {
	key := fmt.Sprintf("%s/%s/%s", tenantID, userID, messageID)
	reader := bytes.NewReader(data)
	_, err := bs.client.PutObject(ctx, bs.bucketName(), key, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return "", fmt.Errorf("upload blob: %w", err)
	}
	return key, nil
}

// download retrieves encrypted message data from MinIO by blob reference.
// This is unexported to prevent bypassing ownership checks — callers outside
// the package should use DownloadVerified instead.
func (bs *BlobStore) download(ctx context.Context, blobRef string) ([]byte, error) {
	data, err := getFrom(ctx, bs.client, bs.bucketName(), blobRef)
	if err == nil {
		return data, nil
	}
	// On a genuine miss, try the migration fallback (old account) before
	// giving up. Any other error is returned as-is.
	if bs.fallback != nil && errors.Is(err, ErrBlobNotFound) {
		fbData, fbErr := getFrom(ctx, bs.fallback, bs.bucketName(), blobRef)
		if fbErr == nil {
			atomic.AddInt64(&fallbackReadCount, 1)
			slog.Info("blob served from migration fallback", "bucket", bs.bucketName(), "ref", blobRef)
			return fbData, nil
		}
	}
	return nil, err
}

// getFrom performs the actual lazy S3 GET+read against a specific client,
// mapping a NoSuchKey to ErrBlobNotFound. Shared by the primary and fallback
// paths so both classify a missing object identically.
func getFrom(ctx context.Context, client *minio.Client, bucket, blobRef string) ([]byte, error) {
	obj, err := client.GetObject(ctx, bucket, blobRef, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get blob: %w", err)
	}
	defer obj.Close()
	data, err := io.ReadAll(obj)
	if err != nil {
		// MinIO's GetObject is lazy — the actual S3 GET happens here on
		// Read. NoSuchKey/404 from S3 surfaces as ErrorResponse with
		// Code=="NoSuchKey". Wrap as ErrBlobNotFound so callers can map
		// it to a 404 instead of returning a misleading 500.
		errResp := minio.ToErrorResponse(err)
		if errResp.Code == "NoSuchKey" {
			return nil, fmt.Errorf("%w: %s", ErrBlobNotFound, blobRef)
		}
		return nil, fmt.Errorf("read blob: %w", err)
	}
	return data, nil
}

// ErrBlobNotFound is returned by download/DownloadVerified when the
// underlying object doesn't exist in MinIO. Callers should map this
// to a 404 rather than a 500 — the row in the DB outlived the blob,
// which usually means a half-completed delete or a stale ref.
var ErrBlobNotFound = fmt.Errorf("blob not found")

// DownloadVerified retrieves encrypted message data and verifies ownership.
// The blobRef format is "tenantID/userID/messageID". Returns an error if the
// embedded userID doesn't match the requesting user.
func (bs *BlobStore) DownloadVerified(ctx context.Context, blobRef string, requestingUserID uuid.UUID) ([]byte, error) {
	parts := strings.SplitN(blobRef, "/", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid blob reference format")
	}
	embeddedUserID, err := uuid.Parse(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in blob reference: %w", err)
	}
	if embeddedUserID != requestingUserID {
		return nil, fmt.Errorf("blob ownership mismatch")
	}
	return bs.download(ctx, blobRef)
}

// UploadShared stores an E2E-encrypted attachment blob at a shared path that
// is not tied to any specific user. Access control is enforced via the DB
// (attachment records with key wraps). Path: {tenantID}/att/{attachmentID}
func (bs *BlobStore) UploadShared(ctx context.Context, tenantID, attachmentID uuid.UUID, data []byte) (string, error) {
	key := fmt.Sprintf("%s/att/%s", tenantID, attachmentID)
	reader := bytes.NewReader(data)
	_, err := bs.client.PutObject(ctx, bs.bucketName(), key, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return "", fmt.Errorf("upload shared blob: %w", err)
	}
	return key, nil
}

// DownloadShared retrieves an E2E-encrypted attachment blob by blob reference.
// No user-ID ownership check is performed — access control is enforced via the
// DB (only users with a valid key wrap record can decrypt the data).
func (bs *BlobStore) DownloadShared(ctx context.Context, blobRef string) ([]byte, error) {
	return bs.download(ctx, blobRef)
}

// UploadChunk stores a single chunk of a chunked drive file.
// The object key is "{tenantID}/att/{fileID}/{chunkIndex}".
func (bs *BlobStore) UploadChunk(ctx context.Context, tenantID, fileID uuid.UUID, chunkIndex int, data []byte) (string, error) {
	key := fmt.Sprintf("%s/att/%s/%d", tenantID, fileID, chunkIndex)
	reader := bytes.NewReader(data)
	_, err := bs.client.PutObject(ctx, bs.bucketName(), key, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return "", fmt.Errorf("upload chunk: %w", err)
	}
	return key, nil
}

// UploadChunkStream uploads a chunk by streaming directly from the reader
// without buffering the entire chunk in memory. size must be the exact
// number of bytes that will be read.
func (bs *BlobStore) UploadChunkStream(ctx context.Context, tenantID, fileID uuid.UUID, chunkIndex int, reader io.Reader, size int64) (string, error) {
	key := fmt.Sprintf("%s/att/%s/%d", tenantID, fileID, chunkIndex)
	_, err := bs.client.PutObject(ctx, bs.bucketName(), key, reader, size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return "", fmt.Errorf("upload chunk stream: %w", err)
	}
	return key, nil
}

// UploadSharedStream uploads a shared file by streaming from reader.
func (bs *BlobStore) UploadSharedStream(ctx context.Context, tenantID, attachmentID uuid.UUID, reader io.Reader, size int64) (string, error) {
	key := fmt.Sprintf("%s/att/%s", tenantID, attachmentID)
	_, err := bs.client.PutObject(ctx, bs.bucketName(), key, reader, size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return "", fmt.Errorf("upload shared stream: %w", err)
	}
	return key, nil
}

// DownloadChunk retrieves a single chunk of a chunked drive file.
// blobRef is the base key ("{tenantID}/att/{fileID}"); the chunk is
// fetched at "{blobRef}/{chunkIndex}".
func (bs *BlobStore) DownloadChunk(ctx context.Context, blobRef string, chunkIndex int) ([]byte, error) {
	key := fmt.Sprintf("%s/%d", blobRef, chunkIndex)
	return bs.download(ctx, key)
}

// DownloadStream returns a streaming reader for a blob. Caller must Close()
// the returned reader when done. The returned size comes from a Stat call on
// the object.
func (bs *BlobStore) DownloadStream(ctx context.Context, blobRef string) (io.ReadCloser, int64, error) {
	rc, size, err := streamFrom(ctx, bs.client, bs.bucketName(), blobRef)
	if err == nil {
		return rc, size, nil
	}
	if bs.fallback != nil && errors.Is(err, ErrBlobNotFound) {
		frc, fsize, fbErr := streamFrom(ctx, bs.fallback, bs.bucketName(), blobRef)
		if fbErr == nil {
			atomic.AddInt64(&fallbackReadCount, 1)
			slog.Info("blob streamed from migration fallback", "bucket", bs.bucketName(), "ref", blobRef)
			return frc, fsize, nil
		}
	}
	return nil, 0, err
}

// streamFrom opens a streaming reader against a specific client, mapping a
// NoSuchKey (surfaced by the Stat) to ErrBlobNotFound. Shared by the primary
// and fallback paths.
func streamFrom(ctx context.Context, client *minio.Client, bucket, blobRef string) (io.ReadCloser, int64, error) {
	obj, err := client.GetObject(ctx, bucket, blobRef, minio.GetObjectOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("download stream: %w", err)
	}
	info, err := obj.Stat()
	if err != nil {
		obj.Close()
		errResp := minio.ToErrorResponse(err)
		if errResp.Code == "NoSuchKey" {
			return nil, 0, fmt.Errorf("%w: %s", ErrBlobNotFound, blobRef)
		}
		return nil, 0, fmt.Errorf("stat blob: %w", err)
	}
	return obj, info.Size, nil
}

// DownloadChunkStream returns a streaming reader for a single chunk.
// blobRef is the base key ("{tenantID}/att/{fileID}"); the chunk is
// fetched at "{blobRef}/{chunkIndex}". Caller must Close() the reader.
func (bs *BlobStore) DownloadChunkStream(ctx context.Context, blobRef string, chunkIndex int) (io.ReadCloser, int64, error) {
	key := fmt.Sprintf("%s/%d", blobRef, chunkIndex)
	return bs.DownloadStream(ctx, key)
}

// DownloadSharedStream returns a streaming reader for a shared blob.
// No user-ID ownership check is performed. Caller must Close() the reader.
func (bs *BlobStore) DownloadSharedStream(ctx context.Context, blobRef string) (io.ReadCloser, int64, error) {
	return bs.DownloadStream(ctx, blobRef)
}

// Delete removes an encrypted message blob from MinIO by blob reference.
func (bs *BlobStore) Delete(ctx context.Context, blobRef string) error {
	err := bs.client.RemoveObject(ctx, bs.bucketName(), blobRef, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("delete blob: %w", err)
	}
	return nil
}

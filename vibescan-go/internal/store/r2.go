package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/vibescan/vibescan-go/internal/config"
)

// R2 uploads captures to an S3-compatible bucket (Cloudflare R2). It is nil
// when R2 is disabled or misconfigured, in which case captures fall back to
// MongoDB storage.
type R2 struct {
	client *minio.Client
	bucket string
}

// NewR2 constructs an R2 client from config. It returns nil (no error) when R2
// is disabled, matching the Python behavior of signalling fallback via absence.
func NewR2(cfg *config.Config) (*R2, error) {
	if !cfg.R2Enabled {
		return nil, nil
	}
	endpoint := cfg.R2Endpoint
	secure := true
	if u, err := url.Parse(cfg.R2Endpoint); err == nil && u.Host != "" {
		endpoint = u.Host
		secure = u.Scheme != "http"
	}
	opts := &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.R2AccessKey, cfg.R2SecretKey, ""),
		Secure: secure,
	}
	// AWS S3 requires the bucket's region for SigV4 signing; R2/MinIO can
	// auto-discover, so only set it when configured (keeps existing behavior).
	if cfg.R2Region != "" {
		opts.Region = cfg.R2Region
	}
	client, err := minio.New(endpoint, opts)
	if err != nil {
		return nil, err
	}
	return &R2{client: client, bucket: cfg.R2Bucket}, nil
}

// ObjectKey builds the R2 object key for a capture, mirroring
// common/r2_storage.py:build_r2_object_key
// (Format: <octet1>/<octet2>/<ip>-<port>.<ext>).
func ObjectKey(ipStr string, port int, ext string) string {
	ipSafe := strings.ReplaceAll(ipStr, ":", "_")
	sep := "."
	if !strings.Contains(ipSafe, ".") {
		sep = "_"
	}
	parts := strings.Split(ipSafe, sep)
	first, second := "0", "0"
	if len(parts) > 0 {
		first = parts[0]
	}
	if len(parts) > 1 {
		second = parts[1]
	}
	return fmt.Sprintf("%s/%s/%s-%d.%s", first, second, ipSafe, port, ext)
}

// Upload decodes a base64 capture and stores it at the derived object key,
// returning the key on success (mirrors upload_capture_to_r2).
func (r *R2) Upload(ctx context.Context, captureB64, ipStr string, port int, ext string) (string, error) {
	img, err := base64.StdEncoding.DecodeString(captureB64)
	if err != nil {
		return "", err
	}
	key := ObjectKey(ipStr, port, ext)
	contentType := "image/png"
	if ext == "jpg" || ext == "jpeg" {
		contentType = "image/jpeg"
	}
	_, err = r.client.PutObject(ctx, r.bucket, key, bytes.NewReader(img), int64(len(img)),
		minio.PutObjectOptions{
			ContentType:  contentType,
			CacheControl: "public, max-age=31536000, immutable",
		})
	if err != nil {
		return "", err
	}
	return key, nil
}

// Package storage stores Munki package binaries on local disk or S3-compatible storage.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ErrNotFound is returned when an object does not exist.
var ErrNotFound = errors.New("object not found")

// Info describes a stored object.
type Info struct {
	Size    int64
	ModTime time.Time
	ETag    string
}

// ErrNoPresign means the backend serves bytes itself.
var ErrNoPresign = errors.New("presign unsupported")

// Storage is the package blob backend.
type Storage interface {
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	Stat(ctx context.Context, key string) (Info, error)
	// Presign returns a time-limited GET URL. Local storage returns ErrNoPresign.
	Presign(ctx context.Context, key string, ttl time.Duration) (string, error)
}

// New returns the configured backend.
func New(driver, dir, endpoint, bucket, access, secret, region string, ssl bool) (Storage, error) {
	switch driver {
	case "local", "":
		if dir == "" {
			dir = "data"
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		return &Local{Dir: dir}, nil
	case "s3":
		return NewS3(endpoint, bucket, access, secret, region, ssl)
	default:
		return nil, fmt.Errorf("unknown storage driver %q", driver)
	}
}

// Local stores objects under a directory.
type Local struct {
	Dir string
}

// ValidateKey rejects empty keys, traversal, and keys that change when cleaned.
func ValidateKey(key string) error {
	if key == "" || strings.ContainsAny(key, "\\\x00") {
		return fmt.Errorf("invalid storage key")
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+key), "/")
	if cleaned == "" || cleaned == "." || cleaned != key || strings.Contains(cleaned, "..") {
		return fmt.Errorf("invalid storage key")
	}
	return nil
}

func (l *Local) path(key string) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	full := filepath.Join(l.Dir, filepath.FromSlash(key))
	rel, err := filepath.Rel(l.Dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid storage key")
	}
	return full, nil
}

func (l *Local) Put(_ context.Context, key string, r io.Reader, _ int64, _ string) error {
	full, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	tmp := full + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, r)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, full)
}

func (l *Local) Open(_ context.Context, key string) (io.ReadCloser, error) {
	full, err := l.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

func (l *Local) Delete(_ context.Context, key string) error {
	full, err := l.path(key)
	if err != nil {
		return err
	}
	err = os.Remove(full)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (l *Local) Stat(_ context.Context, key string) (Info, error) {
	full, err := l.path(key)
	if err != nil {
		return Info{}, err
	}
	st, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return Info{}, ErrNotFound
		}
		return Info{}, err
	}
	if st.IsDir() {
		return Info{}, ErrNotFound
	}
	sum := sha256.Sum256([]byte(strconv.FormatInt(st.Size(), 10) + ":" + strconv.FormatInt(st.ModTime().UnixNano(), 10)))
	return Info{Size: st.Size(), ModTime: st.ModTime().UTC(), ETag: `"` + hex.EncodeToString(sum[:]) + `"`}, nil
}

func (l *Local) Presign(context.Context, string, time.Duration) (string, error) {
	return "", ErrNoPresign
}

// S3 stores objects in an S3-compatible bucket.
type S3 struct {
	client *minio.Client
	bucket string
}

// NormalizeEndpoint splits an S3 host and whether TLS should be used.
// An explicit http:// or https:// scheme wins over the ssl flag. A path is rejected.
func NormalizeEndpoint(endpoint string, ssl bool) (host string, secure bool, err error) {
	endpoint = strings.TrimSpace(endpoint)
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		secure = true
		endpoint = strings.TrimPrefix(endpoint, "https://")
	case strings.HasPrefix(endpoint, "http://"):
		secure = false
		endpoint = strings.TrimPrefix(endpoint, "http://")
	default:
		secure = ssl
	}
	endpoint = strings.TrimSuffix(endpoint, "/")
	if endpoint == "" || strings.Contains(endpoint, "/") {
		return "", false, fmt.Errorf("s3 endpoint must be host or host:port")
	}
	return endpoint, secure, nil
}

// NewS3 builds a client. endpoint may include a scheme.
func NewS3(endpoint, bucket, access, secret, region string, ssl bool) (*S3, error) {
	host, secure, err := NormalizeEndpoint(endpoint, ssl)
	if err != nil {
		return nil, err
	}
	if bucket == "" {
		return nil, fmt.Errorf("s3 bucket is required")
	}
	client, err := minio.New(host, &minio.Options{
		Creds:  credentials.NewStaticV4(access, secret, ""),
		Secure: secure,
		Region: region,
	})
	if err != nil {
		return nil, err
	}
	return &S3{client: client, bucket: bucket}, nil
}

// EnsureBucket creates the bucket when it is missing.
func (s *S3) EnsureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{})
}

func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{ContentType: contentType})
	return err
}

func (s *S3) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		resp := minio.ToErrorResponse(err)
		if resp.Code == "NoSuchKey" || resp.StatusCode == 404 {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return obj, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

func (s *S3) Stat(ctx context.Context, key string) (Info, error) {
	if err := ValidateKey(key); err != nil {
		return Info{}, err
	}
	st, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		resp := minio.ToErrorResponse(err)
		if resp.Code == "NoSuchKey" || resp.StatusCode == 404 {
			return Info{}, ErrNotFound
		}
		return Info{}, err
	}
	etag := st.ETag
	if etag != "" && !strings.HasPrefix(etag, `"`) {
		etag = `"` + etag + `"`
	}
	return Info{Size: st.Size, ModTime: st.LastModified.UTC(), ETag: etag}, nil
}

func (s *S3) Presign(ctx context.Context, key string, ttl time.Duration) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	u, err := s.client.PresignedGetObject(ctx, s.bucket, key, ttl, nil)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// Package blob is the pluggable package store used by Munki and AutoPkg.
//
// The local driver is usable now. The S3-compatible driver is a deliberate
// stub: the configuration shape is stable, and the implementation lands with
// the Munki repo phase so we do not pretend objects round-trip.
package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Store saves package artifacts (pkgs, icons, AutoPkg outputs).
type Store interface {
	Put(ctx context.Context, key string, r io.Reader) error
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// Config selects a driver. Driver is "local" or "s3".
type Config struct {
	Driver string
	// Dir is the root for the local driver.
	Dir string
	// Endpoint, Bucket, AccessKey, and SecretKey configure the S3 driver.
	Endpoint  string
	Bucket    string
	AccessKey string
	SecretKey string
	Region    string
}

// ErrNotImplemented is returned by drivers that are specified but not built yet.
var ErrNotImplemented = errors.New("blob driver not implemented")

// New returns the configured store.
func New(cfg Config) (Store, error) {
	switch cfg.Driver {
	case "", "local":
		dir := cfg.Dir
		if dir == "" {
			dir = "data/blobs"
		}
		return NewLocal(dir)
	case "s3":
		if cfg.Bucket == "" || cfg.Endpoint == "" {
			return nil, errors.New("s3 blob store requires MC_BLOB_S3_ENDPOINT and MC_BLOB_S3_BUCKET")
		}
		return nil, fmt.Errorf("%w: s3 (endpoint %s, bucket %s) lands in the Munki phase", ErrNotImplemented, cfg.Endpoint, cfg.Bucket)
	default:
		return nil, fmt.Errorf("unknown blob driver %q", cfg.Driver)
	}
}

// Local stores objects on disk.
type Local struct {
	Dir string
}

// NewLocal creates a local store, including the root directory.
func NewLocal(dir string) (*Local, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Local{Dir: dir}, nil
}

func (l *Local) path(key string) (string, error) {
	clean := filepath.Clean("/" + key)
	if strings.Contains(clean, "..") || clean == "/" {
		return "", fmt.Errorf("invalid blob key %q", key)
	}
	return filepath.Join(l.Dir, clean), nil
}

// Put writes an object, replacing any previous value.
func (l *Local) Put(_ context.Context, key string, r io.Reader) error {
	path, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
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
	return os.Rename(tmp, path)
}

// Open returns the object contents.
func (l *Local) Open(_ context.Context, key string) (io.ReadCloser, error) {
	path, err := l.path(key)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

// Delete removes an object. Missing objects are not an error.
func (l *Local) Delete(_ context.Context, key string) error {
	path, err := l.path(key)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

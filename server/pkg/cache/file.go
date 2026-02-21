package cache

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileCache implements Cache using the local filesystem.
// Zero external dependency — suitable for low-traffic or development scenarios.
// Keys are hashed into a two-level directory structure to avoid filesystem limits.
type FileCache struct {
	dir        string
	prefix     string
	defaultTTL time.Duration
	mu         sync.RWMutex
	stopCh     chan struct{}
}

// File format: first 8 bytes = expiration unix timestamp (big-endian int64), rest = payload.
const fileHeaderSize = 8

// NewFileCache creates a filesystem-backed cache.
// dir is the root directory for cached files.
func NewFileCache(dir, prefix string, defaultTTL time.Duration) (*FileCache, error) {
	if dir == "" {
		dir = "data/cache/file"
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("cache: create file cache directory: %w", err)
	}

	fc := &FileCache{
		dir:        dir,
		prefix:     prefix,
		defaultTTL: defaultTTL,
		stopCh:     make(chan struct{}),
	}
	go fc.cleanupLoop()
	return fc, nil
}

// filePath returns a two-level hash path: dir/ab/cd/<hash>
func (fc *FileCache) filePath(key string) string {
	h := sha256.Sum256([]byte(fc.prefix + key))
	hex := fmt.Sprintf("%x", h)
	return filepath.Join(fc.dir, hex[:2], hex[2:4], hex)
}

func (fc *FileCache) Get(_ context.Context, key string) ([]byte, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	path := fc.filePath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("cache: file read error: %w", err)
	}

	if len(data) < fileHeaderSize {
		// Corrupt entry, remove
		_ = os.Remove(path)
		return nil, ErrNotFound
	}

	// Check expiration
	expiresAt := int64(binary.BigEndian.Uint64(data[:fileHeaderSize]))
	if time.Now().Unix() > expiresAt {
		// Expired, lazy delete
		_ = os.Remove(path)
		return nil, ErrNotFound
	}

	return data[fileHeaderSize:], nil
}

func (fc *FileCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = fc.defaultTTL
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	path := fc.filePath(key)

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("cache: file mkdir error: %w", err)
	}

	// Build file content: [8-byte expiration][payload]
	expiresAt := time.Now().Add(ttl).Unix()
	buf := make([]byte, fileHeaderSize+len(value))
	binary.BigEndian.PutUint64(buf[:fileHeaderSize], uint64(expiresAt))
	copy(buf[fileHeaderSize:], value)

	if err := os.WriteFile(path, buf, 0644); err != nil {
		return fmt.Errorf("cache: file write error: %w", err)
	}
	return nil
}

func (fc *FileCache) Delete(_ context.Context, key string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	path := fc.filePath(key)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cache: file delete error: %w", err)
	}
	return nil
}

func (fc *FileCache) Exists(_ context.Context, key string) (bool, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	path := fc.filePath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("cache: file exists error: %w", err)
	}

	if len(data) < fileHeaderSize {
		return false, nil
	}

	expiresAt := int64(binary.BigEndian.Uint64(data[:fileHeaderSize]))
	if time.Now().Unix() > expiresAt {
		return false, nil
	}
	return true, nil
}

func (fc *FileCache) Close() error {
	close(fc.stopCh)
	return nil
}

func (fc *FileCache) Ping(_ context.Context) error {
	// Try creating a temp file to verify write access
	testFile := filepath.Join(fc.dir, ".ping")
	if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
		return fmt.Errorf("cache: file ping error: %w", err)
	}
	_ = os.Remove(testFile)
	return nil
}

// cleanupLoop periodically scans and removes expired cache files.
func (fc *FileCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			fc.cleanup()
		case <-fc.stopCh:
			return
		}
	}
}

func (fc *FileCache) cleanup() {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	now := time.Now().Unix()
	_ = filepath.Walk(fc.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Skip non-cache files
		if info.Name() == ".ping" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil || len(data) < fileHeaderSize {
			_ = os.Remove(path)
			return nil
		}

		expiresAt := int64(binary.BigEndian.Uint64(data[:fileHeaderSize]))
		if now > expiresAt {
			_ = os.Remove(path)
		}
		return nil
	})

	// Remove empty subdirectories
	fc.removeEmptyDirs()
}

// removeEmptyDirs cleans up empty two-level hash directories.
func (fc *FileCache) removeEmptyDirs() {
	entries, err := os.ReadDir(fc.dir)
	if err != nil {
		return
	}
	for _, l1 := range entries {
		if !l1.IsDir() {
			continue
		}
		l1Path := filepath.Join(fc.dir, l1.Name())
		subEntries, err := os.ReadDir(l1Path)
		if err != nil {
			continue
		}
		for _, l2 := range subEntries {
			if !l2.IsDir() {
				continue
			}
			l2Path := filepath.Join(l1Path, l2.Name())
			files, err := os.ReadDir(l2Path)
			if err == nil && len(files) == 0 {
				_ = os.Remove(l2Path)
			}
		}
		// Re-check level-1 after potentially removing level-2
		remaining, err := os.ReadDir(l1Path)
		if err == nil && len(remaining) == 0 {
			_ = os.Remove(l1Path)
		}
	}
}

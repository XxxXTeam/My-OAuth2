package cache

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// BadgerCache implements Cache using BadgerDB (embedded persistent KV store).
// Ideal for single-instance deployments that need persistent cache without external services.
type BadgerCache struct {
	db         *badger.DB
	prefix     string
	defaultTTL time.Duration
}

// NewBadgerCache creates a BadgerDB-backed cache.
// dbPath is the directory where BadgerDB stores its data files.
func NewBadgerCache(dbPath, prefix string, defaultTTL time.Duration) (*BadgerCache, error) {
	if dbPath == "" {
		dbPath = "data/cache/badger"
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}

	// Ensure directory exists
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		return nil, fmt.Errorf("cache: create badger directory: %w", err)
	}

	opts := badger.DefaultOptions(dbPath).
		WithLoggingLevel(badger.WARNING).
		WithNumVersionsToKeep(1).
		WithCompactL0OnClose(true).
		WithValueLogFileSize(64 << 20) // 64MB value log

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("cache: open badger: %w", err)
	}

	bc := &BadgerCache{
		db:         db,
		prefix:     prefix,
		defaultTTL: defaultTTL,
	}

	// Start background GC goroutine to reclaim value log space
	go bc.gcLoop()

	return bc, nil
}

func (bc *BadgerCache) gcLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if bc.db.IsClosed() {
			return
		}
		// Run GC until less than 0.5 of value log space can be reclaimed
		for {
			err := bc.db.RunValueLogGC(0.5)
			if err != nil {
				break
			}
		}
	}
}

func (bc *BadgerCache) key(k string) []byte {
	return []byte(bc.prefix + k)
}

func (bc *BadgerCache) Get(_ context.Context, key string) ([]byte, error) {
	var result []byte
	err := bc.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(bc.key(key))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return ErrNotFound
			}
			return err
		}
		result, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		if err == ErrNotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("cache: badger get error: %w", err)
	}
	return result, nil
}

func (bc *BadgerCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = bc.defaultTTL
	}
	err := bc.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry(bc.key(key), value).WithTTL(ttl)
		return txn.SetEntry(entry)
	})
	if err != nil {
		return fmt.Errorf("cache: badger set error: %w", err)
	}
	return nil
}

func (bc *BadgerCache) Delete(_ context.Context, key string) error {
	err := bc.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(bc.key(key))
	})
	if err != nil && err != badger.ErrKeyNotFound {
		return fmt.Errorf("cache: badger delete error: %w", err)
	}
	return nil
}

func (bc *BadgerCache) Exists(_ context.Context, key string) (bool, error) {
	exists := false
	err := bc.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(bc.key(key))
		if err == nil {
			exists = true
		} else if err == badger.ErrKeyNotFound {
			return nil
		} else {
			return err
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("cache: badger exists error: %w", err)
	}
	return exists, nil
}

func (bc *BadgerCache) Close() error {
	return bc.db.Close()
}

func (bc *BadgerCache) Ping(_ context.Context) error {
	if bc.db.IsClosed() {
		return fmt.Errorf("cache: badger is closed")
	}
	return nil
}

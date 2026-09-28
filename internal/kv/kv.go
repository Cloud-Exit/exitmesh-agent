// Package kv is the small durable key-value store used for agent metadata: alert state,
// log offsets, bundle state, key manifest sequence, cursors.
package kv

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Store is a durable key-value namespace. Writes are durable when they return.
type Store interface {
	Get(key string) ([]byte, bool, error)
	Put(key string, value []byte) error
	Delete(key string) error
	// ForEach visits keys with prefix in ascending order.
	ForEach(prefix string, fn func(key string, value []byte) error) error
	// Batch applies puts (nil value deletes) atomically.
	Batch(ops map[string][]byte) error
}

// Bolt is a Store backed by one bbolt bucket.
type Bolt struct {
	db     *bolt.DB
	bucket []byte
}

// OpenBolt opens (creating) a bbolt file. The caller holds any directory lock.
func OpenBolt(path string) (*bolt.DB, error) {
	return bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second, NoFreelistSync: false})
}

// NewBolt returns a Store over bucket in db, creating the bucket.
func NewBolt(db *bolt.DB, bucket string) (*Bolt, error) {
	b := []byte(bucket)
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(b)
		return err
	}); err != nil {
		return nil, err
	}
	return &Bolt{db: db, bucket: b}, nil
}

func (s *Bolt) Get(key string) ([]byte, bool, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(s.bucket).Get([]byte(key))
		if v != nil {
			out = append([]byte{}, v...)
		}
		return nil
	})
	return out, out != nil, err
}

func (s *Bolt) Put(key string, value []byte) error {
	if value == nil {
		value = []byte{}
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(s.bucket).Put([]byte(key), value) })
}

func (s *Bolt) Delete(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(s.bucket).Delete([]byte(key)) })
}

func (s *Bolt) ForEach(prefix string, fn func(string, []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(s.bucket).Cursor()
		p := []byte(prefix)
		for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
			if err := fn(string(k), append([]byte{}, v...)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Bolt) Batch(ops map[string][]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(s.bucket)
		for k, v := range ops {
			var err error
			if v == nil {
				err = b.Delete([]byte(k))
			} else {
				err = b.Put([]byte(k), v)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Memory is an in-memory Store for tests and ephemeral use.
type Memory struct {
	mu sync.Mutex
	m  map[string][]byte
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{m: map[string][]byte{}} }

func (s *Memory) Get(key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	return append([]byte(nil), v...), ok, nil
}

func (s *Memory) Put(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = append([]byte{}, value...)
	return nil
}

func (s *Memory) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

func (s *Memory) ForEach(prefix string, fn func(string, []byte) error) error {
	s.mu.Lock()
	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	vals := make([][]byte, len(keys))
	for i, k := range keys {
		vals[i] = append([]byte{}, s.m[k]...)
	}
	s.mu.Unlock()
	for i, k := range keys {
		if err := fn(k, vals[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Memory) Batch(ops map[string][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range ops {
		if v == nil {
			delete(s.m, k)
		} else {
			s.m[k] = append([]byte{}, v...)
		}
	}
	return nil
}

// Prefixed scopes a Store under a key prefix.
type Prefixed struct {
	S      Store
	Prefix string
}

func (p Prefixed) Get(k string) ([]byte, bool, error) { return p.S.Get(p.Prefix + k) }
func (p Prefixed) Put(k string, v []byte) error       { return p.S.Put(p.Prefix+k, v) }
func (p Prefixed) Delete(k string) error              { return p.S.Delete(p.Prefix + k) }
func (p Prefixed) ForEach(prefix string, fn func(string, []byte) error) error {
	return p.S.ForEach(p.Prefix+prefix, func(k string, v []byte) error { return fn(strings.TrimPrefix(k, p.Prefix), v) })
}
func (p Prefixed) Batch(ops map[string][]byte) error {
	out := make(map[string][]byte, len(ops))
	for k, v := range ops {
		out[p.Prefix+k] = v
	}
	return p.S.Batch(out)
}

// ErrNotFound is returned by helpers that require a key.
var ErrNotFound = errors.New("kv: not found")

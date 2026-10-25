package imagesbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var cacheName = regexp.MustCompile(`^[a-f0-9]{64}\.json$`)

// cache keeps ready results per digest on disk, evicting the least recently used beyond its entry and byte bounds.
type cache struct {
	dir        string
	maxEntries int
	maxBytes   int64

	mu      sync.Mutex
	entries map[string]*cacheEntry
	bytes   int64
}

type cacheEntry struct {
	size int64
	used time.Time
}

func openCache(dir string, maxEntries int, maxBytes int64) (*cache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("imagesbom: cache dir: %w", err)
	}
	c := &cache{dir: dir, maxEntries: maxEntries, maxBytes: maxBytes, entries: map[string]*cacheEntry{}}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("imagesbom: cache dir: %w", err)
	}
	for _, de := range des {
		p := filepath.Join(dir, de.Name())
		info, err := de.Info()
		if err != nil || !info.Mode().IsRegular() || !cacheName.MatchString(de.Name()) {
			_ = os.RemoveAll(p)
			continue
		}
		c.entries[strings.TrimSuffix(de.Name(), ".json")] = &cacheEntry{size: info.Size(), used: info.ModTime()}
		c.bytes += info.Size()
	}
	c.mu.Lock()
	c.evict()
	c.mu.Unlock()
	return c, nil
}

func (c *cache) path(hex string) string { return filepath.Join(c.dir, hex+".json") }

func (c *cache) has(hex string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries[hex] != nil
}

func (c *cache) get(hex string, now time.Time) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[hex]
	if e == nil {
		return Result{}, false
	}
	b, err := os.ReadFile(c.path(hex))
	var r Result
	if err == nil {
		err = json.Unmarshal(b, &r)
	}
	if err != nil || r.Status != StatusReady || r.hex() != hex {
		c.drop(hex)
		return Result{}, false
	}
	e.used = now
	_ = os.Chtimes(c.path(hex), now, now)
	return r, true
}

func (c *cache) put(r Result, now time.Time) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if int64(len(b)) > c.maxBytes {
		return fmt.Errorf("the inventory of %s is %d bytes, above the %d byte cache bound", r.Digest, len(b), c.maxBytes)
	}
	hex := r.hex()
	tmp, err := os.CreateTemp(c.dir, "put-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), c.path(hex))
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	_ = os.Chtimes(c.path(hex), now, now)
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.entries[hex]; old != nil {
		c.bytes -= old.size
	}
	c.entries[hex] = &cacheEntry{size: int64(len(b)), used: now}
	c.bytes += int64(len(b))
	c.evict()
	return nil
}

func (c *cache) drop(hex string) {
	if e := c.entries[hex]; e != nil {
		c.bytes -= e.size
		delete(c.entries, hex)
	}
	_ = os.Remove(c.path(hex))
}

// evict runs under mu.
func (c *cache) evict() {
	if len(c.entries) <= c.maxEntries && c.bytes <= c.maxBytes {
		return
	}
	keys := make([]string, 0, len(c.entries))
	for k := range c.entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := c.entries[keys[i]], c.entries[keys[j]]
		if !a.used.Equal(b.used) {
			return a.used.Before(b.used)
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		if len(c.entries) <= c.maxEntries && c.bytes <= c.maxBytes {
			return
		}
		c.drop(k)
	}
}

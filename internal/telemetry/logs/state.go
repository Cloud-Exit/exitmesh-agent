package logs

import (
	"bytes"
	"encoding/json"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

// fileState is a persisted file position; Pending maps a CRI stream to where its open partial group starts.
type fileState struct {
	Dev     uint64           `json:"dev"`
	Ino     uint64           `json:"ino"`
	Name    string           `json:"name"`
	Offset  int64            `json:"off"`
	Size    int64            `json:"size"`
	FPLen   int              `json:"fpn"`
	FPSum   uint64           `json:"fp"`
	Pending map[string]int64 `json:"pending,omitempty"`
}

func (fs fileState) id() fileID      { return fileID{fs.Dev, fs.Ino} }
func (fs fileState) fp() fingerprint { return fingerprint{fs.FPLen, fs.FPSum} }

func (fs fileState) start() int64 {
	s := fs.Offset
	for _, p := range fs.Pending {
		s = min(s, p)
	}
	return s
}

type streamState struct {
	Files      []fileState       `json:"files"`
	Rotated    map[string]string `json:"rotated,omitempty"`
	PrefixLost []string          `json:"lost,omitempty"`
}

func stateOf(t *tracked, pending map[string]int64) fileState {
	if t.restored != nil && t.readPos < t.replayUntil {
		return *t.restored
	}
	fs := fileState{Dev: t.id.dev, Ino: t.id.ino, Name: t.name, Offset: t.offset, Size: t.size, FPLen: t.fp.n, FPSum: t.fp.sum}
	if len(pending) > 0 {
		fs.Pending = pending
	}
	return fs
}

// checkpointer writes changed stream states to the store in one batch.
type checkpointer struct {
	store   kv.Store
	written map[string][]byte
}

func newCheckpointer(s kv.Store, prefix string) (*checkpointer, map[string]*streamState, error) {
	c := &checkpointer{store: s, written: map[string][]byte{}}
	loaded := map[string]*streamState{}
	if s == nil {
		return c, loaded, nil
	}
	err := s.ForEach(prefix, func(k string, v []byte) error {
		var st streamState
		if json.Unmarshal(v, &st) == nil {
			loaded[k] = &st
			c.written[k] = v
		}
		return nil
	})
	return c, loaded, err
}

func (c *checkpointer) commit(states map[string]*streamState, deleted []string) error {
	ops := map[string][]byte{}
	for k, st := range states {
		b, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if old, ok := c.written[k]; ok && bytes.Equal(old, b) {
			continue
		}
		ops[k] = b
	}
	for _, k := range deleted {
		if _, ok := c.written[k]; ok {
			ops[k] = nil
		}
	}
	if len(ops) == 0 || c.store == nil {
		return nil
	}
	if err := c.store.Batch(ops); err != nil {
		return err
	}
	for k, v := range ops {
		if v == nil {
			delete(c.written, k)
		} else {
			c.written[k] = v
		}
	}
	return nil
}

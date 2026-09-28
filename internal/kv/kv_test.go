package kv

import (
	"path/filepath"
	"testing"
)

func exercise(t *testing.T, s Store) {
	t.Helper()
	if err := s.Put("a/1", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.Batch(map[string][]byte{"a/2": []byte("y"), "b/1": []byte("z"), "a/1": nil}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get("a/1"); ok {
		t.Fatal("batch delete failed")
	}
	var keys []string
	if err := s.ForEach("a/", func(k string, v []byte) error { keys = append(keys, k+"="+string(v)); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "a/2=y" {
		t.Fatalf("foreach %v", keys)
	}
	p := Prefixed{S: s, Prefix: "b/"}
	if v, ok, _ := p.Get("1"); !ok || string(v) != "z" {
		t.Fatal("prefixed get")
	}
	if err := s.Delete("b/1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := p.Get("1"); ok {
		t.Fatal("delete")
	}
}

func TestMemory(t *testing.T) { exercise(t, NewMemory()) }

func TestBolt(t *testing.T) {
	db, err := OpenBolt(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := NewBolt(db, "meta")
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, s)
}

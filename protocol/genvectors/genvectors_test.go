package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCommittedVectorsUpToDate(t *testing.T) {
	files := generate()
	if len(files) != 6 {
		t.Fatalf("generated %d files", len(files))
	}
	for name, want := range files {
		have, err := os.ReadFile(filepath.Join("..", "vectors", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(have, want) {
			t.Errorf("%s is out of date: run go run ./protocol/genvectors", name)
		}
	}
	again := generate()
	for name, b := range files {
		if !bytes.Equal(again[name], b) {
			t.Errorf("%s is not deterministic", name)
		}
	}
}

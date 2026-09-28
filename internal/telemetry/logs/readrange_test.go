package logs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func rangeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	d := containerDir(t, root, "shop", "api-1", "u1", "api")
	var gz, rot, act string
	for i := 1; i <= 15; i++ {
		l := cri(i, "stdout", "F", fmt.Sprintf("line-%02d", i)) + cri(i, "stderr", "F", fmt.Sprintf("err-%02d", i))
		switch {
		case i <= 5:
			gz += l
		case i <= 10:
			rot += l
		default:
			act += l
		}
	}
	act += cri(16, "stdout", "P", "joined-") + cri(16, "stdout", "F", "line")
	appendTo(t, filepath.Join(d, "0.log.20260901-120005"), gz)
	gzipAndRemove(t, filepath.Join(d, "0.log.20260901-120005"))
	appendTo(t, filepath.Join(d, "0.log.20260901-120010"), rot)
	appendTo(t, filepath.Join(d, "0.log"), act)
	o := containerDir(t, root, "other", "db-1", "u2", "db")
	appendTo(t, filepath.Join(o, "0.log"), cri(12, "stdout", "F", "other ns"))
	mt := []struct {
		p string
		t time.Time
	}{
		{filepath.Join(d, "0.log.20260901-120005.gz"), ts(5)},
		{filepath.Join(d, "0.log.20260901-120010"), ts(10)},
		{filepath.Join(d, "0.log"), ts(16)},
		{filepath.Join(o, "0.log"), ts(12)},
	}
	for _, m := range mt {
		if err := os.Chtimes(m.p, m.t, m.t); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestReadRangeBounds(t *testing.T) {
	root := rangeFixture(t)
	sel := func(l map[string]string) bool { return l["namespace"] == "shop" && l["stream"] == "stdout" }
	res, err := ReadRange(context.Background(), root, sel, ts(3), ts(16), RangeOptions{Node: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range res.Lines {
		got = append(got, l.Text)
	}
	want := []string{"line-03", "line-04", "line-05", "line-06", "line-07", "line-08", "line-09", "line-10", "line-11", "line-12", "line-13", "line-14", "line-15", "joined-line"}
	eq(t, got, want)
	if res.Truncated || res.ScanLimited || res.FilesRead != 3 || res.Lines[0].Labels["node"] != "n1" || res.Lines[0].Labels["stream"] != "stdout" {
		t.Fatalf("result %+v", res)
	}

	res, err = ReadRange(context.Background(), root, sel, ts(7), ts(20), RangeOptions{MaxLines: 3})
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	for _, l := range res.Lines {
		got = append(got, l.Text)
	}
	eq(t, got, []string{"line-14", "line-15", "joined-line"})
	if !res.Truncated || res.Omitted != 7 || res.FilesRead != 2 {
		t.Fatalf("limited result %+v", res)
	}

	res, err = ReadRange(context.Background(), root, sel, ts(0), ts(20), RangeOptions{MaxBytes: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 2 || res.Lines[0].Text != "line-15" || res.Lines[1].Text != "joined-line" || !res.Truncated {
		t.Fatalf("byte limited %+v", res.Lines)
	}

	res, err = ReadRange(context.Background(), root, sel, ts(0), ts(20), RangeOptions{MaxScanBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ScanLimited || res.FilesRead != 1 || res.BytesScanned < 100 {
		t.Fatalf("scan limited %+v", res)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadRange(ctx, root, sel, ts(0), ts(20), RangeOptions{}); err == nil {
		t.Fatal("canceled read succeeded")
	}
	if res, err := ReadRange(context.Background(), filepath.Join(root, "missing"), sel, ts(0), ts(20), RangeOptions{}); err != nil || len(res.Lines) != 0 {
		t.Fatalf("missing root: %v %+v", err, res)
	}
}

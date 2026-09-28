package journal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

const baseRT = 1_700_000_000_000_000

func id(b byte) ID128 {
	var v ID128
	for i := range v {
		v[i] = b + byte(i)
	}
	return v
}

func opts(compact, keyed bool, comp compression, file byte, seq *uint64) writerOptions {
	return writerOptions{compact: compact, keyed: keyed, comp: comp, fileID: id(file), machineID: id(0x40), bootID: id(0x80), seqnumID: id(0xc0), seq: seq}
}

func entryFields(i int) []string {
	return []string{
		fmt.Sprintf("MESSAGE=request %d handled %s", i, strings.Repeat("payload ", i%30)),
		"PRIORITY=" + strconv.Itoa(i%8),
		"_TRANSPORT=journal",
		fmt.Sprintf("_SYSTEMD_UNIT=svc%d.service", i%5),
		"SYSLOG_IDENTIFIER=svc",
		"_HOSTNAME=web-1",
		fmt.Sprintf("BINARY=\x00\x01\n%d", i%3),
	}
}

func wantFields(i int) map[string]string {
	out := map[string]string{}
	for _, f := range entryFields(i) {
		k, v, _ := strings.Cut(f, "=")
		out[k] = v
	}
	return out
}

func fill(w *testWriter, from, to int, step uint64) {
	for i := from; i < to; i++ {
		w.append(baseRT+uint64(i)*step, 5_000_000+uint64(i), entryFields(i)...)
	}
}

func readAll(t *testing.T, r *Reader) []Entry {
	t.Helper()
	var out []Entry
	for {
		e, ok := r.Next()
		if !ok {
			return out
		}
		out = append(out, e)
	}
}

func mustFlush(t *testing.T, w *testWriter) {
	t.Helper()
	if err := w.flush(); err != nil {
		t.Fatal(err)
	}
}

func mustOpen(t *testing.T, o Options) *Reader {
	t.Helper()
	r, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

var variants = []struct {
	name    string
	compact bool
	keyed   bool
	comp    compression
	header  int
}{
	{"regular-jenkins", false, false, compNone, 272},
	{"regular-keyed-xz", false, true, compXZ, 272},
	{"compact-keyed-zstd", true, true, compZSTD, 272},
	{"compact-keyed-lz4", true, true, compLZ4, 272},
	{"regular-v246-lz4", false, false, compLZ4, 256},
}

func writeVariant(t *testing.T, dir string, i int) *testWriter {
	v := variants[i]
	o := opts(v.compact, v.keyed, v.comp, byte(0x10*i+1), nil)
	o.headerSize = v.header
	w := newTestWriter(filepath.Join(dir, v.name+".journal"), o)
	fill(w, 0, 300, 1000)
	w.state = stateArchived
	mustFlush(t, w)
	return w
}

func compressedObjects(w *testWriter) int {
	n := 0
	for off := uint64(w.o.headerSize); off < uint64(len(w.buf)); {
		size := w.u64(off + 8)
		if w.buf[off] == objData && w.buf[off+1] != 0 {
			n++
		}
		off += (size + 7) &^ 7
	}
	return n
}

func TestHashVectors(t *testing.T) {
	if got := jenkins64([]byte("Four score and seven years ago")) >> 32; got != 0x17770551 {
		t.Fatalf("lookup3 vector: %x", got)
	}
	if got := jenkins64(nil); got != 0xdeadbeefdeadbeef {
		t.Fatalf("empty lookup3: %x", got)
	}
	var key [16]byte
	msg := make([]byte, 15)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range msg {
		msg[i] = byte(i)
	}
	if got := siphash24(msg, key); got != 0xa129ca6149be45e5 {
		t.Fatalf("siphash vector: %x", got)
	}
}

func TestReadEveryFormatVariant(t *testing.T) {
	for i, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			dir := t.TempDir()
			w := writeVariant(t, dir, i)
			if v.comp != compNone && compressedObjects(w) == 0 {
				t.Fatal("fixture has no compressed data objects")
			}
			r := mustOpen(t, Options{Dirs: []string{dir}})
			got := readAll(t, r)
			if len(got) != 300 {
				t.Fatalf("read %d entries, want 300 (errors %v)", len(got), r.FileErrors())
			}
			for n, e := range got {
				if !reflect.DeepEqual(e.Fields, wantFields(n)) {
					t.Fatalf("entry %d fields %q, want %q", n, e.Fields, wantFields(n))
				}
				if e.Realtime != time.UnixMicro(baseRT+int64(n)*1000) || e.Cursor.Seqnum != uint64(n+1) || e.Cursor.SeqnumID != id(0xc0) {
					t.Fatalf("entry %d at %v cursor %v", n, e.Realtime, e.Cursor)
				}
			}
			if len(r.FileErrors()) != 0 {
				t.Fatalf("errors %v", r.FileErrors())
			}
			if len(r.files) != 0 {
				t.Fatal("fully read archived file kept open")
			}
		})
	}
}

func TestSystemdAcceptsFixtures(t *testing.T) {
	jc, err := exec.LookPath("journalctl")
	if err != nil {
		t.Skip("journalctl not installed; fixtures are validated where it is")
	}
	dir := t.TempDir()
	for i := range variants {
		w := writeVariant(t, dir, i)
		out, err := exec.Command(jc, "--file="+w.path, "--verify").CombinedOutput()
		if err != nil {
			t.Fatalf("%s: journalctl --verify: %v\n%s", variants[i].name, err, out)
		}
		out, err = exec.Command(jc, "--file="+w.path, "-o", "export", "--no-pager").Output()
		if err != nil {
			t.Fatalf("%s: export: %v", variants[i].name, err)
		}
		if n := strings.Count(string(out), "__CURSOR="); n != 300 {
			t.Fatalf("%s: journalctl read %d entries", variants[i].name, n)
		}
		if !strings.Contains(string(out), "MESSAGE=request 299 handled "+strings.Repeat("payload ", 299%30)) {
			t.Fatalf("%s: journalctl did not decode the last message", variants[i].name)
		}
	}
}

func TestMergeAcrossFilesInRealtimeOrder(t *testing.T) {
	root := t.TempDir()
	machine := filepath.Join(root, id(0x40).String())
	if err := os.MkdirAll(machine, 0o755); err != nil {
		t.Fatal(err)
	}
	seq := new(uint64)
	sys := newTestWriter(filepath.Join(machine, "system.journal"), opts(true, true, compZSTD, 1, seq))
	usr := newTestWriter(filepath.Join(machine, "user-1000.journal"), opts(true, true, compNone, 2, seq))
	for i := 0; i < 100; i++ {
		w := sys
		if i%3 == 0 {
			w = usr
		}
		w.append(baseRT+uint64(i)*10, uint64(i), entryFields(i)...)
	}
	other := newTestWriter(filepath.Join(root, "remote.journal"), writerOptions{fileID: id(3), machineID: id(0x50), bootID: id(0x90), seqnumID: id(0xa0)})
	for i := 0; i < 20; i++ {
		other.append(baseRT+uint64(i)*50+5, uint64(i), "MESSAGE=remote "+strconv.Itoa(i))
	}
	mustFlush(t, sys)
	mustFlush(t, usr)
	mustFlush(t, other)
	if err := os.WriteFile(filepath.Join(machine, "notes.txt"), []byte("not a journal"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := mustOpen(t, Options{Dirs: []string{root, filepath.Join(root, "missing")}})
	got := readAll(t, r)
	if len(got) != 120 {
		t.Fatalf("read %d entries, want 120", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].Realtime.Before(got[i-1].Realtime) {
			t.Fatalf("entry %d out of realtime order", i)
		}
	}
	local := 0
	for _, e := range got {
		if e.Cursor.SeqnumID == id(0xc0) {
			if !reflect.DeepEqual(e.Fields, wantFields(local)) {
				t.Fatalf("local entry %d fields %q", local, e.Fields)
			}
			local++
		}
	}
	if local != 100 {
		t.Fatalf("local entries %d", local)
	}
}

func TestCursorResume(t *testing.T) {
	dir := t.TempDir()
	seq := new(uint64)
	w := newTestWriter(filepath.Join(dir, "system.journal"), opts(false, true, compXZ, 1, seq))
	fill(w, 0, 300, 1000)
	mustFlush(t, w)
	other := newTestWriter(filepath.Join(dir, "other.journal"), writerOptions{fileID: id(9), bootID: id(0x90), seqnumID: id(0xa0), machineID: id(0x50)})
	other.append(baseRT+50_500, 1, "MESSAGE=other early")
	other.append(baseRT+250_500, 2, "MESSAGE=other late")
	mustFlush(t, other)
	store := kv.NewMemory()
	r := mustOpen(t, Options{Dirs: []string{dir}, Store: store})
	var first []Entry
	for len(first) < 101 {
		e, ok := r.Next()
		if !ok {
			t.Fatal("ran out of entries")
		}
		first = append(first, e)
	}
	if first[len(first)-1].Fields["MESSAGE"] != wantFields(99)["MESSAGE"] {
		t.Fatalf("101st entry %q", first[len(first)-1].Fields["MESSAGE"])
	}
	if err := r.SaveCursor(); err != nil {
		t.Fatal(err)
	}
	b, ok, _ := store.Get(DefaultCursorKey)
	if !ok || string(b) != first[len(first)-1].Cursor.String() {
		t.Fatalf("stored cursor %q", b)
	}
	r.Close()
	r2 := mustOpen(t, Options{Dirs: []string{dir}, Store: store})
	rest := readAll(t, r2)
	if len(rest) != 201 {
		t.Fatalf("resumed %d entries, want 201", len(rest))
	}
	if rest[0].Fields["MESSAGE"] != wantFields(100)["MESSAGE"] {
		t.Fatalf("resume started at %q", rest[0].Fields["MESSAGE"])
	}
	late := 0
	for _, e := range rest {
		if e.Fields["MESSAGE"] == "other early" {
			t.Fatal("entry of another sequence domain before the cursor redelivered")
		}
		if e.Fields["MESSAGE"] == "other late" {
			late++
		}
	}
	if late != 1 {
		t.Fatal("entry of another sequence domain after the cursor missing")
	}
	if c, ok := r2.Cursor(); !ok || c.Seqnum != 300 {
		t.Fatalf("cursor after resume %v", c)
	}
}

func TestSinceWithoutCursor(t *testing.T) {
	dir := t.TempDir()
	old := newTestWriter(filepath.Join(dir, "system@old.journal"), opts(false, true, compNone, 1, nil))
	fill(old, 0, 50, 1000)
	old.state = stateArchived
	mustFlush(t, old)
	w := newTestWriter(filepath.Join(dir, "system.journal"), opts(false, true, compNone, 2, old.o.seq))
	fill(w, 50, 300, 1000)
	mustFlush(t, w)
	r := mustOpen(t, Options{Dirs: []string{dir}, Since: time.UnixMicro(baseRT + 200*1000)})
	got := readAll(t, r)
	if len(got) != 100 || got[0].Fields["MESSAGE"] != wantFields(200)["MESSAGE"] {
		t.Fatalf("since: %d entries, first %q", len(got), got[0].Fields["MESSAGE"])
	}
}

func TestFollowGrowthAndRotation(t *testing.T) {
	dir := t.TempDir()
	seq := new(uint64)
	w := newTestWriter(filepath.Join(dir, "system.journal"), opts(true, true, compLZ4, 1, seq))
	fill(w, 0, 10, 1000)
	mustFlush(t, w)
	r := mustOpen(t, Options{Dirs: []string{dir}})
	if n := len(readAll(t, r)); n != 10 {
		t.Fatalf("initial %d", n)
	}
	fill(w, 10, 15, 1000)
	mustFlush(t, w)
	if _, ok := r.Next(); ok {
		t.Fatal("appended entry visible before Refresh")
	}
	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, r)
	if len(got) != 5 || got[0].Fields["MESSAGE"] != wantFields(10)["MESSAGE"] {
		t.Fatalf("growth: %d entries", len(got))
	}
	fill(w, 15, 17, 1000)
	w.state = stateArchived
	mustFlush(t, w)
	archived := filepath.Join(dir, "system@"+id(0xc0).String()+"-0000000000000001-0005f5e100000000.journal")
	if err := os.Rename(w.path, archived); err != nil {
		t.Fatal(err)
	}
	nw := newTestWriter(filepath.Join(dir, "system.journal"), opts(true, true, compLZ4, 2, seq))
	fill(nw, 17, 20, 1000)
	mustFlush(t, nw)
	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	got = readAll(t, r)
	var msgs []string
	for _, e := range got {
		msgs = append(msgs, e.Fields["MESSAGE"])
	}
	if len(got) != 5 || got[0].Fields["MESSAGE"] != wantFields(15)["MESSAGE"] || got[4].Fields["MESSAGE"] != wantFields(19)["MESSAGE"] {
		t.Fatalf("after rotation: %q", msgs)
	}
	if len(r.files) != 1 || r.files[0].obj.h.fileID != id(2) {
		t.Fatal("archived file not closed after it was fully read")
	}
	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	if extra := readAll(t, r); len(extra) != 0 {
		t.Fatalf("rescan re-read %d entries of the rotated file", len(extra))
	}
}

func TestDeletedFileStillReadThroughOpenHandle(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(filepath.Join(dir, "system@x.journal"), opts(false, true, compNone, 1, nil))
	fill(w, 0, 20, 1000)
	w.state = stateArchived
	mustFlush(t, w)
	r := mustOpen(t, Options{Dirs: []string{dir}})
	if err := os.Remove(w.path); err != nil {
		t.Fatal(err)
	}
	if n := len(readAll(t, r)); n != 20 {
		t.Fatalf("read %d entries from a vacuumed file", n)
	}
}

func TestPartialWriteStallsUntilComplete(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(filepath.Join(dir, "system.journal"), opts(false, true, compNone, 1, nil))
	fill(w, 0, 10, 1000)
	mustFlush(t, w)
	full := append([]byte(nil), w.buf...)
	fill(w, 10, 12, 1000)
	mustFlush(t, w)
	if err := os.Truncate(w.path, int64(len(full))+64); err != nil {
		t.Fatal(err)
	}
	r := mustOpen(t, Options{Dirs: []string{dir}})
	if n := len(readAll(t, r)); n != 10 {
		t.Fatalf("read %d entries before the torn tail", n)
	}
	if len(r.FileErrors()) != 0 {
		t.Fatalf("torn tail of an online file reported as corruption: %v", r.FileErrors())
	}
	mustFlush(t, w)
	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, r); len(got) != 2 || got[1].Fields["MESSAGE"] != wantFields(11)["MESSAGE"] {
		t.Fatalf("after completion: %d", len(got))
	}
}

func TestCorruptAndUnsupportedFilesAreReportedAndSkipped(t *testing.T) {
	dir := t.TempDir()
	good := newTestWriter(filepath.Join(dir, "good.journal"), opts(false, true, compNone, 1, nil))
	fill(good, 0, 5, 1000)
	mustFlush(t, good)
	if err := os.WriteFile(filepath.Join(dir, "garbage.journal"), []byte(strings.Repeat("x", 400)), 0o644); err != nil {
		t.Fatal(err)
	}
	future := newTestWriter(filepath.Join(dir, "future.journal"), opts(false, true, compNone, 2, nil))
	fill(future, 0, 3, 1000)
	mustFlush(t, future)
	b, _ := os.ReadFile(future.path)
	b[12] |= 1 << 7
	os.WriteFile(future.path, b, 0o644)
	broken := newTestWriter(filepath.Join(dir, "broken.journal~"), opts(false, true, compNone, 3, nil))
	fill(broken, 0, 6, 1000)
	broken.state = stateArchived
	e3 := broken.u64(broken.entryArray + 24 + 3*8)
	broken.buf[e3] = 7
	mustFlush(t, broken)

	r := mustOpen(t, Options{Dirs: []string{dir}})
	got := readAll(t, r)
	if len(got) != 5+3 {
		t.Fatalf("read %d entries, want the good file plus the intact prefix of the broken one", len(got))
	}
	errs := r.FileErrors()
	if !errors.Is(errs[filepath.Join(dir, "garbage.journal")], ErrCorrupt) || !errors.Is(errs[future.path], ErrUnsupported) || !errors.Is(errs[broken.path], ErrCorrupt) {
		t.Fatalf("file errors %v", errs)
	}
	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	if extra := readAll(t, r); len(extra) != 0 {
		t.Fatalf("refresh re-read %d entries", len(extra))
	}
}

func TestOversizedDataObjectIsSkipped(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(filepath.Join(dir, "system.journal"), opts(false, true, compNone, 1, nil))
	w.append(baseRT, 1, "MESSAGE="+strings.Repeat("y", 4000), "PRIORITY=3")
	w.append(baseRT+1, 2, "MESSAGE=small", "PRIORITY=3")
	mustFlush(t, w)
	r := mustOpen(t, Options{Dirs: []string{dir}, MaxObjectBytes: 1024})
	got := readAll(t, r)
	if len(got) != 2 {
		t.Fatalf("read %d entries (errors %v)", len(got), r.FileErrors())
	}
	if _, ok := got[0].Fields["MESSAGE"]; ok || got[0].Fields["PRIORITY"] != "3" || got[1].Message() != "small" {
		t.Fatalf("fields %q %q", got[0].Fields, got[1].Fields)
	}
}

func TestFollowPersistsCursorAndStops(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(filepath.Join(dir, "system.journal"), opts(true, true, compZSTD, 1, nil))
	fill(w, 0, 3, 1000)
	mustFlush(t, w)
	store := kv.NewMemory()
	r := mustOpen(t, Options{Dirs: []string{dir}, Store: store, PollInterval: 5 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var got []string
	err := r.Follow(ctx, func(e Entry) error {
		got = append(got, e.Message())
		if len(got) == 3 {
			fill(w, 3, 6, 1000)
			if err := w.flush(); err != nil {
				return err
			}
		}
		if len(got) == 6 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || len(got) != 6 {
		t.Fatalf("follow: %v with %d entries", err, len(got))
	}
	b, _, _ := store.Get(DefaultCursorKey)
	c, err := ParseCursor(string(b))
	if err != nil || c.Seqnum != 6 {
		t.Fatalf("persisted cursor %q %v", b, err)
	}

	fill(w, 6, 8, 1000)
	mustFlush(t, w)
	r.Close()
	r2 := mustOpen(t, Options{Dirs: []string{dir}, Store: store, PollInterval: 5 * time.Millisecond})
	boom := errors.New("sink full")
	calls := 0
	err = r2.Follow(context.Background(), func(e Entry) error {
		calls++
		if calls == 2 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) {
		t.Fatalf("follow error %v", err)
	}
	b, _, _ = store.Get(DefaultCursorKey)
	if c, _ := ParseCursor(string(b)); c.Seqnum != 7 {
		t.Fatalf("cursor after a failed delivery %q, want the entry before it", b)
	}
}

func TestLabelsAndCursorSyntax(t *testing.T) {
	e := Entry{Fields: map[string]string{"_SYSTEMD_UNIT": "nginx.service", "SYSLOG_IDENTIFIER": "nginx", "PRIORITY": "3", "_TRANSPORT": "stdout", "MESSAGE": "boom", "_PID": "12"}}
	want := map[string]string{"unit": "nginx.service", "syslog_identifier": "nginx", "priority": "3", "transport": "stdout"}
	if !reflect.DeepEqual(e.Labels(), want) || e.Message() != "boom" {
		t.Fatalf("labels %v", e.Labels())
	}
	if l := (Entry{Fields: map[string]string{"MESSAGE": "x"}}).Labels(); len(l) != 0 {
		t.Fatalf("absent fields produced labels %v", l)
	}
	c := Cursor{SeqnumID: id(0xc0), Seqnum: 0x12b, Realtime: 0x60a241822cc10}
	p, err := ParseCursor(c.String() + ";b=808182838485868788898a8b8c8d8e8f;x=64a9147fd5891055")
	if err != nil || p != c {
		t.Fatalf("round trip %v %v", p, err)
	}
	for _, bad := range []string{"", "s=zz;i=1;t=1", "s=" + id(1).String() + ";i=1", "s=" + id(1).String() + ";i=q;t=1", "garbage"} {
		if _, err := ParseCursor(bad); err == nil {
			t.Fatalf("cursor %q accepted", bad)
		}
	}
	store := kv.NewMemory()
	store.Put(DefaultCursorKey, []byte("broken"))
	if _, err := Open(Options{Dirs: []string{t.TempDir()}, Store: store}); err == nil {
		t.Fatal("malformed stored cursor accepted")
	}
}

func TestEntryArrayGrowthAndSeekEnd(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(filepath.Join(dir, "system.journal"), opts(true, true, compNone, 1, nil))
	for i := 0; i < 1000; i++ {
		w.append(baseRT+uint64(i), uint64(i), "MESSAGE=m"+strconv.Itoa(i))
	}
	mustFlush(t, w)
	if w.nArrays < 4 {
		t.Fatalf("only %d entry arrays", w.nArrays)
	}
	store := kv.NewMemory()
	store.Put(DefaultCursorKey, []byte(Cursor{SeqnumID: id(0xc0), Seqnum: 1000, Realtime: baseRT + 999}.String()))
	r := mustOpen(t, Options{Dirs: []string{dir}, Store: store})
	if len(r.files) != 1 || !r.files[0].finished() {
		t.Fatal("file covered by the cursor not positioned at its end")
	}
	w.append(baseRT+5000, 5000, "MESSAGE=after")
	mustFlush(t, w)
	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, r); len(got) != 1 || got[0].Message() != "after" {
		t.Fatalf("after seek to end: %v", got)
	}
}

func TestFileFailingAtOpenIsRetriedWhenItChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "system.journal")
	if err := os.WriteFile(path, []byte("LPKSHH"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := mustOpen(t, Options{Dirs: []string{dir}})
	if !errors.Is(r.FileErrors()[path], ErrCorrupt) {
		t.Fatalf("errors %v", r.FileErrors())
	}
	if err := r.Refresh(); err != nil || len(readAll(t, r)) != 0 {
		t.Fatal("unchanged broken file re-read")
	}
	w := newTestWriter(path, opts(false, true, compNone, 1, nil))
	fill(w, 0, 4, 1000)
	mustFlush(t, w)
	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, r); len(got) != 4 || len(r.FileErrors()) != 0 {
		t.Fatalf("after the header was written: %d entries, errors %v", len(got), r.FileErrors())
	}
}

func TestPayloadDecodingErrors(t *testing.T) {
	d, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	o := &objects{maxBytes: 1024, zstd: d}
	w := newTestWriter(filepath.Join(t.TempDir(), "x.journal"), writerOptions{comp: compLZ4})
	big := []byte("MESSAGE=" + strings.Repeat("z", 5000))
	for _, c := range []compression{compXZ, compLZ4, compZSTD} {
		w.o.comp = c
		enc, flag := w.compress(big)
		if flag == 0 {
			t.Fatalf("compression %d did not compress", c)
		}
		if _, err := o.payload(enc, flag); !errors.Is(err, errTooLarge) {
			t.Fatalf("compression %d over the limit: %v", c, err)
		}
		if _, err := o.payload(append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}, enc[8:]...), flag); err == nil {
			t.Fatalf("compression %d accepted a damaged payload", c)
		}
	}
	if _, err := o.payload([]byte("abc"), objCompressedXZ|objCompressedLZ4); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("several flags: %v", err)
	}
	if _, err := o.payload([]byte{1, 2}, objCompressedLZ4); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short lz4: %v", err)
	}
}

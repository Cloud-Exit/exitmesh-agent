package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cloud-exit/exitmesh-agent/internal/spool"
)

// fsOps are the ownership syscalls of prepare-state, replaceable in tests that cannot chown.
type fsOps struct {
	chown func(path string, uid, gid int) error
	chmod func(path string, mode os.FileMode) error
}

var stateFS = fsOps{chown: os.Lchown, chmod: os.Chmod}

// mountInfo is read to decide whether the state directory is a mount point.
var mountInfo = "/proc/self/mountinfo"

func prepareStateCmd(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("prepare-state", stderr)
	dir := fs.String("dir", "", "state directory")
	uid := fs.Int("uid", -1, "owner user ID")
	gid := fs.Int("gid", -1, "owner group ID")
	if err := parse(fs, args, "dir"); err != nil {
		return err
	}
	if *uid < 0 || *gid < 0 {
		return fmt.Errorf("%w: --uid and --gid are required", errUsage)
	}
	d, err := stateDir(*dir)
	if err != nil {
		return err
	}
	changed, err := prepareState(stateFS, d, *uid, *gid)
	if err != nil {
		return err
	}
	if changed {
		fmt.Fprintf(stdout, "%s: owner %d:%d, mode 0700\n", d, *uid, *gid)
	} else {
		fmt.Fprintf(stdout, "%s: already owned by %d:%d with mode 0700\n", d, *uid, *gid)
	}
	return nil
}

// stateDir accepts only an absolute directory other than the filesystem root, lexically cleaned.
func stateDir(raw string) (string, error) {
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("%w: --dir must be an absolute path, got %q", errUsage, raw)
	}
	dir := filepath.Clean(raw)
	if dir == string(filepath.Separator) {
		return "", fmt.Errorf("%w: --dir must not be the filesystem root", errUsage)
	}
	return dir, nil
}

// prepareState fixes the top directory only: chown to root first, so chmod needs only CAP_CHOWN, then to uid:gid.
func prepareState(ops fsOps, dir string, uid, gid int) (bool, error) {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return false, err
		}
		fi, err = os.Lstat(dir)
	}
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("%s is not a directory (symbolic links are refused)", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("%s: no ownership information", dir)
	}
	if int(st.Uid) == uid && int(st.Gid) == gid && fi.Mode().Perm() == 0o700 && fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 {
		return false, nil
	}
	if err := ops.chown(dir, 0, 0); err != nil {
		return false, fmt.Errorf("chown %s to root: %w", dir, err)
	}
	if err := ops.chmod(dir, 0o700); err != nil {
		return false, fmt.Errorf("chmod %s: %w", dir, err)
	}
	if err := ops.chown(dir, uid, gid); err != nil {
		return false, fmt.Errorf("chown %s to %d:%d: %w", dir, uid, gid, err)
	}
	return true, nil
}

func dirFlag(name string, args []string, stderr io.Writer, extra func(*flag.FlagSet)) (string, error) {
	fs := newFlags(name, stderr)
	dir := fs.String("dir", "", "state directory")
	if extra != nil {
		extra(fs)
	}
	if err := parse(fs, args, "dir"); err != nil {
		return "", err
	}
	return stateDir(*dir)
}

// lockedError explains a held state lock.
func lockedError(dir string) error {
	return fmt.Errorf("%s is locked by a running agent; stop the agent first (refusing to delete anything)", dir)
}

// removeState takes the directory lock, deletes the contents (the lock file last), and the directory unless it is a mount point.
func removeState(dir string, keepDir bool) (removedDir bool, err error) {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) { //nolint:gosec // dir passed stateDir: absolute, cleaned, not the root
		return false, nil
	}
	unlock, err := spool.LockDir(dir)
	if errors.Is(err, spool.ErrLocked) {
		return false, lockedError(dir)
	}
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := removeContents(dir); err != nil {
		return false, err
	}
	if keepDir {
		return false, nil
	}
	mp, err := isMountPoint(dir)
	if err != nil {
		return false, err
	}
	if mp {
		return false, nil
	}
	if err := os.Remove(dir); err != nil { //nolint:gosec // dir passed stateDir: absolute, cleaned, not the root
		if errors.Is(err, syscall.EBUSY) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// removeContents deletes the entries of dir, the lock file last, through an os.Root so no removal escapes dir.
func removeContents(dir string) (err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	ents, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.Name() == "LOCK" {
			continue
		}
		if err := root.RemoveAll(e.Name()); err != nil {
			return err
		}
	}
	if err := root.Remove("LOCK"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func isMountPoint(dir string) (bool, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	f, err := os.Open(mountInfo)
	if err != nil {
		return devBoundary(abs)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 4 && unescapeMount(fields[4]) == abs {
			return true, nil
		}
	}
	return false, sc.Err()
}

func devBoundary(abs string) (bool, error) {
	var a, b syscall.Stat_t
	if err := syscall.Stat(abs, &a); err != nil {
		return false, err
	}
	if err := syscall.Stat(filepath.Dir(abs), &b); err != nil {
		return false, err
	}
	return a.Dev != b.Dev, nil
}

// unescapeMount decodes the octal escapes mountinfo uses for spaces and similar bytes.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func cleanupCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var wait *bool
	dir, err := dirFlag("cleanup", args, stderr, func(fs *flag.FlagSet) {
		wait = fs.Bool("wait", false, "after deleting, release the lock and block until SIGTERM (per-node completion signal)")
	})
	if err != nil {
		return err
	}
	removed, err := removeState(dir, false)
	if err != nil {
		return err
	}
	if removed {
		fmt.Fprintf(stdout, "%s deleted\n", dir)
	} else {
		fmt.Fprintf(stdout, "%s is clean\n", dir)
	}
	if *wait {
		fmt.Fprintln(stdout, "cleanup complete; waiting for termination")
		<-ctx.Done()
	}
	return nil
}

func purgeStateCmd(_ context.Context, args []string, stdout, stderr io.Writer) error {
	dir, err := dirFlag("purge-state", args, stderr, nil)
	if err != nil {
		return err
	}
	if _, err := removeState(dir, false); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s purged. Purging does not de-enroll: unless this agent was de-enrolled, ExitMesh shows it as offline until an administrator de-enrolls it.\n", dir)
	return nil
}

func prepareImageCmd(_ context.Context, args []string, stdout, stderr io.Writer) error {
	dir, err := dirFlag("prepare-image", args, stderr, nil)
	if err != nil {
		return err
	}
	if _, err := removeState(dir, true); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s is empty: the identity, credential, and all state were removed, so instances started from this image enroll as new targets.\n", dir)
	fmt.Fprintln(stdout, "The image tooling must also reset /etc/machine-id (for example truncate it to an empty file), or clones present the same machine ID and raise an identity conflict.")
	return nil
}

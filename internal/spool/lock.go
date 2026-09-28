// Package spool is the writer's durable record store, the node agent queue, and directory locks.
package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// ErrLocked reports that the directory lock is held, by another process or another open in this one.
var ErrLocked = errors.New("spool: directory is locked")

const lockName = "LOCK"

// LockDir takes an exclusive non-blocking flock on dir/LOCK, creating dir if needed.
func LockDir(dir string) (unlock func() error, err error) {
	if dir == "" {
		return nil, errors.New("spool: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, lockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flock(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	var once sync.Once
	var uerr error
	return func() error {
		once.Do(func() {
			uerr = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			if cerr := f.Close(); uerr == nil {
				uerr = cerr
			}
		})
		return uerr
	}, nil
}

func flock(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EWOULDBLOCK):
			return fmt.Errorf("%w: %s", ErrLocked, f.Name())
		default:
			return fmt.Errorf("spool: flock %s: %w", f.Name(), err)
		}
	}
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeFileAtomic replaces path with data: temp file, fsync, rename, directory fsync.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

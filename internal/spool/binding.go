package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const activeSpoolFile = "active-spool"
const replacementPrefix = "spool-writer-"

// OpenActive resolves the coordinator binding; the caller holds the parent directory lock.
func OpenActive(opts Options) (*Spool, error) {
	root := filepath.Dir(opts.Dir)
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	b, err := dir.ReadFile(activeSpoolFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		name := strings.TrimSpace(string(b))
		if name != filepath.Base(name) || !strings.HasPrefix(name, replacementPrefix) || strings.ContainsAny(name, `/\\`) {
			return nil, errors.New("spool: invalid active spool binding")
		}
		opts.Dir = filepath.Join(root, name)
		if info, err := dir.Lstat(name); err != nil {
			return nil, err
		} else if !info.IsDir() {
			return nil, errors.New("spool: active binding is not a directory")
		}
		if info, err := dir.Lstat(filepath.Join(name, "meta.db")); err != nil {
			return nil, fmt.Errorf("spool: active binding is missing its database: %w", err)
		} else if !info.Mode().IsRegular() {
			return nil, errors.New("spool: active binding is not a regular database")
		}
	}
	return Open(opts)
}

// StageReplacement creates an empty writer beside the old spool, leaving the binding unchanged.
func (s *Spool) StageReplacement() (*Spool, string, error) {
	opts := s.opts
	dir, err := os.MkdirTemp(filepath.Dir(opts.Dir), replacementPrefix)
	if err != nil {
		return nil, "", err
	}
	opts.Dir = dir
	next, err := Open(opts)
	if err != nil {
		return nil, "", errors.Join(err, os.RemoveAll(dir))
	}
	return next, dir, nil
}

// ActivateReplacement switches only the pointer; callers must retain both directories after any error.
func (s *Spool) ActivateReplacement(next *Spool) error {
	root := filepath.Dir(s.opts.Dir)
	if filepath.Dir(next.opts.Dir) != root || !strings.HasPrefix(filepath.Base(next.opts.Dir), replacementPrefix) || next.opts.Dir == s.opts.Dir {
		return errors.New("spool: replacement must be a distinct sibling spool")
	}
	id := next.Identity()
	if id.TargetID == "" || id.TargetID == s.Identity().TargetID || id.Credential == "" || id.EnrollmentTokenHash == "" {
		return errors.New("spool: replacement requires successful enrollment for a different target")
	}
	if _, ok := next.Epoch(); ok {
		return errors.New("spool: replacement already contains history")
	}
	if err := syncDir(next.opts.Dir); err != nil {
		return err
	}
	if err := syncDir(root); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(root, activeSpoolFile), []byte(filepath.Base(next.opts.Dir)+"\n"))
}

func (s *Spool) Directory() string { return s.opts.Dir }

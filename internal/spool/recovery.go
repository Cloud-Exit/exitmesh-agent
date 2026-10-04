package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// RecoverEnrollment changes only enrollment credentials and a recoverable halt, under the writer lock.
func RecoverEnrollment(dir, target string) (err error) {
	if !protocol.ValidTargetID(target) {
		return errors.New("spool: recovery requires a valid target")
	}
	path := filepath.Join(dir, "meta.db")
	if fi, err := os.Lstat(path); err != nil {
		return err
	} else if !fi.Mode().IsRegular() {
		return errors.New("spool: recovery requires an existing regular metadata database")
	}
	unlock, err := LockDir(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	db, err := kv.OpenBolt(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	return db.Update(func(tx *bolt.Tx) error {
		m := tx.Bucket(bucketMeta)
		if m == nil {
			return errors.New("spool: missing metadata")
		}
		var id Identity
		if ok, err := getJSON(m, keyIdentity, &id); err != nil {
			return err
		} else if !ok || id.TargetID != target || id.TargetType != protocol.TargetKubernetes {
			return errors.New("spool: recovery token must match the existing Kubernetes target")
		}
		var halt Halt
		if ok, err := getJSON(m, keyHalt, &halt); err != nil {
			return err
		} else if ok && halt.Code != "superseded" && halt.Code != protocol.CodeUnauthorized {
			return fmt.Errorf("spool: enrollment recovery cannot clear halt %q", halt.Code)
		}
		id.Credential, id.CredentialID = "", ""
		if err := putJSON(m, keyIdentity, id); err != nil {
			return err
		}
		return m.Delete(keyHalt)
	})
}

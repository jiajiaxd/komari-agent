//go:build !windows

package sshmgr

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// writeFileAtomic replaces path through a temporary file in the same
// directory and flushes both the file and the directory to disk.
func writeFileAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".komari-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if uid >= 0 && gid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// writeFilePreserving replaces an existing file keeping its mode and owner.
func writeFilePreserving(path string, data []byte) error {
	mode, uid, gid := os.FileMode(0o644), 0, 0
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(sys.Uid), int(sys.Gid)
		}
	}
	return writeFileAtomic(path, data, mode, uid, gid)
}

// writeAuthorizedKeys writes root's authorized_keys with the permissions
// sshd's StrictModes requires.
func writeAuthorizedKeys(path string, data []byte, acc account) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		_ = os.Chown(dir, acc.uid, acc.gid)
	}
	return writeFileAtomic(path, data, 0o600, acc.uid, acc.gid)
}

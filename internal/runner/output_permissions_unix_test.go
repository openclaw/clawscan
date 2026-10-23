//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRunOutputHonorsPrivateUmask(t *testing.T) {
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)
	TestRunOutputRemainsPrivate(t)
}

func TestAtomicOutputDoesNotAddOwnerPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(path, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(path, map[string]string{"status": "retained"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("owner permissions widened: info=%v err=%v", info, err)
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveClawHubDirReturnsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("clawhub", 0o755); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveClawHubDir("clawhub")
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(dir, "clawhub")
	if resolved != want {
		t.Fatalf("resolved = %q, want %q", resolved, want)
	}
}

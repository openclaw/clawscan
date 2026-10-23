package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIProfilesRejectConfigOutputAlias(t *testing.T) {
	for _, selection := range []string{"one", "all"} {
		t.Run(selection, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "SKILL.md")
			config := filepath.Join(root, "config.yml")
			writeFile(t, target, "# Inert\n")
			body := []byte("version: 1\nprofiles:\n  first:\n    scanners: [clawscan-static]\n  second:\n    scanners: [clawscan-static]\n")
			if err := os.WriteFile(config, body, 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{target, "--config", config, "--output", config, "--json"}
			if selection == "one" {
				args = append(args, "--profile", "first")
			}
			var runErr error
			stdout := captureStdout(t, func() { runErr = run(args, nil) })
			after, err := os.ReadFile(config)
			if runErr == nil || !strings.Contains(runErr.Error(), "output") || err != nil || !bytes.Equal(body, after) || stdout != "" {
				t.Fatalf("profile alias modified config or started work: err=%v bytesIntact=%v stdout=%q", runErr, bytes.Equal(body, after), stdout)
			}
		})
	}
}

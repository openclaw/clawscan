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

func TestCLIPreflightUsesActualResolvedSidecarInventory(t *testing.T) {
	for _, mode := range []string{"dot", "dot-slash", "default-single", "default-multiple-collision", "profile", "all-profiles"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			skill := filepath.Join(root, "skill")
			writeFile(t, filepath.Join(skill, "SKILL.md"), "# Inert\n")
			t.Chdir(skill)
			args := []string{".", "--scanner", "clawscan-static"}
			relative := "skill/clawscan-static.json"
			switch mode {
			case "dot-slash":
				args[0] = "./"
			case "default-single", "default-multiple-collision":
				args = args[1:]
				writeFile(t, filepath.Join(skill, "skills", "a", "SKILL.md"), "# Inert a\n")
				relative = "skills/a/clawscan-static.json"
				if mode == "default-multiple-collision" {
					writeFile(t, filepath.Join(skill, "skills", "a!", "SKILL.md"), "# Inert b\n")
					relative = "skills/a-2/clawscan-static.json"
				}
			case "profile", "all-profiles":
				config := filepath.Join(root, "config.yml")
				writeFile(t, config, "version: 1\nprofiles:\n  first:\n    scanners: [clawscan-static]\n  second:\n    scanners: [clawscan-static]\n")
				args = []string{".", "--config", config}
				relative = "profiles/first/skill/clawscan-static.json"
				if mode == "profile" {
					args = append(args, "--profile", "first")
				}
			}
			input := filepath.Join(root, "reports", filepath.FromSlash(relative))
			body := "{\"generated\":\"protected context\"}\n"
			writeFile(t, input, body)
			args = append(args, "--sandbox", "off", "--context", input, "--output", filepath.Join(root, "reports", "artifact.json"), "--json")
			var runErr error
			stdout := captureStdout(t, func() { runErr = run(args, []string{}) })
			after, readErr := os.ReadFile(input)
			if runErr == nil || !strings.Contains(runErr.Error(), "aliases input") || stdout != "" || readErr != nil || string(after) != body {
				t.Fatalf("actual sidecar input not protected before work: err=%v stdout=%q intact=%v read=%v", runErr, stdout, string(after) == body, readErr)
			}
		})
	}
}

package profiles

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/runner"
)

func TestLoadedConfigRemainsProtectedWithBuiltinProfile(t *testing.T) {
	for _, selection := range []string{"explicit", "discovered"} {
		for _, alias := range []string{"direct", "hardlink", "symlink-parent", "external"} {
			t.Run(selection+"/"+alias, func(t *testing.T) {
				root := t.TempDir()
				config := filepath.Join(root, ".clawscan.yml")
				body := []byte("version: 1\nprofiles:\n  local:\n    scanners: [clawscan-static]\n")
				writeFile(t, config, string(body))
				target := filepath.Join(root, "target", "SKILL.md")
				writeFile(t, target, "# Generated inert target\n")
				output := config
				switch alias {
				case "hardlink":
					output = filepath.Join(root, "linked.json")
					if err := os.Link(config, output); err != nil {
						t.Fatal(err)
					}
				case "symlink-parent":
					parent := filepath.Join(t.TempDir(), "alias")
					if err := os.Symlink(root, parent); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
					output = filepath.Join(parent, ".clawscan.yml")
				case "external":
					output = filepath.Join(root, "evidence", "artifact.json")
				}
				args := []string{target, "--profile", "clawhub", "--scanner", "clawscan-static", "--sandbox", "off", "--judge", "{{ prompt:" + filepath.Join(root, "missing.md") + " }}", "--output", output}
				if selection == "explicit" {
					args = append(args, "--config", config)
				} else {
					args = append(args, "--discover-config")
				}
				opts, err := ResolveArgs(args, root)
				if err != nil {
					t.Fatal(err)
				}
				if opts.ConfigSource != "built-in" {
					t.Fatalf("profile provenance changed: %q", opts.ConfigSource)
				}
				result, runErr := runner.RunTargets(opts, runner.RunContext{Env: map[string]string{}}, root)
				if runErr == nil {
					t.Fatal("expected failure")
				}
				after, err := os.ReadFile(config)
				if err != nil || !bytes.Equal(body, after) {
					t.Fatalf("loaded config overwritten: %s, %v, run=%v", after, err, runErr)
				}
				if alias != "external" {
					if !strings.Contains(runErr.Error(), "aliases input") {
						t.Fatalf("expected input-alias rejection: %v", runErr)
					}
					return
				}
				stored, err := os.ReadFile(output)
				var artifact runner.Artifact
				if err != nil || json.Unmarshal(stored, &artifact) != nil || artifact.Complete || artifact.Status != "failed" || artifact.ConfigSource == nil || *artifact.ConfigSource != "built-in" || result.Single == nil || artifact.Scanners["clawscan-static"].Status != "completed" {
					t.Fatalf("external failure evidence lost: %s, %v", stored, err)
				}
			})
		}
	}
}

func TestAllConfigProfilesRetainLoadedFileForDeferredOutput(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "settings.yml")
	body := []byte("version: 1\nprofiles:\n  first:\n    scanners: [clawscan-static]\n  second:\n    scanners: [clawscan-static]\n")
	writeFile(t, config, string(body))
	target := filepath.Join(root, "SKILL.md")
	writeFile(t, target, "# Inert generated target\n")
	resolved, err := ResolveRunSet([]string{target, "--config", config}, root)
	if err != nil || !resolved.AllProfiles || len(resolved.Options) != 2 {
		t.Fatalf("all-profile resolution failed: %+v, %v", resolved, err)
	}
	for _, opts := range resolved.Options {
		if opts.ConfigSource != config || opts.LoadedConfigPath != config {
			t.Fatalf("loaded identity or project provenance changed: %+v", opts)
		}
	}
	batch, err := runner.RunProfileBatch(resolved.Options, runner.RunContext{Env: map[string]string{}}, root)
	if err != nil || len(batch.Runs) != 2 || !batch.Runs[0].Complete || !batch.Runs[1].Complete {
		t.Fatalf("safe profile execution failed: %+v, %v", batch, err)
	}
	writeErr := runner.WriteRunTargetsResultBundle(config, runner.RunTargetsResult{Batch: &batch})
	after, err := os.ReadFile(config)
	if writeErr == nil || !strings.Contains(writeErr.Error(), "aliases input") || err != nil || !bytes.Equal(body, after) {
		t.Fatalf("all-profile loaded config overwritten: %v, %v", writeErr, err)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/runner"
)

func TestCLIPreparationFailureRejectsConfigOutputAlias(t *testing.T) {
	for _, selection := range []string{"one", "all"} {
		t.Run(selection, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			config := filepath.Join(root, "config.yml")
			body := []byte("version: 1\nprofiles:\n  first:\n    scanners: [clawscan-static]\n  second:\n    scanners: [clawscan-static]\n")
			if err := os.WriteFile(config, body, 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--config", config, "--output", config, "--json"}
			if selection == "one" {
				args = append(args, "--profile", "first")
			}
			var runErr error
			stdout := captureStdout(t, func() { runErr = run(args, []string{}) })
			after, err := os.ReadFile(config)
			if runErr == nil || !strings.Contains(runErr.Error(), "aliases input") || stdout != "" || err != nil || !bytes.Equal(body, after) {
				t.Fatalf("failed preparation overwrote config or bypassed safety: %v, %v, %q", runErr, err, stdout)
			}
		})
	}
}

func TestCLIPreparationFailureRetainsSafeOutput(t *testing.T) {
	for _, selection := range []string{"scanner", "profile", "all-profiles"} {
		for _, output := range []string{"default", "explicit", "json"} {
			t.Run(selection+"/"+output, func(t *testing.T) {
				root := t.TempDir()
				t.Chdir(root)
				config := filepath.Join(root, "config.yml")
				writeFile(t, config, "version: 1\nprofiles:\n  first:\n    scanners: [clawscan-static]\n    judge:\n      command: must-not-run\n  second:\n    scanners: [clawscan-static]\n    judge:\n      command: must-not-run\n")
				args := []string{"--sandbox", "off"}
				switch selection {
				case "scanner":
					args = append(args, "--scanner", "clawscan-static", "--judge", "must-not-run")
				case "profile":
					args = append(args, "--config", config, "--profile", "first")
				case "all-profiles":
					args = append(args, "--config", config)
				}
				outputPath := filepath.Join(root, defaultOutputPath)
				if output == "explicit" {
					outputPath = filepath.Join(root, "failure.json")
					writeFile(t, outputPath, "authorized previous output\n")
					args = append(args, "--output", outputPath, "--json")
				} else if output == "json" {
					args = append(args, "--json")
				}
				var runErr error
				stdout := captureStdout(t, func() { runErr = run(args, []string{}) })
				if runErr == nil || selection != "all-profiles" && !strings.Contains(runErr.Error(), "./skills was not found") {
					t.Fatalf("target discovery failure was lost: %v", runErr)
				}
				raw := []byte(stdout)
				if output != "json" {
					var err error
					raw, err = os.ReadFile(outputPath)
					if err != nil {
						t.Fatal(err)
					}
					if output == "explicit" && string(raw) != stdout {
						t.Fatal("disk and stdout failure evidence differ")
					}
				}
				var runs []runner.Artifact
				if selection == "all-profiles" {
					var batch runner.BatchArtifact
					if err := json.Unmarshal(raw, &batch); err != nil || len(batch.Runs) != 2 || len(batch.Errors) != 2 {
						t.Fatalf("profile preparation evidence lost: %s, %v", raw, err)
					}
					for _, failure := range batch.Errors {
						if !strings.Contains(failure.Error, "./skills was not found") {
							t.Fatalf("profile preparation error lost: %+v", failure)
						}
					}
					runs = batch.Runs
				} else {
					var artifact runner.Artifact
					if err := json.Unmarshal(raw, &artifact); err != nil {
						t.Fatal(err)
					}
					runs = []runner.Artifact{artifact}
				}
				for _, artifact := range runs {
					result := artifact.Scanners["clawscan-static"]
					if artifact.Status != "failed" || artifact.Complete || artifact.Gate != "error" || !strings.Contains(artifact.Error, "./skills was not found") || result.Status != "not_started" || result.StartedAt != "" || len(result.Raw) != 0 && string(result.Raw) != "null" || artifact.Judge == nil || artifact.Judge.Status != "not_started" || artifact.Judge.CommandStarted == nil || *artifact.Judge.CommandStarted {
						t.Fatalf("preparation failure fabricated or lost stage evidence: %+v", artifact)
					}
				}
			})
		}
	}
}

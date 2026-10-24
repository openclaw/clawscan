package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openclaw/clawscan/internal/runner"
)

func TestCLIMissingTargetCannotBecomeScanInput(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for attempt := 0; attempt < 2; attempt++ {
		var runErr error
		stdout := captureStdout(t, func() {
			runErr = run([]string{"./missing", "--scanner", "clawscan-static", "--output", "./missing/reports/artifact.json", "--sandbox", "off", "--json"}, []string{})
		})
		if runErr == nil {
			t.Fatalf("attempt %d accepted missing input: %s", attempt, stdout)
		}
		if _, err := os.Lstat(filepath.Join(root, "missing")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("attempt %d manufactured missing source: %v", attempt, err)
		}
		var artifact runner.Artifact
		if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
			t.Fatal(err)
		}
		stage := artifact.Scanners["clawscan-static"]
		if artifact.Complete || artifact.Status != "failed" || artifact.Gate != "error" || artifact.Target.Input != "./missing" || stage.Status != "not_started" || stage.StartedAt != "" || len(stage.Raw) != 0 && string(stage.Raw) != "null" {
			t.Fatalf("attempt %d invented scan evidence: %+v", attempt, artifact)
		}
	}
}

func TestCLIMissingTargetFailureAcrossProfiles(t *testing.T) {
	for _, selection := range []string{"one", "all"} {
		for _, canceled := range []bool{false, true} {
			for _, nested := range []bool{false, true} {
				t.Run(selection+"/"+map[bool]string{false: "failed", true: "canceled"}[canceled]+"/"+map[bool]string{false: "external", true: "nested"}[nested], func(t *testing.T) {
					root := t.TempDir()
					t.Chdir(root)
					config := filepath.Join(root, "settings.yml")
					writeFile(t, config, "version: 1\nprofiles:\n  first:\n    scanners: [clawscan-static]\n  second:\n    scanners: [clawscan-static]\n")
					output := filepath.Join(root, "reports", "artifact.json")
					if nested {
						output = filepath.Join(root, "missing", "reports", "artifact.json")
					}
					args := []string{"./missing", "--config", config, "--output", output, "--sandbox", "off", "--json"}
					if selection == "one" {
						args = append(args, "--profile", "first")
					}
					caller, cancel := context.WithCancel(context.Background())
					defer cancel()
					if canceled {
						cancel()
					}
					for attempt := 0; attempt < 2; attempt++ {
						var runErr error
						stdout := captureStdout(t, func() { runErr = runContext(caller, args, []string{}) })
						if runErr == nil || canceled && !errors.Is(runErr, context.Canceled) {
							t.Fatalf("incorrect operational failure: %v", runErr)
						}
						if _, err := os.Lstat(filepath.Join(root, "missing")); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("failure output created input: %v", err)
						}
						var runs []runner.Artifact
						if selection == "all" {
							var batch runner.BatchArtifact
							if err := json.Unmarshal([]byte(stdout), &batch); err != nil || len(batch.Runs) != 2 || batch.Summary.TargetCount != 1 {
								t.Fatalf("profile failure inventory lost: %s %v", stdout, err)
							}
							runs = batch.Runs
						} else {
							var artifact runner.Artifact
							if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
								t.Fatal(err)
							}
							runs = []runner.Artifact{artifact}
						}
						for _, artifact := range runs {
							if artifact.Complete || artifact.Gate != "error" || artifact.Target.Input != "./missing" || artifact.Scanners["clawscan-static"].Status != "not_started" || artifact.Status != map[bool]string{false: "failed", true: "canceled"}[canceled] {
								t.Fatalf("fabricated missing input/stage: %+v", artifact)
							}
						}
						if !nested {
							if _, err := os.Stat(output); err != nil {
								t.Fatalf("safe failure observation lost: %v", err)
							}
						}
					}
				})
			}
		}
	}
}

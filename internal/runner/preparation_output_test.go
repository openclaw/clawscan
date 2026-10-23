package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunTargetsDiscoveryFailuresRetainSafeOutput(t *testing.T) {
	for _, discovery := range []string{"missing", "not-directory", "empty"} {
		t.Run(discovery, func(t *testing.T) {
			root := t.TempDir()
			want := "./skills was not found"
			switch discovery {
			case "not-directory":
				if err := os.WriteFile(filepath.Join(root, "skills"), []byte("inert file\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				want = "./skills is not a directory"
			case "empty":
				if err := os.Mkdir(filepath.Join(root, "skills"), 0o700); err != nil {
					t.Fatal(err)
				}
				want = "No valid skills found"
			}
			output := filepath.Join(root, "artifact.json")
			result, err := RunTargets(Options{
				Scanners: []string{"clawscan-static", "snyk"}, Judge: &JudgeOptions{Command: "must-not-run"}, OutputPath: output,
			}, RunContext{Env: map[string]string{}}, root)
			if err == nil || !strings.Contains(err.Error(), want) || result.Single == nil {
				t.Fatalf("discovery failure evidence lost: %+v, %v", result, err)
			}
			artifact := result.Single
			if artifact.Complete || artifact.Status != "failed" || artifact.Gate != "error" || artifact.Error != err.Error() || artifact.Judge == nil || artifact.Judge.Status != "not_started" || artifact.Judge.CommandStarted == nil || *artifact.Judge.CommandStarted {
				t.Fatalf("incorrect preparation lifecycle: %+v", artifact)
			}
			for scanner, stage := range artifact.Scanners {
				if stage.Status != "not_started" || stage.StartedAt != "" || len(stage.Raw) != 0 || stage.OutputPath != "" {
					t.Fatalf("scanner %s started during discovery failure: %+v", scanner, stage)
				}
			}
			raw, readErr := os.ReadFile(output)
			var stored Artifact
			if readErr != nil || json.Unmarshal(raw, &stored) != nil || stored.Error != artifact.Error || stored.Complete || stored.Status != "failed" {
				t.Fatalf("failed output not retained: %s, %v", raw, readErr)
			}
		})
	}
}

func TestRunTargetsDiscoveryFailureStillRejectsInputOutputAliases(t *testing.T) {
	for _, source := range []string{"context", "config", "scanner", "prompt", "schema", "hardlink", "symlink-parent"} {
		t.Run(source, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "input.json")
			body := []byte("generated protected input\n")
			if err := os.WriteFile(input, body, 0o600); err != nil {
				t.Fatal(err)
			}
			opts := Options{Scanners: []string{"clawscan-static"}, OutputPath: input}
			switch source {
			case "context", "hardlink", "symlink-parent":
				opts.ContextPath = input
			case "config":
				opts.ConfigSource = input
			case "scanner":
				opts.ScannerResultPaths = map[string]string{"clawscan-static": input}
			case "prompt":
				opts.Judge = &JudgeOptions{Command: "cat {{ prompt:" + input + " }}"}
			case "schema":
				opts.Judge = &JudgeOptions{Command: "cat {{ output_schema:" + input + " }}"}
			}
			if source == "hardlink" {
				opts.OutputPath = filepath.Join(root, "output.json")
				if err := os.Link(input, opts.OutputPath); err != nil {
					t.Fatal(err)
				}
			} else if source == "symlink-parent" {
				if err := os.Symlink(root, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				opts.OutputPath = filepath.Join(root, "alias", "input.json")
			}
			result, err := RunTargets(opts, RunContext{Env: map[string]string{}}, root)
			after, readErr := os.ReadFile(input)
			if err == nil || !strings.Contains(err.Error(), "aliases input") || result.Single != nil || result.Batch != nil || readErr != nil || !bytes.Equal(body, after) {
				t.Fatalf("preparation path overwrote input or bypassed safety: %+v, %v, %v", result, err, readErr)
			}
		})
	}
}

func TestRunTargetsDiscoveryFailureRetainsOutputFailure(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "artifact.json")
	result, err := RunTargets(Options{Scanners: []string{"clawscan-static"}, OutputPath: output}, RunContext{
		Env: map[string]string{},
		Now: func() time.Time {
			if err := os.MkdirAll(output, 0o700); err != nil {
				t.Fatal(err)
			}
			return time.Unix(0, 0)
		},
	}, root)
	if err == nil || !strings.Contains(err.Error(), "./skills was not found") || !strings.Contains(err.Error(), "refusing non-regular output") || result.Single == nil || result.Single.Complete || result.Single.Status != "failed" || result.Single.Scanners["clawscan-static"].Status != "not_started" || result.Single.Error != err.Error() {
		t.Fatalf("output failure masked preparation failure or evidence: %+v, %v", result, err)
	}
}

func TestRunTargetsCanceledDiscoveryRetainsSafeOutput(t *testing.T) {
	root := t.TempDir()
	caller, cancel := context.WithCancel(context.Background())
	cancel()
	output := filepath.Join(root, "artifact.json")
	result, err := RunTargets(Options{
		Scanners: []string{"clawscan-static"}, Judge: &JudgeOptions{Command: "must-not-run"}, OutputPath: output,
	}, RunContext{Context: caller, Env: map[string]string{}}, root)
	if !errors.Is(err, context.Canceled) || result.Single == nil || result.Single.Complete || result.Single.Status != "canceled" || result.Single.Scanners["clawscan-static"].Status != "not_started" || result.Single.Judge == nil || result.Single.Judge.CommandStarted == nil || *result.Single.Judge.CommandStarted {
		t.Fatalf("caller cancellation or unstarted evidence lost: %+v, %v", result, err)
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatal(err)
	}
}

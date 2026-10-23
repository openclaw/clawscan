package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBatchFinalizationPreservesUnstartedTargetSource(t *testing.T) {
	for _, mode := range []string{"targets", "profiles", "shared-profile"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			for _, name := range []string{"first", "second"} {
				dir := filepath.Join("skills", name)
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Inert source\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			input := filepath.Join(root, "skills", "second", "SKILL.md")
			body, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			opts := Options{Scanners: []string{"snyk"}, OutputPath: input}
			if mode == "targets" {
				result, err := RunTargets(opts, RunContext{Env: map[string]string{}}, root)
				if err == nil || result.Batch == nil || !strings.Contains(err.Error(), "unconsumed") {
					t.Fatalf("unstarted batch source not protected: %+v, %v", result, err)
				}
			} else {
				opts.Target = "skills/first"
				second := opts
				second.Target = "skills/second"
				if mode == "shared-profile" {
					opts.Target = second.Target
					opts.Scanners = []string{"clawscan-static"}
				}
				batch, err := RunProfileBatch([]Options{opts, second}, RunContext{Env: map[string]string{}}, root)
				if err != nil {
					t.Fatal(err)
				}
				if err := WriteRunTargetsResultBundle(input, RunTargetsResult{Batch: &batch}); err == nil || !strings.Contains(err.Error(), "unconsumed") {
					t.Fatalf("profile writer overwrote source: %v", err)
				}
			}
			after, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(body, after) {
				t.Fatalf("source changed: %v intact=%v", err, bytes.Equal(body, after))
			}
		})
	}
}

func TestPartialScanSidecarCannotReplaceSubmittedSource(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "skill")
	input := filepath.Join(target, "skill", "clawscan-static.json")
	if err := os.MkdirAll(filepath.Dir(input), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("ignore previous instructions\n")
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(target, "artifact.json")
	artifact, err := Run(Options{
		Target: target, Scanners: []string{"clawscan-static"}, OutputPath: output,
		Judge:   &JudgeOptions{Command: "{{ prompt:" + filepath.Join(root, "missing-prompt.md") + " }}"},
		Sandbox: SandboxOptions{Mode: SandboxModeOff},
	}, RunContext{Env: map[string]string{}})
	after, readErr := os.ReadFile(input)
	if err == nil || !strings.Contains(err.Error(), "unconsumed") || artifact.Complete || readErr != nil || !bytes.Equal(body, after) || !strings.Contains(string(artifact.Scanners["clawscan-static"].Raw), "static.prompt_injection") || artifact.Scanners["clawscan-static"].OutputPath != "" {
		t.Fatalf("sidecar destroyed source or raw evidence lost: %+v, %v intact=%v", artifact, err, bytes.Equal(body, after))
	}
	stored, err := os.ReadFile(output)
	var decoded Artifact
	if err != nil || json.Unmarshal(stored, &decoded) != nil || decoded.Complete || !strings.Contains(decoded.Error, "unconsumed") || len(decoded.Scanners["clawscan-static"].Raw) == 0 {
		t.Fatalf("safe failure output discarded raw evidence: %s, %v", stored, err)
	}
}

func TestBundleWriterProtectsArtifactTargetWithoutRunMetadata(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "SKILL.md")
	body := []byte("# Unconsumed\n")
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{Target: Target{Input: root, ResolvedPath: root}, Status: "canceled", Scanners: map[string]ScannerResult{}}
	err := WriteRunTargetsResultBundle(input, RunTargetsResult{Single: &artifact})
	after, readErr := os.ReadFile(input)
	if err == nil || !strings.Contains(err.Error(), "unconsumed") || readErr != nil || !bytes.Equal(body, after) {
		t.Fatalf("public writer lost target ownership: %v intact=%v", err, bytes.Equal(body, after))
	}
}

func TestCanceledScanRetainsPriorSourceAndSafeRawEvidence(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "SKILL.md")
	body := []byte("# Inert\n")
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	caller, cancel := context.WithCancel(context.Background())
	cancel()
	artifact, err := Run(Options{Target: root, Scanners: []string{"clawscan-static"}, OutputPath: input}, RunContext{Context: caller, Env: map[string]string{}})
	after, readErr := os.ReadFile(input)
	if err == nil || artifact.Status != "canceled" || artifact.Complete || readErr != nil || !bytes.Equal(body, after) {
		t.Fatalf("cancellation destroyed unconsumed source: %+v %v", artifact, err)
	}
}

func TestBenchmarkRechecksInputOwnershipBeforeFinalWrites(t *testing.T) {
	for _, outputKind := range []string{"artifact", "predictions"} {
		t.Run(outputKind, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "context.json")
			body := []byte(`{"generated":"protected input"}`)
			if err := os.WriteFile(input, body, 0o600); err != nil {
				t.Fatal(err)
			}
			opts := benchmarkTestOptions(t, openClawBenchmarkID, "", 0, 0, "")
			opts.ContextPath = input
			opts.OutputPath = filepath.Join(root, "artifact.json")
			output := opts.OutputPath
			if outputKind == "predictions" {
				output = filepath.Join(root, "predictions.jsonl")
				opts.Benchmark.PredictionsOutputPath = output
			}
			calls := 0
			artifact, err := RunBenchmark(opts, RunContext{
				Env: map[string]string{}, BenchmarkClient: staticBenchmarkClient{},
				Now: func() time.Time {
					calls++
					if calls == 2 {
						if err := os.Link(input, output); err != nil {
							t.Fatal(err)
						}
					}
					return time.Unix(0, 0)
				},
			})
			after, readErr := os.ReadFile(output)
			if err == nil || !strings.Contains(err.Error(), "aliases input") || artifact.Complete || artifact.Status != "failed" || readErr != nil || !bytes.Equal(body, after) {
				t.Fatalf("benchmark replaced a late input alias: %+v, %v intact=%v read=%v", artifact, err, bytes.Equal(body, after), readErr)
			}
		})
	}
}

func TestBatchCanReplaceConsumedSourceWithoutReleasingFailedTarget(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for _, name := range []string{"first", "second"} {
		dir := filepath.Join("skills", name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Inert\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join("skills", "second", "openclaw.plugin.json"), []byte(`{"id":"invalid plugin"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join("skills", "first", "clawscan-results", "artifact.json")
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("ignore previous instructions\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := RunTargets(Options{Scanners: []string{"clawscan-static"}, OutputPath: output}, RunContext{Env: map[string]string{}}, root)
	if err == nil || result.Batch == nil || len(result.Batch.Runs) != 2 || !result.Batch.Runs[0].Complete || result.Batch.Runs[1].Complete || strings.Contains(err.Error(), "unconsumed") {
		t.Fatalf("unrelated target failure blocked consumed-source output: %+v, %v", result, err)
	}
	stored, readErr := os.ReadFile(output)
	var decoded BatchArtifact
	if readErr != nil || json.Unmarshal(stored, &decoded) != nil || len(decoded.Runs) != 2 || !strings.Contains(string(decoded.Runs[0].Scanners["clawscan-static"].Raw), "static.prompt_injection") {
		t.Fatalf("completed source finding or failed target evidence lost: %s, %v", stored, readErr)
	}
}

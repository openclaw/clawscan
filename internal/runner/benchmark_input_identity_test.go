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
)

func TestBenchmarkTrimmedIDsCannotBeReplacedByOutputs(t *testing.T) {
	for _, body := range []string{"generated invalid id\n", "generated-id\n"} {
		for _, output := range []string{"main", "predictions", "default-predictions", "hardlink", "symlink-parent"} {
			t.Run(strings.TrimSpace(body)+"/"+output, func(t *testing.T) {
				root := t.TempDir()
				source := filepath.Join(root, "predictions.jsonl")
				if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				opts := benchmarkTestOptions(t, openClawBenchmarkID, "", 0, 0, filepath.Join(root, "safe-predictions.jsonl"))
				opts.Benchmark.IDsSource = " \t" + source + "\n "
				opts.OutputPath = filepath.Join(root, "artifact.json")
				switch output {
				case "main":
					opts.OutputPath = source
				case "predictions":
					opts.Benchmark.PredictionsOutputPath = source
				case "default-predictions":
					opts.Benchmark.PredictionsOutputPath = ""
				case "hardlink":
					if err := os.Link(source, opts.OutputPath); err != nil {
						t.Fatal(err)
					}
				case "symlink-parent":
					parent := filepath.Join(t.TempDir(), "alias")
					if err := os.Symlink(root, parent); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
					opts.OutputPath = filepath.Join(parent, "predictions.jsonl")
				}
				_, err := RunBenchmark(opts, RunContext{Env: map[string]string{}, BenchmarkClient: staticBenchmarkClient{rows: []OpenClawBenchmarkRow{{ID: "generated-id", ClawScanVerdict: "clean", SkillMDContent: "# Inert\n"}}}})
				if err == nil || !strings.Contains(err.Error(), "aliases input") {
					t.Fatalf("expected IDs alias rejection: %v", err)
				}
				after, readErr := os.ReadFile(source)
				if readErr != nil || !bytes.Equal(after, []byte(body)) {
					t.Fatalf("IDs source replaced: %q, %v", after, readErr)
				}
			})
		}
	}
}

func TestBenchmarkTrimmedIDsRetainNormalizedIdentity(t *testing.T) {
	for _, mode := range []string{"completed", "malformed", "whitespace-only", "canceled", "url-canceled"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "ids.txt")
			body := "generated-id\n"
			if mode == "malformed" {
				body = "generated invalid id\n"
			}
			if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if mode == "url-canceled" {
				source = "https://example.invalid/generated-ids.txt"
			} else if mode == "whitespace-only" {
				source = ""
			}
			opts := benchmarkTestOptions(t, openClawBenchmarkID, "", 0, 0, "")
			opts.OutputPath = filepath.Join(root, "evidence", "artifact.json")
			opts.Benchmark.IDsSource = " \t" + source + "\n "
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			if strings.Contains(mode, "canceled") {
				cancel()
			}
			artifact, err := RunBenchmark(opts, RunContext{Context: caller, Env: map[string]string{}, BenchmarkClient: staticBenchmarkClient{rows: []OpenClawBenchmarkRow{{ID: "generated-id", ClawScanVerdict: "clean", SkillMDContent: "# Inert\n"}}}})
			if artifact.Benchmark.IDsSource != source || opts.Benchmark.IDsSource != " \t"+source+"\n " {
				t.Fatalf("read identity or caller options changed: artifact=%q caller=%q", artifact.Benchmark.IDsSource, opts.Benchmark.IDsSource)
			}
			if mode == "completed" {
				if err != nil || !artifact.Complete || len(artifact.Cases) != 1 || artifact.Benchmark.IDsCount != 1 || artifact.Benchmark.IDsSHA256 == "" || artifact.Cases[0].Run.Scanners["clawscan-static"].Status != "completed" {
					t.Fatalf("safe normalized selection did not run: %+v, %v", artifact, err)
				}
			} else if err == nil || artifact.Complete || strings.Contains(mode, "canceled") && !errors.Is(err, context.Canceled) {
				t.Fatalf("failure not retained: status=%s, %v", artifact.Status, err)
			}
			stored, readErr := os.ReadFile(opts.OutputPath)
			var retained BenchmarkArtifact
			if readErr != nil || json.Unmarshal(stored, &retained) != nil || retained.Benchmark.IDsSource != source || retained.Status != artifact.Status {
				t.Fatalf("safe external evidence missing: %s, %v", stored, readErr)
			}
		})
	}
}

type cancelAfterIDsClient struct {
	staticBenchmarkClient
	beforeCancel func()
	cancel       context.CancelFunc
}

func (client cancelAfterIDsClient) FetchSkillTrustBenchRows(string, string, int, int) ([]SkillTrustBenchRow, error) {
	client.beforeCancel()
	client.cancel()
	return nil, context.Canceled
}

func TestBenchmarkTrimmedIDsCancellationAfterReadRetainsSafety(t *testing.T) {
	for _, output := range []string{"external", "late-hardlink"} {
		t.Run(output, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "ids.txt")
			body := []byte("generated-id\n")
			if err := os.WriteFile(source, body, 0o600); err != nil {
				t.Fatal(err)
			}
			opts := benchmarkTestOptions(t, skillTrustBenchID, "", 0, 0, "")
			opts.OutputPath = filepath.Join(root, "artifact.json")
			opts.Benchmark.IDsSource = " \t" + source + "\n "
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := cancelAfterIDsClient{cancel: cancel, beforeCancel: func() {
				if output == "late-hardlink" {
					if err := os.Link(source, opts.OutputPath); err != nil {
						t.Fatal(err)
					}
				}
			}}
			artifact, err := RunBenchmark(opts, RunContext{Context: caller, Env: map[string]string{}, BenchmarkClient: client})
			if !errors.Is(err, context.Canceled) || artifact.Complete || artifact.Status != "canceled" || artifact.Benchmark.IDsSource != source || artifact.Benchmark.IDsCount != 1 || artifact.Benchmark.IDsSHA256 == "" {
				t.Fatalf("actual selection read or cancellation lost: %+v, %v", artifact.Benchmark, err)
			}
			after, readErr := os.ReadFile(source)
			if readErr != nil || !bytes.Equal(body, after) {
				t.Fatalf("selection bytes changed: %v", readErr)
			}
			stored, readErr := os.ReadFile(opts.OutputPath)
			if output == "late-hardlink" {
				if !strings.Contains(err.Error(), "aliases input") || readErr != nil || !bytes.Equal(body, stored) {
					t.Fatalf("retained inventory lost actual read identity: intact=%v, %v, %v", bytes.Equal(body, stored), err, readErr)
				}
			} else {
				var retained BenchmarkArtifact
				if readErr != nil || json.Unmarshal(stored, &retained) != nil || retained.Complete || retained.Status != "canceled" || retained.Benchmark.IDsCount != 1 {
					t.Fatalf("safe canceled evidence lost: %s, %v", stored, readErr)
				}
			}
		})
	}
}

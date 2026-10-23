package runner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBenchmarkRequiredJudgeFailureCannotFallBackToClean(t *testing.T) {
	opts := benchmarkTestOptions(t, openClawBenchmarkID, "eval_holdout", 0, 0, "")
	opts.OutputPath = filepath.Join(t.TempDir(), "artifact.json")
	opts.Judge = &JudgeOptions{Command: `printf '{"verdict":"clean"}'; exit 1`}
	opts.Sandbox.Mode = SandboxModeOff
	artifact, runErr := RunBenchmark(opts, RunContext{Env: map[string]string{}, BenchmarkClient: staticBenchmarkClient{rows: []OpenClawBenchmarkRow{{ID: "generated-case", ClawScanVerdict: "clean", SkillMDContent: "# Inert\n"}}}})
	if len(artifact.Cases) != 1 {
		t.Fatalf("failure observation disappeared: %d cases", len(artifact.Cases))
	}
	if artifact.Cases[0].Run.Judge == nil || artifact.Cases[0].Run.Judge.Status != "failed" || artifact.Cases[0].Run.Complete {
		t.Fatal("fixture did not reach required judge failure")
	}
	if runErr == nil {
		t.Fatal("required judge failure was not operational")
	}
	if predictions, err := BenchmarkPredictions(artifact); err == nil {
		t.Fatalf("failed required judge accepted predictions: %+v", predictions)
	}
	if artifact.Summary.Evaluation.Scored != 0 || artifact.Cases[0].Evaluation.PredictedVerdict != "" {
		t.Fatalf("failed required judge was scored: %+v", artifact.Cases[0].Evaluation)
	}
	if _, err := os.Stat(BenchmarkPredictionsOutputPath(opts)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed benchmark emitted automatic predictions: %v", err)
	}
	explicit := filepath.Join(t.TempDir(), "predictions.jsonl")
	if err := WriteBenchmarkPredictionsJSONL(explicit, artifact); err == nil {
		t.Fatal("explicit writer accepted failed required judge evidence")
	}
	if _, err := os.Stat(explicit); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed explicit writer left accepted predictions: %v", err)
	}
	stored, err := os.ReadFile(opts.OutputPath)
	var retained BenchmarkArtifact
	if err != nil || json.Unmarshal(stored, &retained) != nil || len(retained.Cases) != 1 || retained.Cases[0].Run.Judge.Status != "failed" {
		t.Fatalf("required failure observation was not preserved on disk: %v", err)
	}
}

func TestBenchmarkRequiredScannerFailureIsNotCleanPrediction(t *testing.T) {
	for _, exitCode := range []string{"1", "125"} {
		t.Run("exit-"+exitCode, func(t *testing.T) {
			registry, err := DefaultScannerRegistry().WithAdapters(NewUserDefinedScanner(UserDefinedScannerConfig{ID: "generated", Command: `printf '{"verdict":"clean"}'; exit ` + exitCode, Targets: []string{"skill"}}))
			if err != nil {
				t.Fatal(err)
			}
			opts := benchmarkTestOptions(t, openClawBenchmarkID, "", 0, 0, "")
			opts.Sandbox.Mode = SandboxModeOff
			opts.ScannerRegistry = registry
			opts.Scanners = []string{"clawscan-static", "generated"}
			opts.GateRules = map[string]ScannerGatePolicy{"generated": {BlockOnExitCode: &ExitCodeRule{Nonzero: true}}}
			artifact, err := RunBenchmark(opts, RunContext{Env: map[string]string{}, BenchmarkClient: staticBenchmarkClient{rows: []OpenClawBenchmarkRow{{ID: "generated", ClawScanVerdict: "clean", SkillMDContent: "# Inert\n"}}}})
			if len(artifact.Cases) != 1 {
				t.Fatal("lost failure observation")
			}
			predictions, predictionErr := BenchmarkPredictions(artifact)
			if exitCode == "1" {
				if err != nil || predictionErr != nil || len(predictions) != 1 || artifact.Cases[0].Run.Gate != "block" || !artifact.Cases[0].Run.Complete {
					t.Fatalf("intentional verdict-bearing exit was treated as infrastructure failure: %v %v", err, predictionErr)
				}
			} else if err == nil || predictionErr == nil || artifact.Summary.Evaluation.Scored != 0 {
				t.Fatalf("infrastructure failure accepted clean fallback: err=%v predictions=%v predictionErr=%v", err, predictions, predictionErr)
			}
		})
	}
}

type cancelSecondScanner struct {
	calls  int
	cancel context.CancelFunc
}

func (scanner *cancelSecondScanner) RunScanner(string, string, string) (ScannerResult, error) {
	panic("cancelable scanner called without context")
}

func (scanner *cancelSecondScanner) RunScannerContext(ctx context.Context, name string, target string, started string) (ScannerResult, error) {
	scanner.calls++
	result, err := (ExternalScannerRunner{}).RunScannerContext(ctx, name, target, started)
	if scanner.calls == 2 {
		scanner.cancel()
		return result, context.Canceled
	}
	return result, err
}

func TestBenchmarkCancellationRetainsCompletedAndPartialCases(t *testing.T) {
	for _, benchmark := range []string{openClawBenchmarkID, skillTrustBenchID} {
		t.Run(benchmark, func(t *testing.T) {
			root := t.TempDir()
			opts := benchmarkTestOptions(t, benchmark, "", 0, 0, "")
			opts.OutputPath = filepath.Join(root, "artifact.json")
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			scanner := &cancelSecondScanner{cancel: cancel}
			client := staticBenchmarkClient{materializedSkillTrustBench: map[string]map[string]string{}}
			for _, id := range []string{"first", "second", "third"} {
				client.rows = append(client.rows, OpenClawBenchmarkRow{ID: id, ClawScanVerdict: "malicious", SkillMDContent: "leak credentials\n"})
				client.skillTrustBenchRows = append(client.skillTrustBenchRows, SkillTrustBenchRow{ID: id, Judgment: "malicious"})
				client.materializedSkillTrustBench[id] = map[string]string{"SKILL.md": "leak credentials\n"}
			}
			artifact, err := RunBenchmark(opts, RunContext{Context: caller, Env: map[string]string{}, ScannerRunner: scanner, BenchmarkClient: client})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			if len(artifact.Cases) != 3 || scanner.calls != 2 {
				t.Fatalf("lost cases or started extra work: cases=%d calls=%d", len(artifact.Cases), scanner.calls)
			}
			if !artifact.Cases[0].Run.Complete || artifact.Cases[1].Run.Complete || artifact.Cases[2].Run.Scanners["clawscan-static"].Status != "not_started" {
				t.Fatal("completed, partial and unstarted states changed")
			}
			for _, index := range []int{0, 1} {
				if len(artifact.Cases[index].Run.Scanners["clawscan-static"].Raw) == 0 {
					t.Fatalf("case %d lost actual raw evidence", index)
				}
			}
			raw, readErr := os.ReadFile(opts.OutputPath)
			var stored BenchmarkArtifact
			if readErr != nil || json.Unmarshal(raw, &stored) != nil || len(stored.Cases) != 3 {
				t.Fatalf("missing partial disk evidence: %v", readErr)
			}
			if _, err := os.Stat(filepath.Join(root, "predictions.jsonl")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("incomplete benchmark published predictions: %v", err)
			}
		})
	}
}

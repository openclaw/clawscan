package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClawHubUsablePartialReachesJudge(t *testing.T) {
	raw, err := os.ReadFile("testdata/skillspector-usable-partial.json")
	if err != nil {
		t.Fatal(err)
	}
	promptSource, err := os.ReadFile("../profiles/clawhub/prompt.md")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, verdict := range []string{"benign", "suspicious", "malicious"} {
		t.Run(verdict, func(t *testing.T) {
			target, err := filepath.Abs(filepath.Join("testdata", "partial-judge", verdict))
			if err != nil {
				t.Fatal(err)
			}
			command := &recordingCommandRunner{}
			command.runHook = func(_ string, _ []string, workspace string) error {
				fullReport, err := os.ReadFile(filepath.Join(workspace, "skillspector-report-0.json"))
				if err != nil || !bytes.Equal(fullReport, raw) {
					t.Fatalf("judge workspace lost complete raw report: err=%v", err)
				}
				prompt, err := os.ReadFile(filepath.Join(workspace, "prompt.md"))
				if err != nil {
					return err
				}
				for _, evidence := range []string{"unsupported_syntax", "SSD-1", "analysisCompleteness", "Independently investigate material gaps", "residual uncertainty"} {
					if !strings.Contains(string(prompt), evidence) {
						t.Fatalf("judge lost %s", evidence)
					}
				}
				receipt := partialJudgeReceipt(t, workspace)
				gapFile, err := os.ReadFile(filepath.Join(workspace, "artifact", "fixture-001.md"))
				if err != nil || len(gapFile) == 0 {
					t.Fatalf("gap artifact unavailable for investigation: err=%v", err)
				}
				receipt["version"] = 2
				receipt["required_file"] = "artifact/SKILL.md"
				receipt["additional_files_inspected"] = []string{"artifact/fixture-001.md"}
				delete(receipt, "files_inspected")
				command.writeOutput = string(judgeRetryOutput(t, map[string]any{
					"verdict": verdict, "artifact_inspection": receipt,
					"user_guidance": "Inspected artifact/fixture-001.md: " + strings.TrimSpace(string(gapFile)) + " The scanner's parser limitation remains recorded; runtime behavior was not executed.",
				}).Stdout)
				return nil
			}
			output := filepath.Join(t.TempDir(), "run.json")
			artifact, err := Run(Options{
				Target: target, Profile: "clawhub", Scanners: []string{"skillspector"},
				OutputPath:         output,
				ScannerResultPaths: map[string]string{"skillspector": path},
				Judge:              &JudgeOptions{Command: "judge --prompt {{ prompt:clawhub/prompt.md }} --output {{ output }}", Files: map[string][]byte{"clawhub/prompt.md": promptSource}},
			}, RunContext{Env: map[string]string{}, CommandRunner: command})
			if err != nil {
				t.Fatal(err)
			}
			if !artifact.Complete || artifact.Status != "completed" || artifact.Judge == nil || artifact.Judge.Status != "completed" {
				t.Fatalf("adjudication incomplete: status=%s judge=%+v", artifact.Status, artifact.Judge)
			}
			result := artifact.Scanners["skillspector"]
			if result.Status != "partial" || !bytes.Equal(result.Raw, raw) {
				t.Fatalf("partial status or raw evidence changed: %+v", result)
			}
			if result.OutputPath == "" {
				t.Fatal("partial report missing from output bundle")
			}
			saved, err := os.ReadFile(filepath.Join(filepath.Dir(output), filepath.FromSlash(result.OutputPath)))
			if err != nil || !bytes.Equal(saved, raw) {
				t.Fatalf("saved partial report changed: err=%v", err)
			}
			serialized, err := json.Marshal(result)
			if err != nil || !bytes.Contains(serialized, []byte(`"reportPolicy":"judge-gaps"`)) {
				t.Fatalf("missing explicit consumer policy: %s err=%v", serialized, err)
			}
			if artifact.Judge.Result.(map[string]any)["verdict"] != verdict {
				t.Fatal("runner changed independent judge verdict")
			}
			predictions, err := BenchmarkPredictions(BenchmarkArtifact{
				Benchmark: BenchmarkMetadata{ID: openClawBenchmarkID},
				Cases:     []BenchmarkCase{{ID: "partial-fixture", Run: artifact}},
			})
			wantPrediction := verdict
			if verdict == "benign" {
				wantPrediction = "clean"
			}
			if err != nil || len(predictions) != 1 || predictions[0].Prediction != wantPrediction {
				t.Fatalf("benchmark lost adjudicated partial verdict: predictions=%+v err=%v", predictions, err)
			}
		})
	}
}

func TestSkillSpectorPartialCommandContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/skillspector-usable-partial.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"", "custom", "clawhub", "clawhub-aig"} {
		for _, exit := range []int{0, 1, 2, 137} {
			t.Run(fmt.Sprintf("%s/exit-%d", profile, exit), func(t *testing.T) {
				command := &recordingCommandRunner{writeOutput: string(raw), exitCode: intPointer(exit)}
				if exit != 0 {
					command.err = errCommandFailed
				}
				result, err := (ExternalScannerRunner{Profile: profile, CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
				want := "failed"
				if (profile == "clawhub" || profile == "clawhub-aig") && exit <= 1 {
					want = "partial"
				}
				if err != nil || result.Status != want || !bytes.Equal(result.Raw, raw) {
					t.Fatalf("status=%s want=%s err=%v exit=%v", result.Status, want, err, result.ExitCode)
				}
				if exit <= MaxGateExitCode && (result.ExitCode == nil || *result.ExitCode != exit) || exit > MaxGateExitCode && result.ExitCode != nil {
					t.Fatalf("infrastructure exit code became verdict-eligible: %v", result.ExitCode)
				}
			})
		}
	}
}

func TestClawHubPartialRejectsInvalidReport(t *testing.T) {
	fixture, err := os.ReadFile("testdata/skillspector-usable-partial.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, section, field string
		value                any
	}{
		{"unsuccessful", "root", "execution_successful", false},
		{"missing-success", "root", "execution_successful", nil},
		{"error", "root", "error", "fixture failure"},
		{"conflicting-alias", "root", "executionSuccessful", false},
		{"case-conflicting-execution", "root", "Execution_successful", false},
		{"missing-issues", "root", "issues", nil},
		{"invalid-issue", "root", "issues", []any{false}},
		{"missing-components", "root", "components", nil},
		{"missing-completeness", "root", "analysis_completeness", nil},
		{"malformed-metadata", "root", "metadata", false},
		{"nested-failure", "accounting", "execution_successful", false},
		{"failed-status", "accounting", "status", "failed"},
		{"case-conflicting-status", "accounting", "Status", "failed"},
		{"invalid-count", "accounting", "fully_inspected_files", "1"},
		{"contradictory-count", "accounting", "fully_inspected_files", 3},
		{"malformed-coverage", "accounting", "coverage_percent", "unknown"},
		{"malformed-limitations", "accounting", "limitations", false},
		{"invalid-exception", "accounting", "ledger_exceptions", []any{map[string]any{"fatal": true}}},
		{"invalid-analyzers", "accounting", "analyzer_statuses", []any{nil}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var report map[string]any
			if err := json.Unmarshal(fixture, &report); err != nil {
				t.Fatal(err)
			}
			section := report
			if test.section == "accounting" {
				section = report["analysis_completeness"].(map[string]any)
			}
			section[test.field] = test.value
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			command := &recordingCommandRunner{writeOutput: string(raw), exitCode: intPointer(0)}
			result, err := (ExternalScannerRunner{Profile: "clawhub", CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
			if err != nil || result.Status != "failed" || result.ReportPolicy != "" || !bytes.Equal(result.Raw, raw) {
				t.Fatalf("invalid report qualified: status=%s policy=%s err=%v", result.Status, result.ReportPolicy, err)
			}
		})
	}
}

func TestClawHubPartialRequiresSuccessfulJudge(t *testing.T) {
	raw, err := os.ReadFile("testdata/skillspector-usable-partial.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"no-judge", "missing-receipt", "wrong-hash", "command-failed"} {
		t.Run(failure, func(t *testing.T) {
			target := t.TempDir()
			if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			opts := Options{Profile: "clawhub", Target: target, Scanners: []string{"skillspector"}, ScannerResultPaths: map[string]string{"skillspector": path}}
			command := judgeRetryCommand(func(workspace string, _ time.Duration) (CommandOutput, error) {
				result := map[string]any{"verdict": "benign"}
				if failure != "missing-receipt" {
					receipt := partialJudgeReceipt(t, workspace)
					if failure == "wrong-hash" {
						receipt["required_file_sha256"] = strings.Repeat("0", 64)
					}
					result["artifact_inspection"] = receipt
				}
				if failure == "command-failed" {
					return judgeRetryOutput(t, result), errors.New("synthetic harness crash")
				}
				return judgeRetryOutput(t, result), nil
			})
			if failure != "no-judge" {
				opts.Judge = &JudgeOptions{Command: "judge"}
			}
			artifact, _ := Run(opts, RunContext{Env: map[string]string{}, CommandRunner: command})
			if artifact.Complete || artifact.Status != "failed" || artifact.Gate != "error" {
				t.Fatalf("partial without successful judge qualified: %+v", artifact)
			}
			if failure != "no-judge" && (artifact.Judge == nil || artifact.Judge.Status != "failed") {
				t.Fatalf("failed judge state lost: %+v", artifact.Judge)
			}
		})
	}
}

func TestClawHubPartialHasNoCoverageGate(t *testing.T) {
	fixture, err := os.ReadFile("testdata/skillspector-usable-partial.json")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(fixture, &report); err != nil {
		t.Fatal(err)
	}
	accounting := report["analysis_completeness"].(map[string]any)
	accounting["fully_inspected_files"], accounting["scanned_components"] = 0, 0
	accounting["entirely_uninspected_files"], accounting["coverage_percent"] = 1, 0
	accounting["limitations"] = []string{"Semantic analyzer unavailable; inspect material artifact gaps independently."}
	accounting["analyzer_statuses"] = []any{map[string]any{"analyzer_id": "semantic_security_discovery", "status": "failed", "planned_work": 2, "completed": 0, "partial": 1, "failed": 1}}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	command := &recordingCommandRunner{writeOutput: string(raw), exitCode: intPointer(0)}
	result, err := (ExternalScannerRunner{Profile: "clawhub", CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
	if err != nil || result.Status != "partial" || result.ReportPolicy != "judge-gaps" || !bytes.Equal(result.Raw, raw) {
		t.Fatalf("coverage or nonfatal analyzer gap became rigid gate: %+v err=%v", result, err)
	}
}

func TestClawHubPartialPreservesSecurityGates(t *testing.T) {
	fixture, err := os.ReadFile("testdata/skillspector-usable-partial.json")
	if err != nil {
		t.Fatal(err)
	}
	target, err := filepath.Abs(filepath.Join("testdata", "partial-judge", "malicious"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	command := judgeRetryCommand(func(workspace string, _ time.Duration) (CommandOutput, error) {
		return judgeRetryOutput(t, map[string]any{"verdict": "benign", "artifact_inspection": partialJudgeReceipt(t, workspace)}), nil
	})
	artifact, err := Run(Options{
		Profile: "clawhub", Target: target, Scanners: []string{"skillspector"}, ScannerResultPaths: map[string]string{"skillspector": path},
		Judge:     &JudgeOptions{Command: "judge"},
		GateRules: map[string]ScannerGatePolicy{"skillspector": {JSONRules: []JSONGateRule{{ID: "retained-high-finding", Paths: []string{"issues[].severity"}, Equals: json.RawMessage(`"HIGH"`), Action: "block"}}}},
	}, RunContext{Env: map[string]string{}, CommandRunner: command})
	if err != nil || !artifact.Complete || artifact.Gate != "block" || len(artifact.GateRules) != 1 {
		t.Fatalf("adjudication bypassed configured finding gate: gate=%s rules=%+v err=%v", artifact.Gate, artifact.GateRules, err)
	}
}

func TestClawHubPartialMissingMalformedAndCrashedOutput(t *testing.T) {
	fixture, err := os.ReadFile("testdata/skillspector-usable-partial.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "{", "null", "[]", "{}", strings.Replace(string(fixture), `"execution_successful": true`, `"execution_successful": false, "execution_successful": true`, 1)} {
		t.Run(fmt.Sprintf("bytes-%d", len(raw)), func(t *testing.T) {
			command := &recordingCommandRunner{writeOutput: raw, exitCode: intPointer(0)}
			result, err := (ExternalScannerRunner{Profile: "clawhub", CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
			if err != nil || result.Status != "failed" || result.ReportPolicy != "" {
				t.Fatalf("invalid output qualified: %+v err=%v", result, err)
			}
		})
	}
	command := &recordingCommandRunner{writeOutput: string(fixture), err: errors.New("fixture timeout without an exit code")}
	result, err := (ExternalScannerRunner{Profile: "clawhub", CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
	if err != nil || result.Status != "failed" || result.ReportPolicy != "" || !bytes.Equal(result.Raw, fixture) {
		t.Fatalf("crashed command became usable: %+v err=%v", result, err)
	}
}

func partialJudgeReceipt(t *testing.T, workspace string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(workspace, "artifact-inspection.json"))
	if err != nil {
		t.Fatal(err)
	}
	var challenge artifactInspectionChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(challenge.RequiredFile)))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"status": "completed", "challenge": challenge.Challenge, "required_file_sha256": sha256Hex(string(artifact)), "files_inspected": []string{challenge.RequiredFile}}
}

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

func TestRunClawHubJudgeRecoversMissingRequiredFileReceipt(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo"), 0o600); err != nil {
		t.Fatal(err)
	}
	scannerEvidence := json.RawMessage(`{"status":"completed","issues":[{"severity":"HIGH","description":"fixture evidence"}]}`)
	judgeRunner := &recordingCommandRunner{}
	attempts := 0
	judgeRunner.runHook = func(_ string, _ []string, cwd string) error {
		attempts++
		raw, err := os.ReadFile(filepath.Join(cwd, "artifact-inspection.json"))
		if err != nil {
			return err
		}
		var challenge artifactInspectionChallenge
		if err := json.Unmarshal(raw, &challenge); err != nil {
			return err
		}
		required, err := os.ReadFile(filepath.Join(cwd, filepath.FromSlash(challenge.RequiredFile)))
		if err != nil {
			return err
		}
		inspected := "artifact/artifact-inspection.json"
		if attempts == 2 {
			inspected = challenge.RequiredFile
		}
		judgeRunner.writeOutput = fmt.Sprintf(`{"verdict":"suspicious","artifact_inspection":{"status":"completed","challenge":%q,"required_file_sha256":%q,"files_inspected":[%q]}}`, challenge.Challenge, sha256Hex(string(required)), inspected)
		return nil
	}
	artifact, err := Run(Options{
		Target: target, Profile: "clawhub", Scanners: []string{"skillspector"},
		Judge: &JudgeOptions{Command: "judge --output {{ output }}"},
	}, RunContext{
		Env: map[string]string{"OPENAI_API_KEY": "fixture-only"},
		ScannerRunner: staticScannerRunner{results: map[string]ScannerResult{
			"skillspector": {Status: "completed", Raw: scannerEvidence},
		}},
		CommandRunner: judgeRunner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Judge == nil || artifact.Judge.Status != "completed" {
		t.Fatalf("expected validated recovery after omitted required file; attempts=%d judge=%+v", attempts, artifact.Judge)
	}
	if attempts != 2 {
		t.Fatalf("judge attempts = %d; want exactly 2", attempts)
	}
	if !bytes.Equal(artifact.Scanners["skillspector"].Raw, scannerEvidence) {
		t.Fatal("scanner evidence changed during judge recovery")
	}
	result := artifact.Judge.Result.(map[string]any)
	if result["verdict"] != "suspicious" {
		t.Fatalf("security verdict = %v; want suspicious", result["verdict"])
	}
	history := artifact.Judge.Attempts
	if len(history) != 2 || history[0].Status != "failed" || history[1].Status != "completed" {
		t.Fatalf("judge attempt evidence = %+v", history)
	}
	if history[0].Challenge == history[1].Challenge || history[0].Challenge == "" {
		t.Fatal("retry must use a fresh challenge")
	}
	for _, attempt := range history {
		if attempt.RequiredFile != "artifact/SKILL.md" || attempt.RequiredSHA256 != sha256Hex("# Demo") {
			t.Fatalf("required-file evidence = %+v", attempt)
		}
	}
	if !strings.Contains(history[0].Error, "did not include required file artifact/SKILL.md") || history[0].Result == nil {
		t.Fatal("missing original invalid result and validation error")
	}
}

type judgeRetryCommand func(cwd string, timeout time.Duration) (CommandOutput, error)

func (command judgeRetryCommand) Run(_ string, _ []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	return command(cwd, timeout)
}

func judgeRetryArtifact(t *testing.T) Artifact {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo"), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewArtifact(Options{Profile: "clawhub", Target: target}, target, "", "", nil)
}

func judgeRetryReceipt(t *testing.T, cwd string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(cwd, "artifact-inspection.json"))
	if err != nil {
		t.Fatal(err)
	}
	var challenge artifactInspectionChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"status": "completed", "challenge": challenge.Challenge,
		"required_file_sha256": sha256Hex("# Demo"), "files_inspected": []string{challenge.RequiredFile},
	}
}

func judgeRetryOutput(t *testing.T, result map[string]any) CommandOutput {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return CommandOutput{Stdout: string(raw)}
}

func TestRunClawHubJudgeReceiptRetryFailsClosed(t *testing.T) {
	for _, failure := range []string{"missing_receipt", "missing_required_file", "wrong_hash", "stale_challenge", "invalid_json", "command_failure", "no_output"} {
		t.Run(failure, func(t *testing.T) {
			artifact := judgeRetryArtifact(t)
			attempts := 0
			firstChallenge := ""
			command := judgeRetryCommand(func(cwd string, _ time.Duration) (CommandOutput, error) {
				attempts++
				receipt := judgeRetryReceipt(t, cwd)
				if attempts == 1 {
					firstChallenge = receipt["challenge"].(string)
				}
				result := map[string]any{"verdict": "benign", "artifact_inspection": receipt}
				switch failure {
				case "missing_receipt":
					delete(result, "artifact_inspection")
				case "missing_required_file":
					receipt["files_inspected"] = []string{"artifact/artifact-inspection.json"}
				case "wrong_hash":
					receipt["required_file_sha256"] = "wrong"
				case "stale_challenge":
					if attempts == 1 {
						receipt["files_inspected"] = []string{"artifact/artifact-inspection.json"}
					} else {
						receipt["challenge"] = firstChallenge
					}
				case "invalid_json":
					return CommandOutput{Stdout: "not json"}, nil
				case "command_failure":
					return judgeRetryOutput(t, result), errors.New("command timed out")
				case "no_output":
					return CommandOutput{}, nil
				}
				return judgeRetryOutput(t, result), nil
			})
			result, err := RunJudge(JudgeOptions{Command: "judge"}, artifact, command, time.Second, nil, SandboxModeOff)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "failed" || result.Error == "" {
				t.Fatalf("invalid judge must remain failed: %+v", result)
			}
			wantAttempts := 2
			if failure == "invalid_json" || failure == "command_failure" || failure == "no_output" {
				wantAttempts = 1
			}
			if attempts != wantAttempts || len(result.Attempts) != wantAttempts {
				t.Fatalf("attempts = %d, evidence = %d; want %d", attempts, len(result.Attempts), wantAttempts)
			}
		})
	}
}

func TestRunJudgeDoesNotRetryValidSecurityVerdict(t *testing.T) {
	for _, verdict := range []string{"benign", "suspicious", "malicious"} {
		t.Run(verdict, func(t *testing.T) {
			attempts := 0
			command := judgeRetryCommand(func(cwd string, _ time.Duration) (CommandOutput, error) {
				attempts++
				return judgeRetryOutput(t, map[string]any{"verdict": verdict, "artifact_inspection": judgeRetryReceipt(t, cwd)}), nil
			})
			result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(t), command, time.Second, nil, SandboxModeOff)
			if err != nil || result.Status != "completed" || result.Result.(map[string]any)["verdict"] != verdict || attempts != 1 {
				t.Fatalf("result = %+v, err = %v, attempts = %d", result, err, attempts)
			}
		})
	}
}

func TestRunJudgeReceiptRetriesShareDeadline(t *testing.T) {
	var budgets []time.Duration
	command := judgeRetryCommand(func(cwd string, timeout time.Duration) (CommandOutput, error) {
		budgets = append(budgets, timeout)
		receipt := judgeRetryReceipt(t, cwd)
		if len(budgets) == 1 {
			time.Sleep(20 * time.Millisecond)
			receipt["files_inspected"] = []string{"artifact/artifact-inspection.json"}
		}
		return judgeRetryOutput(t, map[string]any{"artifact_inspection": receipt}), nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(t), command, time.Second, nil, SandboxModeOff)
	if err != nil || result.Status != "completed" || len(budgets) != 2 {
		t.Fatalf("result = %+v, err = %v, budgets = %v", result, err, budgets)
	}
	if budgets[0] > time.Second || budgets[1] >= budgets[0]-10*time.Millisecond || budgets[1] <= 0 {
		t.Fatalf("retry reset timeout budget: %v", budgets)
	}
}

func TestRunJudgeDoesNotRetryAfterDeadline(t *testing.T) {
	attempts := 0
	command := judgeRetryCommand(func(cwd string, timeout time.Duration) (CommandOutput, error) {
		attempts++
		time.Sleep(timeout + time.Millisecond)
		return judgeRetryOutput(t, map[string]any{"verdict": "benign"}), nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(t), command, 100*time.Millisecond, nil, SandboxModeOff)
	if err != nil || result.Status != "failed" || attempts != 1 {
		t.Fatalf("result = %+v, err = %v, attempts = %d", result, err, attempts)
	}
}

func TestRunJudgeReceiptRetriesPreserveRedaction(t *testing.T) {
	command := judgeRetryCommand(func(_ string, _ time.Duration) (CommandOutput, error) {
		return CommandOutput{Stdout: `{"summary":"fixture-secret"}`}, nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(t), command, time.Second, map[string]string{"OPENAI_API_KEY": "fixture-secret"}, SandboxModeOff)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attempts) != 2 || bytes.Contains(raw, []byte("fixture-secret")) || !bytes.Contains(raw, []byte("[redacted]")) {
		t.Fatalf("retry evidence did not preserve redaction: %s", raw)
	}
}

func TestRunJudgeReceiptRetryPreparationFailurePreservesEvidence(t *testing.T) {
	artifact := judgeRetryArtifact(t)
	command := judgeRetryCommand(func(_ string, _ time.Duration) (CommandOutput, error) {
		if err := os.RemoveAll(artifact.Target.ResolvedPath); err != nil {
			t.Fatal(err)
		}
		return CommandOutput{Stdout: `{"verdict":"suspicious"}`}, nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, artifact, command, time.Second, nil, SandboxModeOff)
	if err != nil || result.Status != "failed" || len(result.Attempts) != 2 || result.Attempts[0].Result == nil {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	if !strings.Contains(result.Error, "retry could not start") {
		t.Fatalf("retry preparation error missing: %s", result.Error)
	}
}

func TestRunJudgeCustomProfileRemainsSingleAttempt(t *testing.T) {
	artifact := judgeRetryArtifact(t)
	artifact.Profile = "custom"
	attempts := 0
	command := judgeRetryCommand(func(_ string, _ time.Duration) (CommandOutput, error) {
		attempts++
		return CommandOutput{Stdout: `{"ok":true}`}, nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, artifact, command, time.Second, nil, SandboxModeOff)
	if err != nil || result.Status != "completed" || attempts != 1 || len(result.Attempts) != 0 {
		t.Fatalf("result = %+v, err = %v, attempts = %d", result, err, attempts)
	}
}

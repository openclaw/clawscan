package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

func judgeRetryOutput(t *testing.T, result map[string]any) CommandOutput {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return CommandOutput{Stdout: string(raw)}
}

// The runner owns no artifact-inspection receipt. Any judge JSON object is
// accepted as the judge result for every profile, including clawhub.
func TestRunJudgeAcceptsAnyJSONObjectWithoutReceipt(t *testing.T) {
	for _, profile := range []string{"clawhub", "clawhub-aig", "custom"} {
		t.Run(profile, func(t *testing.T) {
			artifact := judgeRetryArtifact(t)
			artifact.Profile = profile
			attempts := 0
			command := judgeRetryCommand(func(cwd string, _ time.Duration) (CommandOutput, error) {
				attempts++
				if _, err := os.Stat(filepath.Join(cwd, "artifact-inspection.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("judge workspace still has an inspection challenge: %v", err)
				}
				return CommandOutput{Stdout: `{"verdict":"benign"}`}, nil
			})
			result, err := RunJudge(JudgeOptions{Command: "judge"}, artifact, command, time.Second, nil, SandboxModeOff)
			if err != nil || result.Status != "completed" || attempts != 1 || len(result.Attempts) != 1 || result.Attempts[0].Status != "completed" {
				t.Fatalf("result = %+v, err = %v, attempts = %d", result, err, attempts)
			}
		})
	}
}

func TestRunJudgeRetriesOnlyUnusableOutputFromASuccessfulCommand(t *testing.T) {
	for _, test := range []struct {
		name         string
		first        func() (CommandOutput, error)
		wantAttempts int
		wantError    string
	}{
		{name: "no_output", first: func() (CommandOutput, error) { return CommandOutput{}, nil }, wantAttempts: 2, wantError: "did not produce JSON output"},
		{name: "invalid_json", first: func() (CommandOutput, error) { return CommandOutput{Stdout: "not json"}, nil }, wantAttempts: 2, wantError: "invalid JSON"},
		{name: "json_array", first: func() (CommandOutput, error) { return CommandOutput{Stdout: `[]`}, nil }, wantAttempts: 2, wantError: "expected JSON object"},
		{name: "command_failure", first: func() (CommandOutput, error) {
			return CommandOutput{Stdout: `{"type":"thread.started"}`, Stderr: "input_too_large"}, errors.New("judge exited 1")
		}, wantAttempts: 1, wantError: "input_too_large"},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempts := 0
			command := judgeRetryCommand(func(_ string, _ time.Duration) (CommandOutput, error) {
				attempts++
				if attempts == 1 {
					return test.first()
				}
				return CommandOutput{Stdout: `{"verdict":"suspicious"}`}, nil
			})
			result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(t), command, time.Second, nil, SandboxModeOff)
			if err != nil {
				t.Fatal(err)
			}
			if attempts != test.wantAttempts || len(result.Attempts) != test.wantAttempts {
				t.Fatalf("attempts = %d, evidence = %d; want %d", attempts, len(result.Attempts), test.wantAttempts)
			}
			if !strings.Contains(result.Attempts[0].Error, test.wantError) {
				t.Fatalf("first attempt error = %q; want %q", result.Attempts[0].Error, test.wantError)
			}
			if test.wantAttempts == 1 {
				if result.Status != "failed" || !strings.Contains(result.Error, test.wantError) {
					t.Fatalf("command failure was masked: %+v", result)
				}
				return
			}
			if result.Status != "completed" || result.Result.(map[string]any)["verdict"] != "suspicious" {
				t.Fatalf("retry did not recover: %+v", result)
			}
		})
	}
}

func TestRunJudgeOutputRetryFailsClosed(t *testing.T) {
	attempts := 0
	command := judgeRetryCommand(func(_ string, _ time.Duration) (CommandOutput, error) {
		attempts++
		return CommandOutput{Stdout: "still not json"}, nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(t), command, time.Second, nil, SandboxModeOff)
	if err != nil || result.Status != "failed" || !strings.Contains(result.Error, "invalid JSON") || attempts != maxJudgeAttempts || len(result.Attempts) != maxJudgeAttempts {
		t.Fatalf("result = %+v, err = %v, attempts = %d", result, err, attempts)
	}
}

func TestRunJudgeDoesNotRetryValidSecurityVerdict(t *testing.T) {
	for _, verdict := range []string{"benign", "suspicious", "malicious"} {
		t.Run(verdict, func(t *testing.T) {
			attempts := 0
			command := judgeRetryCommand(func(_ string, _ time.Duration) (CommandOutput, error) {
				attempts++
				return judgeRetryOutput(t, map[string]any{"verdict": verdict}), nil
			})
			result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(t), command, time.Second, nil, SandboxModeOff)
			if err != nil || result.Status != "completed" || result.Result.(map[string]any)["verdict"] != verdict || attempts != 1 {
				t.Fatalf("result = %+v, err = %v, attempts = %d", result, err, attempts)
			}
		})
	}
}

func TestRunJudgeOutputRetriesShareDeadline(t *testing.T) {
	var budgets []time.Duration
	command := judgeRetryCommand(func(_ string, timeout time.Duration) (CommandOutput, error) {
		budgets = append(budgets, timeout)
		if len(budgets) == 1 {
			time.Sleep(20 * time.Millisecond)
			return CommandOutput{}, nil
		}
		return judgeRetryOutput(t, map[string]any{"verdict": "benign"}), nil
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
	command := judgeRetryCommand(func(_ string, timeout time.Duration) (CommandOutput, error) {
		attempts++
		time.Sleep(timeout + time.Millisecond)
		return CommandOutput{}, nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(t), command, 100*time.Millisecond, nil, SandboxModeOff)
	if err != nil || result.Status != "failed" || attempts != 1 {
		t.Fatalf("result = %+v, err = %v, attempts = %d", result, err, attempts)
	}
}

func TestRunJudgeOutputRetriesPreserveRedaction(t *testing.T) {
	command := judgeRetryCommand(func(_ string, _ time.Duration) (CommandOutput, error) {
		return CommandOutput{Stdout: `"fixture-secret"`}, nil
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

func TestRunJudgeOutputRetryPreparationFailurePreservesEvidence(t *testing.T) {
	artifact := judgeRetryArtifact(t)
	command := judgeRetryCommand(func(_ string, _ time.Duration) (CommandOutput, error) {
		if err := os.RemoveAll(artifact.Target.ResolvedPath); err != nil {
			t.Fatal(err)
		}
		return CommandOutput{Stdout: "not json"}, nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, artifact, command, time.Second, nil, SandboxModeOff)
	if err != nil || result.Status != "failed" || len(result.Attempts) != 2 || result.Attempts[0].Result == nil {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	if !strings.Contains(result.Error, "retry could not start") {
		t.Fatalf("retry preparation error missing: %s", result.Error)
	}
}

// A failed judge command must keep its own error. A judge that enforces its
// own input limit may print a JSON line before rejecting an oversized prompt;
// that partial output must not replace the real error or trigger a retry.
func TestRunClawHubJudgeKeepsCommandError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plugin")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "package.json"), []byte(`{"name":"demo"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	exitCode := 1
	commandRunner := &recordingCommandRunner{
		stdout:   `{"type":"thread.started","thread_id":"t"}`,
		stderr:   `Error: turn/start: turn/start failed: Input exceeds the maximum length of 1048576 characters. (code -32602), data: {"input_error_code":"input_too_large","max_chars":1048576,"actual_chars":1322168}`,
		err:      errCommandFailed,
		exitCode: &exitCode,
	}
	artifact, err := Run(Options{
		Target:          target,
		Profile:         "clawhub",
		Scanners:        []string{fixtureScannerID},
		ScannerRegistry: fixtureScannerRegistry(t),
		Judge: &JudgeOptions{
			Command: "judge --result-file {{ output }}",
		},
	}, RunContext{
		Env:           map[string]string{},
		CommandRunner: commandRunner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Judge == nil || artifact.Judge.Status != "failed" {
		t.Fatalf("judge = %#v", artifact.Judge)
	}
	if !strings.Contains(artifact.Judge.Error, "input_too_large") {
		t.Fatalf("judge error lost the command failure: %q", artifact.Judge.Error)
	}
	if len(commandRunner.calls) != 1 || len(artifact.Judge.Attempts) != 1 {
		t.Fatalf("command failure must not be retried: %d calls", len(commandRunner.calls))
	}
}

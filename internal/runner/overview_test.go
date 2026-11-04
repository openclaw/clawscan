package runner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func overviewArtifact(t *testing.T) Artifact {
	t.Helper()
	artifact := judgeRetryArtifact(t)
	artifact.Judge = &JudgeResult{Status: "completed", Result: map[string]any{"verdict": "suspicious"}}
	return artifact
}

func TestRunOverviewWritesJudgeVerdictIntoWorkspaceAndPrompt(t *testing.T) {
	artifact := overviewArtifact(t)
	var prompt, judge []byte
	command := judgeRetryCommand(func(cwd string, _ time.Duration) (CommandOutput, error) {
		var err error
		if judge, err = os.ReadFile(filepath.Join(cwd, "judge.json")); err != nil {
			t.Fatal(err)
		}
		if prompt, err = os.ReadFile(filepath.Join(cwd, "prompt.md")); err != nil {
			t.Fatal(err)
		}
		return CommandOutput{Stdout: `{"summary":"ok"}`}, nil
	})
	result := RunOverviewContext(context.Background(), OverviewOptions{
		Command: "overview < {{ prompt:overview.md }}",
		Files:   map[string][]byte{"overview.md": []byte("Explain:\n{{ judge.result }}\n")},
	}, artifact, command, time.Second, nil, SandboxModeOff)
	if result.Status != "completed" || result.Error != "" || result.PromptSHA == "" {
		t.Fatalf("result = %+v", result)
	}
	if !strings.Contains(string(judge), `"verdict": "suspicious"`) || !strings.Contains(string(prompt), `"verdict": "suspicious"`) {
		t.Fatalf("judge.json=%s prompt=%s", judge, prompt)
	}
}

func TestRunOverviewTimeoutIsRecordedNotReturned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX sleep command")
	}
	artifact := overviewArtifact(t)
	started := time.Now()
	result := RunOverviewContext(context.Background(), OverviewOptions{Command: "sleep 5"}, artifact,
		defaultCommandRunner{Env: EnvMap(os.Environ())}, 300*time.Millisecond, nil, SandboxModeOff)
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("overview was not bounded by its timeout: %s", elapsed)
	}
	if result.Status != "failed" || !strings.HasPrefix(result.Error, "Overview timed out after 300ms") || result.Result != nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunOverviewStepSkipsWithoutCompletedVerdict(t *testing.T) {
	artifact := judgeRetryArtifact(t)
	artifact.Judge = &JudgeResult{Status: "failed", Error: "judge failed"}
	called := false
	command := &boundCommandRunner{ctx: context.Background(), runner: judgeRetryCommand(func(string, time.Duration) (CommandOutput, error) {
		called = true
		return CommandOutput{}, nil
	})}
	err := runOverviewStep(RunContext{Context: context.Background()}, Options{Overview: &OverviewOptions{Command: "overview"}}, &artifact, command, Options{}, nil, SandboxModeOff)
	if err != nil || called || artifact.Overview == nil || artifact.Overview.Status != "skipped" {
		t.Fatalf("err=%v called=%v overview=%+v", err, called, artifact.Overview)
	}
	if artifact.Judge.Status != "failed" {
		t.Fatalf("overview changed the judge: %+v", artifact.Judge)
	}
}

func TestJudgeResultPromptPlaceholderRequiresCompletedVerdict(t *testing.T) {
	artifact := judgeRetryArtifact(t)
	if _, err := RenderPromptTemplate("{{ judge.result }}", artifact); err == nil || !strings.Contains(err.Error(), "no completed judge verdict") {
		t.Fatalf("err = %v", err)
	}
}

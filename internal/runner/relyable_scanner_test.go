package runner

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type relyableRecordingCommandRunner struct {
	calls  []commandCall
	stdout string
	stderr string
	err    error
}

func (r *relyableRecordingCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	r.calls = append(r.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	return CommandOutput{Stdout: r.stdout, Stderr: r.stderr}, r.err
}

func TestRunExecutesRelyableScannerWithoutHostExecOutsideSandbox(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const relyableJSON = `{"schemaVersion":"relyable-scan-v1","axis":"functional-rederivation","skills":[]}`
	runner := &relyableRecordingCommandRunner{stdout: relyableJSON}
	opts, err := ParseArgs([]string{target, "--scanner", "relyable", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["relyable"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(relyableJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	call := runner.calls[0]
	if call.command != "relyable-scan" {
		t.Fatalf("command = %q", call.command)
	}
	// Outside the Docker sandbox the disposable-host ack must NOT be passed:
	// relyable stays fail-closed and reports UNJUDGEABLE_NO_SANDBOX evidence.
	wantArgs := target + " --json"
	if got := strings.Join(call.args, " "); got != wantArgs {
		t.Fatalf("args = %q, want %q", got, wantArgs)
	}
}

func TestRelyableScannerPassesHostExecAckInDockerSandbox(t *testing.T) {
	runner := ExternalScannerRunner{
		CommandRunner: &relyableRecordingCommandRunner{stdout: `{"ok":true}`},
		SandboxMode:   SandboxModeDocker,
	}
	result, err := runner.runRelyable("/workspace/skill", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	want := "relyable-scan /workspace/skill --json --allow-host-exec"
	if got := strings.Join(result.Command, " "); got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestRelyableScannerCompletesNonZeroExitWithJSONStdout(t *testing.T) {
	const relyableJSON = `{"schemaVersion":"relyable-scan-v1","error":"no SKILL.md found in target or its immediate children"}`
	runner := ExternalScannerRunner{
		CommandRunner: &relyableRecordingCommandRunner{
			stdout: relyableJSON,
			stderr: "",
			err:    errors.New("exit status 2"),
		},
	}
	result, err := runner.runRelyable("/tmp/missing", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q", result.Status)
	}
	if result.Error == "" {
		t.Fatal("expected the command error to be recorded")
	}
	if !bytes.Equal(result.Raw, []byte(relyableJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestRelyableScannerFailsOnEmptyOrInvalidStdout(t *testing.T) {
	for name, stdout := range map[string]string{"empty": "", "invalid": "not json"} {
		runner := ExternalScannerRunner{
			CommandRunner: &relyableRecordingCommandRunner{stdout: stdout},
		}
		result, err := runner.runRelyable("/workspace/skill", "2026-01-01T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "failed" {
			t.Fatalf("%s: status = %q", name, result.Status)
		}
		if result.Raw != nil {
			t.Fatalf("%s: raw = %s", name, result.Raw)
		}
	}
}

func TestRelyableScannerRegistered(t *testing.T) {
	registry := DefaultScannerRegistry()
	if !registry.Contains("relyable") {
		t.Fatal("relyable missing from default scanner registry")
	}
	info, _ := registry.Info("relyable")
	if len(info.RequiredEnv) != 0 {
		t.Fatalf("relyable must not require env vars, got %v", info.RequiredEnv)
	}
	if !info.Installable {
		t.Fatal("relyable should be installable via uv tool install")
	}
}

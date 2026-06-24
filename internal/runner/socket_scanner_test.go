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

func TestParseArgsAcceptsSocketScanner(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "socket"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(opts.Scanners, ","); got != "socket" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestValidateRequirementsRequiresSocketToken(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "socket"})
	if err != nil {
		t.Fatal(err)
	}

	err = ValidateRequirements(opts, map[string]string{})
	if err == nil {
		t.Fatal("expected missing env error")
	}
	if !strings.Contains(err.Error(), "- SOCKET_TOKEN required by scanner socket") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunExecutesSocketScannerWithPreciseSkillTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const socketJSON = `{"id":"scan_123","status":"completed"}`
	runner := &socketRecordingCommandRunner{stdout: socketJSON}
	opts, err := ParseArgs([]string{target, "--scanner", "socket"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SOCKET_TOKEN": "test-socket-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["socket"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(socketJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	call := runner.calls[0]
	if call.command != "npx" {
		t.Fatalf("command = %q", call.command)
	}
	wantArgs := "--yes socket scan create --no-banner --no-spinner --no-interactive --json " + target
	if got := strings.Join(call.args, " "); got != wantArgs {
		t.Fatalf("args = %q, want %q", got, wantArgs)
	}
	if got := strings.Join(result.Command, " "); got != "npx "+wantArgs {
		t.Fatalf("artifact command = %q", got)
	}
	rawArtifact, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawArtifact, []byte("test-socket-secret")) {
		t.Fatalf("artifact leaked SOCKET_TOKEN: %s", rawArtifact)
	}
}

func TestSocketScannerCompletesNonZeroExitWithJSONStdout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const socketJSON = `{"id":"scan_123","status":"failed","alerts":[]}`
	runner := &socketRecordingCommandRunner{
		stdout: socketJSON,
		stderr: "policy violation",
		err:    errors.New("exit status 1"),
	}
	opts, err := ParseArgs([]string{target, "--scanner", "socket"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SOCKET_TOKEN": "test-socket-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["socket"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "exit status 1") || !strings.Contains(result.Error, "policy violation") {
		t.Fatalf("error = %q", result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(socketJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestSocketScannerFailsNonZeroExitWithoutJSONStdout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &socketRecordingCommandRunner{
		stdout: "not json",
		stderr: "authentication failed for test-socket-secret",
		err:    errors.New("exit status 2"),
	}
	opts, err := ParseArgs([]string{target, "--scanner", "socket"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SOCKET_TOKEN": "test-socket-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["socket"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "exit status 2") || !strings.Contains(result.Error, "authentication failed") {
		t.Fatalf("error = %q", result.Error)
	}
	if strings.Contains(result.Error, "test-socket-secret") {
		t.Fatalf("error leaked SOCKET_TOKEN: %q", result.Error)
	}
	if result.Raw != nil {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestSocketScannerFailsSuccessWithoutJSONStdout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &socketRecordingCommandRunner{stdout: ""}
	opts, err := ParseArgs([]string{target, "--scanner", "socket"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SOCKET_TOKEN": "test-socket-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["socket"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "did not return JSON on stdout") {
		t.Fatalf("error = %q", result.Error)
	}
}

func TestSocketScannerFailsSuccessWithInvalidJSONStdout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &socketRecordingCommandRunner{stdout: "not json"}
	opts, err := ParseArgs([]string{target, "--scanner", "socket"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SOCKET_TOKEN": "test-socket-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["socket"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "Socket scanner returned invalid JSON") {
		t.Fatalf("error = %q", result.Error)
	}
	if result.Raw != nil {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestSocketScannerResultFixtureSkipsTokenRequirement(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "socket.json")
	if err := os.WriteFile(fixture, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{
		target,
		"--scanner", "socket",
		"--scanner-result", "socket=" + fixture,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequirements(opts, map[string]string{}); err != nil {
		t.Fatalf("expected fixture-backed Socket result to avoid SOCKET_TOKEN, got %v", err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{},
		CommandRunner: &socketRecordingCommandRunner{err: errors.New("unexpected command")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Scanners["socket"].Status != "completed" {
		t.Fatalf("scanner = %#v", artifact.Scanners["socket"])
	}
	if !bytes.Equal(artifact.Scanners["socket"].Raw, []byte(`{"ok":true}`)) {
		t.Fatalf("raw = %s", artifact.Scanners["socket"].Raw)
	}
}

type socketRecordingCommandRunner struct {
	calls  []commandCall
	stdout string
	stderr string
	err    error
}

func (r *socketRecordingCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	r.calls = append(r.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	return CommandOutput{Stdout: r.stdout, Stderr: r.stderr}, r.err
}

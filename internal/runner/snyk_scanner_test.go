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

func TestRunExecutesSnykScannerWithPreciseSkillTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const snykJSON = `{"ok":true,"issues":[]}`
	runner := &snykRecordingCommandRunner{stdout: snykJSON}
	opts, err := ParseArgs([]string{target, "--scanner", "snyk"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SNYK_TOKEN": "test-snyk-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["snyk"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(snykJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	call := runner.calls[0]
	if call.command != "uvx" {
		t.Fatalf("command = %q", call.command)
	}
	wantArgs := "snyk-agent-scan@latest --json --no-bootstrap --skills " + target
	if got := strings.Join(call.args, " "); got != wantArgs {
		t.Fatalf("args = %q, want %q", got, wantArgs)
	}
	if got := strings.Join(result.Command, " "); got != "uvx "+wantArgs {
		t.Fatalf("artifact command = %q", got)
	}
	rawArtifact, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawArtifact, []byte("test-snyk-secret")) {
		t.Fatalf("artifact leaked SNYK_TOKEN: %s", rawArtifact)
	}
}

func TestSnykScannerCompletesNonZeroExitWithJSONStdout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const snykJSON = `{"ok":false,"issues":[{"id":"prompt-injection"}]}`
	runner := &snykRecordingCommandRunner{
		stdout: snykJSON,
		stderr: "policy violation",
		err:    errors.New("exit status 1"),
	}
	opts, err := ParseArgs([]string{target, "--scanner", "snyk"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SNYK_TOKEN": "test-snyk-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["snyk"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "exit status 1") || !strings.Contains(result.Error, "policy violation") {
		t.Fatalf("error = %q", result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(snykJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestSnykScannerFailsNonZeroExitWithoutJSONStdout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &snykRecordingCommandRunner{
		stdout: "not json",
		stderr: "authentication failed for test-snyk-secret",
		err:    errors.New("exit status 2"),
	}
	opts, err := ParseArgs([]string{target, "--scanner", "snyk"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SNYK_TOKEN": "test-snyk-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["snyk"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "exit status 2") || !strings.Contains(result.Error, "authentication failed") {
		t.Fatalf("error = %q", result.Error)
	}
	if strings.Contains(result.Error, "test-snyk-secret") {
		t.Fatalf("error leaked SNYK_TOKEN: %q", result.Error)
	}
	if result.Raw != nil {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestSnykScannerFailsSuccessWithoutJSONStdout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &snykRecordingCommandRunner{stdout: ""}
	opts, err := ParseArgs([]string{target, "--scanner", "snyk"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SNYK_TOKEN": "test-snyk-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["snyk"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "did not return JSON on stdout") {
		t.Fatalf("error = %q", result.Error)
	}
}

func TestSnykScannerFailsSuccessWithInvalidJSONStdout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &snykRecordingCommandRunner{stdout: "not json"}
	opts, err := ParseArgs([]string{target, "--scanner", "snyk"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SNYK_TOKEN": "test-snyk-secret"},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["snyk"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, errInvalidSnykJSON.Error()) {
		t.Fatalf("error = %q", result.Error)
	}
	if result.Raw != nil {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestSnykScannerResultFixtureSkipsTokenRequirement(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "snyk.json")
	if err := os.WriteFile(fixture, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{
		target,
		"--scanner", "snyk",
		"--scanner-result", "snyk=" + fixture,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequirements(opts, map[string]string{}); err != nil {
		t.Fatalf("expected fixture-backed Snyk result to avoid SNYK_TOKEN, got %v", err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{},
		CommandRunner: &snykRecordingCommandRunner{err: errors.New("unexpected command")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Scanners["snyk"].Status != "completed" {
		t.Fatalf("scanner = %#v", artifact.Scanners["snyk"])
	}
	if !bytes.Equal(artifact.Scanners["snyk"].Raw, []byte(`{"ok":true}`)) {
		t.Fatalf("raw = %s", artifact.Scanners["snyk"].Raw)
	}
}

type snykRecordingCommandRunner struct {
	calls  []commandCall
	stdout string
	stderr string
	err    error
}

func (r *snykRecordingCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	r.calls = append(r.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	return CommandOutput{Stdout: r.stdout, Stderr: r.stderr}, r.err
}

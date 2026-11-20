package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRequirementsRequiresSocketToken(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "socket"})
	if err != nil {
		t.Fatal(err)
	}

	err = ValidateRequirements(opts, map[string]string{})
	if err == nil {
		t.Fatal("expected missing env error")
	}
	if !strings.Contains(err.Error(), "- SOCKET_CLI_API_TOKEN required by scanner socket") {
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
	runner := &stdoutCommandRunner{stdout: socketJSON}
	opts, err := ParseArgs([]string{target, "--scanner", "socket"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"SOCKET_CLI_API_TOKEN": "test-socket-secret"},
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
		t.Fatalf("artifact leaked SOCKET_CLI_API_TOKEN: %s", rawArtifact)
	}
}

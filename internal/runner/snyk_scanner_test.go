package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExecutesSnykScannerWithPreciseSkillTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const snykJSON = `{"ok":true,"issues":[]}`
	runner := &stdoutCommandRunner{stdout: snykJSON}
	artifact := runTestScan(t, []string{target, "--scanner", "snyk"}, RunContext{
		Env:           map[string]string{"SNYK_TOKEN": "test-snyk-secret"},
		CommandRunner: runner,
	})
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
	wantArgs := "snyk-agent-scan@latest scan --json --no-bootstrap --skills " + target
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

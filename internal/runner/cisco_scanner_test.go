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

func TestCiscoScannerCompletesWithJSONOutputFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	const ciscoJSON = `{"scanner":"cisco","findings":[]}`
	runner := &ciscoRecordingCommandRunner{output: ciscoJSON}
	opts, err := ParseArgs([]string{target, "--scanner", "cisco"})
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
	result := artifact.Scanners["cisco"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(ciscoJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	call := runner.calls[0]
	if call.command != "skill-scanner" {
		t.Fatalf("command = %q", call.command)
	}
	if got := strings.Join(call.args[:4], " "); got != "scan "+target+" --format json" {
		t.Fatalf("args = %#v", call.args)
	}
	outputPath := argValue(call.args, "--output")
	if outputPath == "" {
		t.Fatalf("missing --output arg: %#v", call.args)
	}
	if containsArg(call.args, "--use-llm") || containsArg(call.args, "--use-aidefense") || containsArg(call.args, "--use-virustotal") {
		t.Fatalf("unexpected provider-backed Cisco flags: %#v", call.args)
	}
	if artifact.Env["AI_DEFENSE_API_KEY"] != "" || artifact.Env["SKILL_SCANNER_LLM_API_KEY"] != "" || artifact.Env["VIRUSTOTAL_API_KEY"] != "" {
		t.Fatalf("unexpected env requirements: %#v", artifact.Env)
	}
}

func TestCiscoScannerUsesResultDirAsDockerSandboxCWD(t *testing.T) {
	commandRunner := &ciscoRecordingCommandRunner{output: `{"scanner":"cisco","findings":[]}`}
	result, err := (ExternalScannerRunner{
		CommandRunner: commandRunner,
		Env:           map[string]string{},
		SandboxMode:   SandboxModeDocker,
	}).runCisco(t.TempDir(), "2026-07-24T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("result = %#v", result)
	}
	if len(commandRunner.calls) != 1 {
		t.Fatalf("calls = %#v", commandRunner.calls)
	}
	call := commandRunner.calls[0]
	outputPath := argValue(call.args, "--output")
	if call.cwd == "" || call.cwd != filepath.Dir(outputPath) {
		t.Fatalf("cwd = %q, output path = %q", call.cwd, outputPath)
	}
}

func TestCiscoScannerEnablesUpstreamAnalyzersFromEnv(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &ciscoRecordingCommandRunner{output: `{"scanner":"cisco","findings":[]}`}
	opts, err := ParseArgs([]string{target, "--scanner", "cisco"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{
			"SKILL_SCANNER_LLM_API_KEY":           "present",
			"SKILL_SCANNER_META_LLM_MODEL":        "present",
			"VIRUSTOTAL_API_KEY":                  "present",
			"AI_DEFENSE_API_KEY":                  "present",
			"SKILL_SCANNER_LLM_MODEL":             "claude-3-5-sonnet-20241022",
			"SKILL_SCANNER_LLM_PROVIDER":          "anthropic",
			"SKILL_SCANNER_LLM_API_VERSION":       "2025-01-01-preview",
			"SKILL_SCANNER_LLM_FORCE_JSON_OBJECT": "true",
		},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Scanners["cisco"].Status != "completed" {
		t.Fatalf("scanner = %#v", artifact.Scanners["cisco"])
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	call := runner.calls[0]
	for _, want := range []string{"--use-llm", "--enable-meta", "--use-virustotal", "--use-aidefense"} {
		if !containsArg(call.args, want) {
			t.Fatalf("missing %s in args: %#v", want, call.args)
		}
	}
}

func TestCiscoScannerOutputFileIsPreservedInArtifactBundle(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "clawscan-results", "artifact.json")
	const ciscoJSON = `{"scanner":"cisco","findings":[{"id":"network"}]}`
	runner := &ciscoRecordingCommandRunner{output: ciscoJSON}
	opts, err := ParseArgs([]string{target, "--scanner", "cisco", "--output", out})
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

	outputPath := artifact.Scanners["cisco"].OutputPath
	if outputPath != "skill/cisco.json" {
		t.Fatalf("output path = %q", outputPath)
	}
	data, err := os.ReadFile(filepath.Join(dir, "clawscan-results", outputPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != ciscoJSON {
		t.Fatalf("preserved output = %s", data)
	}
}

func TestCiscoScannerCompletesNonZeroExitWithJSONOutputFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	const ciscoJSON = `{"scanner":"cisco","findings":[{"id":"pipeline-risk"}]}`
	runner := &ciscoRecordingCommandRunner{
		output: ciscoJSON,
		stderr: "high severity findings",
		err:    errors.New("exit status 1"),
	}
	opts, err := ParseArgs([]string{target, "--scanner", "cisco"})
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
	result := artifact.Scanners["cisco"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "exit status 1") || !strings.Contains(result.Error, "high severity findings") {
		t.Fatalf("error = %q", result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(ciscoJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestCiscoScannerFailsMissingOutputFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &ciscoRecordingCommandRunner{}
	opts, err := ParseArgs([]string{target, "--scanner", "cisco"})
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
	result := artifact.Scanners["cisco"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "did not write JSON output") {
		t.Fatalf("error = %q", result.Error)
	}
	if result.Raw != nil {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestCiscoScannerFailsInvalidJSONOutputFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &ciscoRecordingCommandRunner{output: "not json"}
	opts, err := ParseArgs([]string{target, "--scanner", "cisco"})
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
	result := artifact.Scanners["cisco"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "invalid JSON") {
		t.Fatalf("error = %q", result.Error)
	}
	if result.Raw != nil {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestRunDispatchesCiscoScannerInsteadOfGenericSkipped(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &ciscoRecordingCommandRunner{output: `{"ok":true}`}
	opts, err := ParseArgs([]string{target, "--scanner", "cisco"})
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
	result := artifact.Scanners["cisco"]
	if result.Status == "skipped" {
		t.Fatalf("generic skipped result leaked through: %#v", result)
	}
	if strings.Contains(result.Error, "foundation slice") {
		t.Fatalf("generic foundation skip leaked through: %q", result.Error)
	}
}

type ciscoRecordingCommandRunner struct {
	calls  []commandCall
	output string
	stderr string
	err    error
}

func (r *ciscoRecordingCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	r.calls = append(r.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	if r.output != "" {
		outputPath := argValue(args, "--output")
		if outputPath != "" {
			if err := os.WriteFile(outputPath, []byte(r.output), 0o644); err != nil {
				return CommandOutput{Stderr: r.stderr}, err
			}
		}
	}
	return CommandOutput{Stderr: r.stderr}, r.err
}

func argValue(args []string, name string) string {
	for i, arg := range args {
		if arg == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

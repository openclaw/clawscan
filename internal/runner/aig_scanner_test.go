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

const aigSARIF = `{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "aig-skill-scan",
        "version": "0.2.1",
        "rules": [
          {"id": "T04", "name": "Embedded Malicious Code"},
          {"id": "T09", "name": "Insecure Skill Coding Practices"}
        ]
      }
    },
    "results": [{
      "ruleId": "T04",
      "level": "error",
      "message": {"text": "Embedded payload"},
      "properties": {"description": "Payload runs locally", "severity": "High"}
    }]
  }]
}`

func TestParseArgsAcceptsAIGScanner(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "aig"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(opts.Scanners, ","); got != "aig" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestValidateRequirementsAcceptsEitherAIGAPIKey(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "aig"})
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range []map[string]string{
		{"LLM_API_KEY": "present"},
		{"OPENAI_API_KEY": "present"},
	} {
		if err := ValidateRequirements(opts, env); err != nil {
			t.Fatalf("env = %#v: %v", env, err)
		}
	}
}

func TestValidateRequirementsRejectsAIGWithoutAPIKey(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "aig"})
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRequirements(opts, map[string]string{})
	if err == nil {
		t.Fatal("expected missing API key error")
	}
	if !strings.Contains(err.Error(), "LLM_API_KEY") || !strings.Contains(err.Error(), "OPENAI_API_KEY") {
		t.Fatalf("error = %q", err)
	}
}

func TestAIGScannerRunsLocalCLIAndPreservesSARIF(t *testing.T) {
	target := createAIGTestSkill(t)
	commandRunner := &aigRecordingCommandRunner{output: aigSARIF}
	opts, err := ParseArgs([]string{target, "--scanner", "aig", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"LLM_API_KEY": "secret-aig-key"},
		CommandRunner: commandRunner,
	})
	if err != nil {
		t.Fatal(err)
	}

	result := artifact.Scanners["aig"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(aigSARIF)) {
		t.Fatalf("raw SARIF changed:\n%s", result.Raw)
	}
	if len(commandRunner.calls) != 1 {
		t.Fatalf("calls = %#v", commandRunner.calls)
	}
	call := commandRunner.calls[0]
	if call.command != "aig-skill-scan" {
		t.Fatalf("command = %q", call.command)
	}
	outputPath := argValue(call.args, "-o")
	if outputPath == "" {
		t.Fatalf("missing -o output path: %#v", call.args)
	}
	if call.cwd != filepath.Dir(outputPath) {
		t.Fatalf("cwd = %q, want writable output directory %q", call.cwd, filepath.Dir(outputPath))
	}
	wantArgs := []string{"--repo", target, "--language", "en", "-o", outputPath}
	if got := strings.Join(call.args, "\x00"); got != strings.Join(wantArgs, "\x00") {
		t.Fatalf("args = %#v, want %#v", call.args, wantArgs)
	}
	if got := artifact.Env["LLM_API_KEY"]; got != "present" {
		t.Fatalf("LLM_API_KEY presence = %q", got)
	}
	if strings.Contains(string(result.Raw), "secret-aig-key") {
		t.Fatalf("raw leaked API key: %s", result.Raw)
	}
}

func TestAIGScannerRecordsOpenAIKeyFallback(t *testing.T) {
	target := createAIGTestSkill(t)
	opts, err := ParseArgs([]string{target, "--scanner", "aig", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"OPENAI_API_KEY": "secret-openai-key"},
		CommandRunner: &aigRecordingCommandRunner{output: aigSARIF},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := artifact.Env["OPENAI_API_KEY"]; got != "present" {
		t.Fatalf("OPENAI_API_KEY presence = %q", got)
	}
	if _, ok := artifact.Env["LLM_API_KEY"]; ok {
		t.Fatalf("unexpected LLM_API_KEY presence: %#v", artifact.Env)
	}
}

func TestAIGScannerDockerRunMountsTargetAndOutputDirectory(t *testing.T) {
	target := createAIGTestSkill(t)
	hostRunner := &aigDockerRecordingCommandRunner{output: aigSARIF}
	opts, err := ParseArgs([]string{target, "--scanner", "aig"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                map[string]string{"LLM_API_KEY": "present"},
		HostCommandRunner:  hostRunner,
		DockerAvailability: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Scanners["aig"].Status != "completed" {
		t.Fatalf("scanner = %#v", artifact.Scanners["aig"])
	}
	if len(hostRunner.calls) != 1 {
		t.Fatalf("calls = %#v", hostRunner.calls)
	}
	call := hostRunner.calls[0]
	if call.command != "docker" {
		t.Fatalf("command = %q", call.command)
	}
	outputPath := argValue(call.args, "-o")
	outputDir := filepath.Dir(outputPath)
	if !containsArgPair(call.args, "-w", outputDir) {
		t.Fatalf("docker args missing writable cwd %q: %#v", outputDir, call.args)
	}
	if !containsMount(call.args, target, true) {
		t.Fatalf("docker args missing read-only target mount %q: %#v", target, call.args)
	}
	if !containsMount(call.args, outputDir, false) {
		t.Fatalf("docker args missing writable output mount %q: %#v", outputDir, call.args)
	}
}

func TestAIGScannerCompletesNonZeroExitWithValidSARIF(t *testing.T) {
	target := createAIGTestSkill(t)
	commandRunner := &aigRecordingCommandRunner{
		output: aigSARIF,
		stderr: "findings require review",
		err:    errors.New("exit status 1"),
	}
	opts, err := ParseArgs([]string{target, "--scanner", "aig", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"LLM_API_KEY": "secret-aig-key"},
		CommandRunner: commandRunner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["aig"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "exit status 1") || !strings.Contains(result.Error, "findings require review") {
		t.Fatalf("error = %q", result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(aigSARIF)) {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestAIGScannerFailsMissingOrInvalidSARIF(t *testing.T) {
	for _, test := range []struct {
		name   string
		output string
		want   string
	}{
		{name: "missing", want: "did not write SARIF output"},
		{name: "invalid json", output: "not json", want: "invalid SARIF 2.1.0 JSON"},
		{name: "wrong version", output: `{"version":"2.0.0","runs":[]}`, want: "invalid SARIF 2.1.0 JSON"},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := createAIGTestSkill(t)
			opts, err := ParseArgs([]string{target, "--scanner", "aig", "--sandbox", "off"})
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := Run(opts, RunContext{
				Env:           map[string]string{"LLM_API_KEY": "present"},
				CommandRunner: &aigRecordingCommandRunner{output: test.output},
			})
			if err != nil {
				t.Fatal(err)
			}
			result := artifact.Scanners["aig"]
			if result.Status != "failed" {
				t.Fatalf("status = %q error = %q", result.Status, result.Error)
			}
			if !strings.Contains(result.Error, test.want) {
				t.Fatalf("error = %q, want %q", result.Error, test.want)
			}
			if result.Raw != nil {
				t.Fatalf("raw = %s", result.Raw)
			}
		})
	}
}

func TestAIGScannerSkipsUnsupportedTargets(t *testing.T) {
	file := filepath.Join(t.TempDir(), "SKILL.md")
	if err := os.WriteFile(file, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{file, "https://github.com/example/skill"} {
		opts, err := ParseArgs([]string{target, "--scanner", "aig", "--sandbox", "off"})
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := Run(opts, RunContext{
			Env:           map[string]string{"LLM_API_KEY": "present"},
			CommandRunner: &aigRecordingCommandRunner{output: aigSARIF},
		})
		if err != nil {
			t.Fatal(err)
		}
		result := artifact.Scanners["aig"]
		if result.Status != "skipped" {
			t.Fatalf("target %q status = %q error = %q", target, result.Status, result.Error)
		}
		if !strings.Contains(result.Error, "directory targets") {
			t.Fatalf("target %q error = %q", target, result.Error)
		}
	}
}

func TestAIGSARIFVerdictNormalizesForBenchmarks(t *testing.T) {
	raw := []byte(`{
	  "version": "2.1.0",
	  "runs": [{
	    "tool": {"driver": {"name": "aig-skill-scan"}},
	    "results": [{"ruleId": "T09"}],
	    "properties": {"verdict": "normal"}
	  }]
	}`)
	prediction, source, err := benchmarkCasePrediction(BenchmarkCase{
		ID: "case-1",
		Run: Artifact{Scanners: map[string]ScannerResult{
			"aig": {Status: "completed", Raw: raw},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if prediction != "clean" || source != "scanner:aig" {
		t.Fatalf("prediction = %q source = %q", prediction, source)
	}
}

func createAIGTestSkill(t *testing.T) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return target
}

type aigRecordingCommandRunner struct {
	calls  []commandCall
	output string
	stderr string
	err    error
}

func (runner *aigRecordingCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	runner.calls = append(runner.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	if runner.output != "" {
		outputPath := argValue(args, "-o")
		if outputPath != "" {
			if err := os.WriteFile(outputPath, []byte(runner.output), 0o644); err != nil {
				return CommandOutput{Stderr: runner.stderr}, err
			}
		}
	}
	return CommandOutput{Stderr: runner.stderr}, runner.err
}

type aigDockerRecordingCommandRunner struct {
	calls  []commandCall
	output string
}

func (runner *aigDockerRecordingCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	runner.calls = append(runner.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	outputPath := argValue(args, "-o")
	if outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(runner.output), 0o644); err != nil {
			return CommandOutput{}, err
		}
	}
	return CommandOutput{}, nil
}

func containsArgPair(args []string, name string, value string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == name && args[index+1] == value {
			return true
		}
	}
	return false
}

func containsMount(args []string, source string, readOnly bool) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] != "--mount" {
			continue
		}
		mount := args[index+1]
		if !strings.Contains(mount, "source="+source+",target="+source) {
			continue
		}
		return strings.HasSuffix(mount, ",readonly") == readOnly
	}
	return false
}

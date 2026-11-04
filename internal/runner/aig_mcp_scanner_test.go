package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const aigMCPSARIF = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "aig-mcp-scan", "version": "0.2.0", "rules": [{"id": "MCP05", "name": "Command Injection and Execution"}]}},
    "results": [{
      "ruleId": "MCP05",
      "level": "error",
      "message": {"text": "Downloads and runs a remote script"},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "index.js"}, "region": {"startLine": 4}}}],
      "properties": {"description": "child_process.exec on fetched code", "severity": "Critical"}
    }],
    "properties": {"securityScore": 10, "scanNote": "complete"}
  }]
}`

func createAIGMCPTestPlugin(t *testing.T) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "plugin")
	for path, content := range map[string]string{
		"openclaw.plugin.json":                   `{"id":"probe-plugin"}`,
		"index.js":                               "export default {};\n",
		"node_modules/dep/index.js":              "module.exports = 1;\n",
		"lib/node_modules/nested/index.js":       "module.exports = 2;\n",
		"lib/not_node_modules/kept.js":           "export {};\n",
		"node_modules.md":                        "kept: only directories named node_modules are dropped\n",
		".git/HEAD":                              "ref: refs/heads/main\n",
		"src/node_modules_like/node_modules/x.j": "dropped\n",
	} {
		full := filepath.Join(target, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return target
}

// aigMCPCommandRunner records each invocation, the staged tree it was shown,
// and writes the configured SARIF to the relative -o path inside cwd.
type aigMCPCommandRunner struct {
	calls    []commandCall
	staged   []string
	output   string
	stderr   string
	err      error
	exitCode *int
}

func (runner *aigMCPCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	runner.calls = append(runner.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	repo := filepath.Join(cwd, argValue(args, "--repo"))
	_ = filepath.WalkDir(repo, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			rel, _ := filepath.Rel(repo, path)
			runner.staged = append(runner.staged, filepath.ToSlash(rel))
		}
		return nil
	})
	if runner.output != "" {
		if err := os.WriteFile(filepath.Join(cwd, argValue(args, "-o")), []byte(runner.output), 0o644); err != nil {
			return CommandOutput{}, err
		}
	}
	return CommandOutput{Stderr: runner.stderr, ExitCode: runner.exitCode}, runner.err
}

func runAIGMCPTest(t *testing.T, target string, env map[string]string, commands CommandRunner) Artifact {
	t.Helper()
	env = withAIGMCPHostExec(env)
	opts, err := ParseArgs([]string{target, "--scanner", "aig-mcp", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{Env: env, CommandRunner: commands})
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

// withAIGMCPHostExec opts unsandboxed unit runs into host execution; the
// recording command runners never execute anything.
func withAIGMCPHostExec(env map[string]string) map[string]string {
	out := map[string]string{aigMCPAllowHostExecEnv: "1"}
	for key, value := range env {
		out[key] = value
	}
	return out
}

func TestAIGMCPStagesPluginWithoutNodeModules(t *testing.T) {
	target := createAIGMCPTestPlugin(t)
	commands := &aigMCPCommandRunner{output: aigMCPSARIF}
	artifact := runAIGMCPTest(t, target, map[string]string{"LLM_API_KEY": "secret-llm-key"}, commands)

	result := artifact.Scanners["aig-mcp"]
	if result.Status != "completed" || string(result.Raw) != aigMCPSARIF {
		t.Fatalf("result = %#v", result)
	}
	want := "index.js,lib/not_node_modules/kept.js,node_modules.md,openclaw.plugin.json"
	if got := strings.Join(commands.staged, ","); got != want {
		t.Fatalf("staged files = %q, want %q", got, want)
	}
	call := commands.calls[0]
	if call.command != "aig-mcp-scan" || strings.HasPrefix(call.cwd, target) {
		t.Fatalf("call = %#v", call)
	}
	if _, err := os.Stat(call.cwd); !os.IsNotExist(err) {
		t.Fatalf("scanner workspace was not removed: %v", err)
	}
	for _, arg := range call.args {
		if strings.Contains(arg, "secret-llm-key") || strings.Contains(arg, target) {
			t.Fatalf("argv carries a secret or host target path: %#v", call.args)
		}
	}
}

func TestAIGMCPModelAndEndpointFollowAIGConventions(t *testing.T) {
	for _, test := range []struct {
		name      string
		env       map[string]string
		wantModel string
		wantURL   string
	}{
		{
			name:      "openai key selects the OpenAI endpoint, never OpenRouter",
			env:       map[string]string{"OPENAI_API_KEY": "k"},
			wantModel: defaultAIGOpenAIModel,
			wantURL:   defaultAIGOpenAIBaseURL,
		},
		{
			name:      "codex key selects the OpenAI endpoint",
			env:       map[string]string{"CODEX_API_KEY": "k"},
			wantModel: defaultAIGOpenAIModel,
			wantURL:   defaultAIGOpenAIBaseURL,
		},
		{
			name:      "aig model and endpoint settings apply",
			env:       map[string]string{"LLM_API_KEY": "k", "DEFAULT_MODEL": "provider/model", "DEFAULT_BASE_URL": "https://llm.example/v1"},
			wantModel: "provider/model",
			wantURL:   "https://llm.example/v1",
		},
		{
			name:      "other tools' model and endpoint settings never pair with the A.I.G key",
			env:       map[string]string{"OPENAI_API_KEY": "k", "LLM_MODEL": "other-model", "OPENAI_MODEL": "other-model", "LLM_BASE_URL": "https://other.example/v1", "OPENAI_BASE_URL": "https://proxy.example/v1"},
			wantModel: defaultAIGOpenAIModel,
			wantURL:   defaultAIGOpenAIBaseURL,
		},
		{
			name:      "a dedicated key keeps A.I.G's own defaults, passed explicitly over host LLM_/OPENAI_ settings",
			env:       map[string]string{"LLM_API_KEY": "k", "LLM_MODEL": "other-model", "OPENAI_BASE_URL": "https://proxy.example/v1"},
			wantModel: aigMCPUpstreamModel,
			wantURL:   aigMCPUpstreamBaseURL,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			commands := &aigMCPCommandRunner{output: aigMCPSARIF}
			runAIGMCPTest(t, createAIGMCPTestPlugin(t), test.env, commands)
			args := commands.calls[0].args
			if got := argValue(args, "-m"); got != test.wantModel {
				t.Fatalf("model = %q, want %q (%#v)", got, test.wantModel, args)
			}
			if got := argValue(args, "-u"); got != test.wantURL {
				t.Fatalf("base URL = %q, want %q (%#v)", got, test.wantURL, args)
			}
			if got := argValue(args, "-p"); got != aigMCPPluginPrompt+aigMCPScopePrompt {
				t.Fatalf("prompt = %q", got)
			}
		})
	}
}

func TestAIGMCPProfileModelDefaultApplies(t *testing.T) {
	opts, err := ParseArgs([]string{createAIGMCPTestPlugin(t), "--scanner", "aig-mcp", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	opts.ScannerEnvDefaults = map[string]string{"DEFAULT_MODEL": "gpt-6.1-sol"}
	commands := &aigMCPCommandRunner{output: aigMCPSARIF}
	if _, err := Run(opts, RunContext{Env: withAIGMCPHostExec(map[string]string{"OPENAI_API_KEY": "k"}), CommandRunner: commands}); err != nil {
		t.Fatal(err)
	}
	if got := argValue(commands.calls[0].args, "-m"); got != "gpt-6.1-sol" {
		t.Fatalf("model = %q", got)
	}
}

func TestAIGMCPRequiresAnAIGAPIKeyOnlyForPlugins(t *testing.T) {
	plugin := createAIGMCPTestPlugin(t)
	opts, err := ParseArgs([]string{plugin, "--scanner", "aig-mcp", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(opts, RunContext{Env: withAIGMCPHostExec(nil), CommandRunner: &aigMCPCommandRunner{}})
	if err == nil || !strings.Contains(err.Error(), "LLM_API_KEY required by scanner aig-mcp (set LLM_API_KEY or OPENAI_API_KEY)") {
		t.Fatalf("err = %v", err)
	}

	commands := &aigMCPCommandRunner{output: aigMCPSARIF}
	artifact := runAIGMCPTest(t, createAIGTestSkill(t), map[string]string{}, commands)
	if len(commands.calls) != 0 {
		t.Fatalf("skill target ran aig-mcp-scan: %#v", commands.calls)
	}
	if result := artifact.Scanners["aig-mcp"]; result.Status != "skipped" || result.Error != "Scanner aig-mcp does not support skill targets." {
		t.Fatalf("result = %#v", result)
	}
}

func TestAIGMCPSkipsNonDirectoryTargets(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.js")
	if err := os.WriteFile(file, []byte("export {};\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commands := &aigMCPCommandRunner{output: aigMCPSARIF}
	runner := ExternalScannerRunner{CommandRunner: commands, Env: withAIGMCPHostExec(map[string]string{"LLM_API_KEY": "k"})}
	for _, target := range []string{file, "https://example.com/plugin"} {
		result, err := runner.runAIGMCP(target, "now")
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "skipped" || !strings.Contains(result.Error, "local plugin directories only") {
			t.Fatalf("target %q result = %#v", target, result)
		}
	}
	if len(commands.calls) != 0 {
		t.Fatalf("calls = %#v", commands.calls)
	}
}

func TestAIGMCPPreservesFailures(t *testing.T) {
	exitOne := 1
	for _, test := range []struct {
		name    string
		runner  *aigMCPCommandRunner
		want    []string
		wantRaw bool
	}{
		{
			name:   "command failure without SARIF",
			runner: &aigMCPCommandRunner{stderr: "openai.AuthenticationError: invalid key secret-llm-key", err: errors.New("exit status 1"), exitCode: &exitOne},
			want:   []string{"exit status 1", "openai.AuthenticationError: invalid key", "aig-mcp-scan did not write SARIF output."},
		},
		{
			name:    "command failure with SARIF",
			runner:  &aigMCPCommandRunner{output: aigMCPSARIF, stderr: "dispatcher close failed", err: errors.New("exit status 1"), exitCode: &exitOne},
			want:    []string{"exit status 1", "dispatcher close failed"},
			wantRaw: true,
		},
		{
			name:   "clean exit without SARIF",
			runner: &aigMCPCommandRunner{stderr: "ERROR | Failed to write output file aig-mcp-scan.sarif.json: disk full"},
			want:   []string{"aig-mcp-scan did not write SARIF output.", "Failed to write output file aig-mcp-scan.sarif.json: disk full"},
		},
		{
			name:    "model returned nothing after retries",
			runner:  &aigMCPCommandRunner{output: aigMCPSARIF, stderr: "ERROR | LLM chat error, retry 5 times, exit\n"},
			want:    []string{"aig-mcp-scan model calls failed", "LLM chat error, retry 5 times"},
			wantRaw: true,
		},
		{
			name:   "invalid SARIF",
			runner: &aigMCPCommandRunner{output: `{"version":"2.0.0","runs":[]}`},
			want:   []string{"aig-mcp-scan returned invalid SARIF 2.1.0 JSON"},
		},
		{
			name:    "model calls failed behind a clean exit",
			runner:  &aigMCPCommandRunner{output: aigMCPSARIF, stderr: "INFO start\nERROR | LLM chat failed after retries: RateLimitError: quota\nINFO done\n"},
			want:    []string{"aig-mcp-scan model calls failed", "LLM chat failed after retries: RateLimitError: quota"},
			wantRaw: true,
		},
		{
			name:    "possibly incomplete audit",
			runner:  &aigMCPCommandRunner{output: strings.Replace(aigMCPSARIF, `"scanNote": "complete"`, `"scanNote": "possibly-incomplete"`, 1)},
			want:    []string{`aig-mcp-scan reported scanNote "possibly-incomplete"`},
			wantRaw: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifact := runAIGMCPTest(t, createAIGMCPTestPlugin(t), map[string]string{"LLM_API_KEY": "secret-llm-key"}, test.runner)
			result := artifact.Scanners["aig-mcp"]
			if result.Status != "failed" {
				t.Fatalf("result = %#v", result)
			}
			for _, want := range test.want {
				if !strings.Contains(result.Error, want) {
					t.Fatalf("error %q missing %q", result.Error, want)
				}
			}
			if strings.Contains(result.Error, "secret-llm-key") {
				t.Fatalf("error leaked the key: %q", result.Error)
			}
			if got := len(result.Raw) != 0; got != test.wantRaw {
				t.Fatalf("raw retained = %v, want %v", got, test.wantRaw)
			}
		})
	}
}

func TestAIGMCPStderrTailIsBounded(t *testing.T) {
	stderr := strings.Repeat("noise line\n", 5000) + "final failure line\n"
	tail := aigMCPStderrTail(stderr)
	if len(tail) > aigMCPStderrTailBytes+64 || !strings.HasSuffix(tail, "final failure line\n") {
		t.Fatalf("tail length = %d", len(tail))
	}
}

func TestAIGMCPDockerRunMountsOnlyTheStagedWorkspace(t *testing.T) {
	target := createAIGMCPTestPlugin(t)
	host := &aigMCPDockerRecordingRunner{output: aigMCPSARIF}
	opts, err := ParseArgs([]string{target, "--scanner", "aig-mcp"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                map[string]string{"OPENAI_API_KEY": "secret-openai-key"},
		HostCommandRunner:  host,
		DockerAvailability: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := artifact.Scanners["aig-mcp"]; result.Status != "completed" {
		t.Fatalf("result = %#v", result)
	}
	args := host.calls[0].args
	workDir := argValue(args, "-w")
	if workDir == "" || !containsMount(args, workDir, false) {
		t.Fatalf("docker args missing writable scanner workspace: %#v", args)
	}
	if !containsArgPair(args, "-e", "OPENAI_API_KEY") {
		t.Fatalf("docker args missing key passthrough: %#v", args)
	}
	for _, arg := range args {
		if strings.Contains(arg, target) || strings.Contains(arg, "secret-openai-key") {
			t.Fatalf("docker args expose the original target or key: %q", arg)
		}
	}
}

type aigMCPDockerRecordingRunner struct {
	calls  []commandCall
	output string
}

func (runner *aigMCPDockerRecordingRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	runner.calls = append(runner.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	workDir := argValue(args, "-w")
	if workDir == "" {
		return CommandOutput{}, fmt.Errorf("missing -w: %v", args)
	}
	return CommandOutput{}, os.WriteFile(filepath.Join(workDir, argValue(args, "-o")), []byte(runner.output), 0o644)
}

func TestAIGMCPSARIFLevelsMapToSeverityAndBenchmarkPredictions(t *testing.T) {
	for level, want := range map[string]string{"error": "high", "ERROR": "high", "warning": "medium", "": "medium", "note": "low", "none": "info"} {
		if got := aigMCPSeverity(level); got != want {
			t.Fatalf("level %q severity = %q, want %q", level, got, want)
		}
	}
	for _, test := range []struct {
		results string
		want    string
	}{
		{results: `[]`, want: "clean"},
		{results: `[{"ruleId":"MCP08","level":"note"}]`, want: "suspicious"},
		{results: `[{"ruleId":"MCP08"}]`, want: "suspicious"},
		{results: `[{"ruleId":"MCP08","level":"warning"},{"ruleId":"MCP01","level":"error"}]`, want: "malicious"},
	} {
		raw := json.RawMessage(`{"version":"2.1.0","runs":[{"results":` + test.results + `}]}`)
		prediction, source, err := benchmarkCasePrediction(BenchmarkCase{
			ID:  "plugin-case",
			Run: Artifact{Scanners: map[string]ScannerResult{"aig-mcp": {Status: "completed", Raw: raw}}},
		})
		if err != nil || prediction != test.want || source != "scanner:aig-mcp" {
			t.Fatalf("results %s: prediction = %q source = %q err = %v", test.results, prediction, source, err)
		}
	}
	if _, ok := aigMCPSARIFPrediction(json.RawMessage(`{"version":"2.1.0"}`)); ok {
		t.Fatal("SARIF without runs accepted")
	}
}

func TestClawHubPromptCarriesAIGMCPSARIFRawOnlyWhenPresent(t *testing.T) {
	source := "SYSTEM\n\nAdditional ClawHub policy for this Codex run:\n- policy\n"
	plugin := Artifact{
		Profile:  "clawhub",
		Target:   Target{Kind: targetKindPlugin},
		Scanners: map[string]ScannerResult{"aig-mcp": {Status: "completed", Raw: json.RawMessage(aigMCPSARIF)}},
	}
	prompt, err := RenderClawHubPrompt(source, plugin)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(prompt, "A.I.G MCP plugin code audit SARIF supplied to Codex:") != 1 {
		t.Fatalf("prompt does not carry exactly one aig-mcp SARIF block:\n%s", prompt)
	}
	for _, want := range []string{`"version": "2.1.0"`, `"ruleId": "MCP05"`, `"level": "error"`, `"securityScore": 10`, `"scanNote": "complete"`} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing raw SARIF field %q:\n%s", want, prompt)
		}
	}
	for _, unwanted := range []string{`"prediction"`, `"maxSeverity"`} {
		if strings.Contains(prompt, unwanted) {
			t.Fatalf("judge evidence carries a ClawScan summary field %s:\n%s", unwanted, prompt)
		}
	}
	skill := Artifact{Profile: "clawhub", Target: Target{Kind: targetKindSkill}, Scanners: map[string]ScannerResult{}}
	prompt, err = RenderClawHubPrompt(source, skill)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "A.I.G MCP") {
		t.Fatalf("skill prompt gained plugin evidence:\n%s", prompt)
	}
}

func TestAIGMCPStagingIsBounded(t *testing.T) {
	target := createAIGMCPTestPlugin(t)
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(target, "node_modules", "dep", fmt.Sprintf("f%d.js", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := ExternalScannerRunner{}
	// node_modules never counts toward the bounds.
	if err := stagePluginScanTarget(runner, target, filepath.Join(t.TempDir(), "ok")); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(target, "dist", "bundle.js")
	if err := os.MkdirAll(filepath.Dir(big), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(aigMCPMaxStagedBytes + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	err = stagePluginScanTarget(runner, target, filepath.Join(t.TempDir(), "big"))
	if err == nil || !strings.Contains(err.Error(), "larger than 256 MiB outside node_modules") {
		t.Fatalf("err = %v", err)
	}
	if err := os.Remove(big); err != nil {
		t.Fatal(err)
	}
	many := filepath.Join(target, "many")
	if err := os.MkdirAll(many, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < aigMCPMaxStagedFiles; i++ {
		if err := os.WriteFile(filepath.Join(many, fmt.Sprintf("%05d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err = stagePluginScanTarget(runner, target, filepath.Join(t.TempDir(), "many"))
	if err == nil || !strings.Contains(err.Error(), "more than 20000 files outside node_modules") {
		t.Fatalf("err = %v", err)
	}
}

func TestAIGMCPInstallPinMatchesRuntimeImage(t *testing.T) {
	dockerfile, err := os.ReadFile(filepath.Join("..", "..", "docker", "clawscan-runtime", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerfile), "\nARG AIG_MCP_SCAN_VERSION="+aigMCPScanVersion+"\n") {
		t.Fatalf("runtime Dockerfile does not pin aig-mcp-scan %s", aigMCPScanVersion)
	}
	plan := DefaultScannerRegistry().adapters[aigMCPScannerID].InstallPlan()
	if got := strings.Join(plan.Commands[0].Args, " "); got != "install aig-mcp-scan=="+aigMCPScanVersion {
		t.Fatalf("install plan = %q", got)
	}
}

func TestAIGMCPRefusesHostExecutionWithoutOptIn(t *testing.T) {
	target := createAIGMCPTestPlugin(t)
	opts, err := ParseArgs([]string{target, "--scanner", "aig-mcp", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	commands := &aigMCPCommandRunner{output: aigMCPSARIF}
	artifact, err := Run(opts, RunContext{Env: map[string]string{"LLM_API_KEY": "k"}, CommandRunner: commands})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["aig-mcp"]
	if result.Status != "failed" || !strings.Contains(result.Error, "set AIG_MCP_SCAN_ALLOW_HOST_EXEC=1") {
		t.Fatalf("result = %#v", result)
	}
	if len(commands.calls) != 0 {
		t.Fatalf("scanner ran on the host without opt-in: %#v", commands.calls)
	}
}

func TestAIGMCPPromptListsFilesTheUpstreamSummaryHides(t *testing.T) {
	target := createAIGMCPTestPlugin(t)
	for _, path := range []string{"dist/index.js", "dist/chunks/a.js", "build/tool.js", "src/dist-notes.md", "node_modules/pkg/dist/x.js"} {
		full := filepath.Join(target, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("export {};\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commands := &aigMCPCommandRunner{output: aigMCPSARIF}
	runAIGMCPTest(t, target, map[string]string{"LLM_API_KEY": "k"}, commands)
	prompt := argValue(commands.calls[0].args, "-p")
	if !strings.HasPrefix(prompt, aigMCPPluginPrompt+aigMCPScopePrompt) ||
		!strings.HasSuffix(prompt, "using these paths: plugin/build/tool.js, plugin/dist/chunks/a.js, plugin/dist/index.js.") {
		t.Fatalf("prompt = %q", prompt)
	}

	commands = &aigMCPCommandRunner{output: aigMCPSARIF}
	runAIGMCPTest(t, createAIGMCPTestPlugin(t), map[string]string{"LLM_API_KEY": "k"}, commands)
	if got := argValue(commands.calls[0].args, "-p"); got != aigMCPPluginPrompt+aigMCPScopePrompt {
		t.Fatalf("prompt without hidden files changed: %q", got)
	}

	many := make([]string, aigMCPMaxListedFiles+3)
	for i := range many {
		many[i] = fmt.Sprintf("dist/f%03d.js", i)
	}
	if got := aigMCPPrompt(many); !strings.HasSuffix(got, "plugin/dist/f399.js (and 3 more lower-priority files).") {
		t.Fatalf("bounded prompt suffix = %q", got[len(got)-80:])
	}
}

func TestAIGMCPStagingRefusesEscapingSymlinks(t *testing.T) {
	target := createAIGMCPTestPlugin(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "escape.txt")); err != nil {
		t.Skip("symlinks unavailable")
	}
	opts, err := ParseArgs([]string{target, "--scanner", "aig-mcp", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	commands := &aigMCPCommandRunner{output: aigMCPSARIF}
	artifact, err := Run(opts, RunContext{Env: withAIGMCPHostExec(map[string]string{"LLM_API_KEY": "k"}), CommandRunner: commands})
	if err == nil || !strings.Contains(err.Error(), "refusing artifact symlink outside target: escape.txt") {
		t.Fatalf("err = %v", err)
	}
	if result := artifact.Scanners["aig-mcp"]; result.Status != "failed" || len(commands.calls) != 0 {
		t.Fatalf("result = %#v calls = %#v", result, commands.calls)
	}
}

func TestAIGMCPInventoriesLargePluginsSourceFirst(t *testing.T) {
	root := t.TempDir()
	write := func(rel string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < aigMCPUpstreamTreeFiles; i++ {
		write(fmt.Sprintf("assets/a%03d.png", i))
	}
	write("lib/z-late.js")
	write("lib/types.d.ts")
	write("lib/z-late.js.map")
	write("skills/helper/SKILL.md")
	listed, err := aigMCPListedFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != aigMCPUpstreamTreeFiles+4 {
		t.Fatalf("listed %d files", len(listed))
	}
	if got := strings.Join(listed[:2], ","); got != "lib/z-late.js,skills/helper/SKILL.md" {
		t.Fatalf("source files must come first: %q", got)
	}
	if got := strings.Join(listed[len(listed)-2:], ","); got != "lib/types.d.ts,lib/z-late.js.map" {
		t.Fatalf("declaration and map files must come last: %q", got)
	}

	small := t.TempDir()
	if err := os.WriteFile(filepath.Join(small, "index.js"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if listed, err := aigMCPListedFiles(small); err != nil || len(listed) != 0 {
		t.Fatalf("a plugin within the upstream summary needs no inventory: %v %v", listed, err)
	}
}

func TestSchemaPluginScannersMatchPluginCapableBuiltIns(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "clawscan.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			Profile struct {
				Properties struct {
					PluginScanners struct {
						Items struct {
							Enum []string `json:"enum"`
						} `json:"items"`
					} `json:"pluginScanners"`
				} `json:"properties"`
			} `json:"profile"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, id := range builtInScannerRegistry().IDs() {
		if ScannerSupportsPluginTargets(id) {
			want = append(want, id)
		}
	}
	if got := strings.Join(schema.Defs.Profile.Properties.PluginScanners.Items.Enum, ","); got != strings.Join(want, ",") {
		t.Fatalf("schema pluginScanners enum = %q, plugin-capable built-ins = %q", got, strings.Join(want, ","))
	}
}

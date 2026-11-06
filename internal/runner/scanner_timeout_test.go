package runner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// timeoutRecordingRunner records each command's timeout and answers like the
// scanners' fixtures, so the runner's per-target budget is observable.
type timeoutRecordingRunner struct {
	timeouts map[string]time.Duration
}

func (runner *timeoutRecordingRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	runner.timeouts[command] = timeout
	if output := argValue(args, "-o"); output != "" {
		if !filepath.IsAbs(output) {
			output = filepath.Join(cwd, output)
		}
		if err := os.WriteFile(output, []byte(aigMCPSARIF), 0o644); err != nil {
			return CommandOutput{}, err
		}
	}
	return CommandOutput{Stdout: `{"findings":[]}`}, nil
}

func scannerTimeouts(t *testing.T, target string, scanners ...string) map[string]time.Duration {
	t.Helper()
	args := []string{target, "--sandbox", "off"}
	for _, scanner := range scanners {
		args = append(args, "--scanner", scanner)
	}
	opts, err := ParseArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	commands := &timeoutRecordingRunner{timeouts: map[string]time.Duration{}}
	if _, err := Run(opts, RunContext{Env: withAIGMCPHostExec(map[string]string{"LLM_API_KEY": "k"}), CommandRunner: commands}); err != nil {
		t.Fatal(err)
	}
	return commands.timeouts
}

func TestPluginScannersGetThirtyMinutesAndSkillScannersKeepTwenty(t *testing.T) {
	plugin := scannerTimeouts(t, createAIGMCPTestPlugin(t), "aig-mcp")
	if got := plugin[aigMCPCommand]; got != 30*time.Minute {
		t.Fatalf("plugin aig-mcp-scan timeout = %s, want 30m0s", got)
	}

	skill := scannerTimeouts(t, createAIGTestSkill(t), "aig")
	if got := skill["aig-skill-scan"]; got != 20*time.Minute {
		t.Fatalf("skill aig-skill-scan timeout = %s, want 20m0s", got)
	}
}

func TestScannerTimeoutDependsOnlyOnTargetKind(t *testing.T) {
	for kind, want := range map[string]time.Duration{
		targetKindPlugin: 30 * time.Minute,
		targetKindSkill:  20 * time.Minute,
		targetKindURL:    20 * time.Minute,
	} {
		if got := scannerTimeoutForTarget(kind); got != want {
			t.Fatalf("%s timeout = %s, want %s", kind, got, want)
		}
	}
	// A directly constructed runner without a budget still gives aig-mcp the
	// plugin budget, since it only ever scans plugins.
	commands := &timeoutRecordingRunner{timeouts: map[string]time.Duration{}}
	runner := ExternalScannerRunner{CommandRunner: commands, Env: withAIGMCPHostExec(map[string]string{"LLM_API_KEY": "k"})}
	if _, err := runner.runAIGMCP(createAIGMCPTestPlugin(t), "now"); err != nil {
		t.Fatal(err)
	}
	if got := commands.timeouts[aigMCPCommand]; got != 30*time.Minute {
		t.Fatalf("default aig-mcp-scan timeout = %s, want 30m0s", got)
	}
}

// TestProfilePluginSelectionUsesPluginBudget follows the clawhub profile's
// shape: skill scanners in Scanners, aig-mcp in PluginScanners.
func TestProfilePluginSelectionUsesPluginBudget(t *testing.T) {
	run := func(target string) map[string]time.Duration {
		opts, err := ParseArgs([]string{target, "--scanner", "aig", "--sandbox", "off"})
		if err != nil {
			t.Fatal(err)
		}
		opts.PluginScanners = []string{aigMCPScannerID}
		commands := &timeoutRecordingRunner{timeouts: map[string]time.Duration{}}
		if _, err := Run(opts, RunContext{Env: withAIGMCPHostExec(map[string]string{"LLM_API_KEY": "k"}), CommandRunner: commands}); err != nil {
			t.Fatal(err)
		}
		return commands.timeouts
	}
	if got := run(createAIGMCPTestPlugin(t)); got[aigMCPCommand] != 30*time.Minute || len(got) != 1 {
		t.Fatalf("plugin run timeouts = %v, want only aig-mcp-scan at 30m0s", got)
	}
	if got := run(createAIGTestSkill(t)); got["aig-skill-scan"] != 20*time.Minute || len(got) != 1 {
		t.Fatalf("skill run timeouts = %v, want only aig-skill-scan at 20m0s", got)
	}
}

// TestDockerSandboxPassesPluginBudgetToTheHost checks the default sandboxed
// path: the docker invocation carries the plugin budget.
func TestDockerSandboxPassesPluginBudgetToTheHost(t *testing.T) {
	opts, err := ParseArgs([]string{createAIGMCPTestPlugin(t), "--scanner", "aig-mcp"})
	if err != nil {
		t.Fatal(err)
	}
	host := &dockerTimeoutRecorder{}
	if _, err := Run(opts, RunContext{
		Env:                map[string]string{"LLM_API_KEY": "k"},
		HostCommandRunner:  host,
		DockerAvailability: func() error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if host.timeout != 30*time.Minute {
		t.Fatalf("docker command timeout = %s, want 30m0s", host.timeout)
	}
}

type dockerTimeoutRecorder struct{ timeout time.Duration }

func (recorder *dockerTimeoutRecorder) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	recorder.timeout = timeout
	workDir := argValue(args, "-w")
	return CommandOutput{}, os.WriteFile(filepath.Join(workDir, argValue(args, "-o")), []byte(aigMCPSARIF), 0o644)
}

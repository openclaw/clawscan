package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/clawscan/internal/runner"
)

func TestTemplateProfileUsesOnlyAIGMCPAndExistingEvidenceAdjudication(t *testing.T) {
	root, err := filepath.Abs("../runner/testdata/templates/benign-mixed")
	if err != nil {
		t.Fatal(err)
	}
	opts, err := ResolveArgs([]string{root, "--profile", "clawhub-template"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	existing, err := ResolveArgs([]string{root, "--profile", "clawhub"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(opts.Scanners, ",") != "aig-mcp" || len(opts.PluginScanners) != 0 {
		t.Fatalf("scanner lists = %v %v", opts.Scanners, opts.PluginScanners)
	}
	if opts.Judge == nil || !opts.Judge.EvidenceOnly || opts.Overview == nil || !opts.Overview.EvidenceOnly {
		t.Fatal("adjudication must be evidence-only")
	}
	if opts.Judge.Command != existing.Judge.Command || opts.Overview.Command != existing.Overview.Command {
		t.Fatal("Template changed existing adjudication command or policy paths")
	}
	for _, path := range []string{"clawhub/evidence-judge.md", "clawhub/evidence-judge.schema.json", "clawhub/evidence-overview.md", "clawhub/overview.schema.json"} {
		if string(opts.Judge.Files[path]) != string(existing.Judge.Files[path]) || len(opts.Judge.Files[path]) == 0 {
			t.Fatalf("shared %s differs", path)
		}
	}
	if len(opts.GateRules) != 0 {
		t.Fatal("Template invented severity gate")
	}
}

// Exercise the real profile resolver, scanner adapter and Docker command
// construction without Docker or provider credentials. This is not a live
// container qualification: the host recorder simulates the reviewed runtime.
func TestTemplateProfileDockerDispatchAndEvidenceOnlyVerdict(t *testing.T) {
	root, err := filepath.Abs("../runner/testdata/templates/benign-mixed")
	if err != nil {
		t.Fatal(err)
	}
	image := "example.invalid/reviewed-runtime@sha256:" + strings.Repeat("a", 64)
	opts, err := ResolveArgs([]string{root, "--profile", "clawhub-template", "--sandbox-image", image, "--no-overview"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	commands := &templateDockerRecorder{t: t, image: image}
	artifact, err := runner.Run(opts, runner.RunContext{Env: map[string]string{"OPENAI_API_KEY": "fixture-not-a-real-key", "UNRELATED_SECRET": "must-not-pass"}, HostCommandRunner: commands, DockerAvailability: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if commands.calls != 2 || artifact.Target.Kind != "template" || artifact.Profile != "clawhub-template" {
		t.Fatalf("artifact = %#v calls=%d", artifact.Target, commands.calls)
	}
	if artifact.Scanners["aig-mcp"].Status != "completed" || artifact.Judge == nil || artifact.Judge.Status != "completed" {
		t.Fatalf("incomplete artifact: %#v", artifact)
	}
}

type templateDockerRecorder struct {
	t     *testing.T
	image string
	calls int
}

func (r *templateDockerRecorder) Run(command string, args []string, _ string, _ time.Duration) (runner.CommandOutput, error) {
	r.calls++
	if command != "docker" {
		r.t.Fatalf("executed outside sandbox: %s", command)
	}
	imageIndex := -1
	cwd := ""
	for i, arg := range args {
		if arg == r.image {
			imageIndex = i
		}
		if arg == "-w" && i+1 < len(args) {
			cwd = args[i+1]
		}
		if strings.Contains(arg, "fixture-not-a-real-key") || strings.Contains(arg, "UNRELATED_SECRET") {
			r.t.Fatal("credential value or unrelated variable leaked to argv")
		}
	}
	if imageIndex < 0 || cwd == "" {
		r.t.Fatalf("missing image/cwd: %v", args)
	}
	entry := args[imageIndex+1]
	if r.calls == 1 {
		if entry != "aig-mcp-scan" || !strings.Contains(strings.Join(args, " "), "CLAW.md contains agent instructions") {
			r.t.Fatal("Template scanner/prompt not dispatched")
		}
		if _, err := os.Stat(filepath.Join(cwd, "template", "node_modules", "shipped-helper", "index.js")); err != nil {
			r.t.Fatal("shipped dependency omitted", err)
		}
		raw := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"aig-mcp-scan","version":"0.2.0"}},"properties":{"scanNote":"complete","securityScore":100},"results":[]}]}`
		if err := os.WriteFile(filepath.Join(cwd, "aig-mcp-scan.sarif.json"), []byte(raw), 0600); err != nil {
			r.t.Fatal(err)
		}
		return runner.CommandOutput{}, nil
	}
	if _, err := os.Stat(filepath.Join(cwd, "target")); !os.IsNotExist(err) {
		r.t.Fatal("judge received target artifact")
	}
	entries, err := os.ReadDir(cwd)
	if err != nil {
		r.t.Fatal(err)
	}
	var prompt string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".md") {
			data, _ := os.ReadFile(filepath.Join(cwd, entry.Name()))
			prompt += string(data)
		}
	}
	if !strings.Contains(prompt, "\"kind\": \"template\"") || !strings.Contains(prompt, "\"aig-mcp\"") {
		r.t.Fatalf("judge missing target/evidence: %s", prompt)
	}
	// An existing evidence-only judge result, not native AIG output.
	raw := `{"verdict":"benign","confidence":"high","dimensions":{"purpose_capability":{"status":"ok","confidence":0.9},"instruction_scope":{"status":"ok","confidence":0.9},"install_mechanism":{"status":"ok","confidence":0.9},"environment_proportionality":{"status":"ok","confidence":0.9},"persistence_privilege":{"status":"ok","confidence":0.9}},"scan_findings_in_context":[]}`
	if err := os.WriteFile(filepath.Join(cwd, "judge-output.json"), []byte(raw), 0600); err != nil {
		r.t.Fatal(err)
	}
	return runner.CommandOutput{}, nil
}

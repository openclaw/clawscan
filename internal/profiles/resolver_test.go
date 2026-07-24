package profiles

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/clawscan/internal/runner"
	"gopkg.in/yaml.v3"
)

func TestResolveArgsUsesEmbeddedClawHubProfile(t *testing.T) {
	dir := t.TempDir()

	opts, err := ResolveArgs([]string{"./skill", "--profile", "clawhub"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if opts.Target != "./skill" {
		t.Fatalf("target = %q", opts.Target)
	}
	if opts.ConfigSource != "built-in" {
		t.Fatalf("config source = %q, want built-in", opts.ConfigSource)
	}
	if got := strings.Join(opts.Scanners, ","); got != "skillspector,clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
	if opts.Judge == nil {
		t.Fatal("expected embedded clawhub judge")
	}
	if !strings.Contains(opts.Judge.Command, "codex exec") {
		t.Fatalf("judge command = %q", opts.Judge.Command)
	}
	if !strings.Contains(opts.Judge.Command, "--sandbox {{ judge_sandbox }}") {
		t.Fatalf("judge command missing runtime-aware sandbox placeholder: %q", opts.Judge.Command)
	}
	if strings.Contains(opts.Judge.Command, "{{ prompt:prompt.md }}") {
		t.Fatalf("judge command kept unresolved profile-local prompt placeholder: %q", opts.Judge.Command)
	}
	if !strings.Contains(opts.Judge.Command, "{{ prompt:clawhub/prompt.md }}") {
		t.Fatalf("judge command missing profile-local embedded prompt placeholder: %q", opts.Judge.Command)
	}
	if strings.Contains(opts.Judge.Command, "{{ output_schema:output.schema.json }}") {
		t.Fatalf("judge command kept unresolved profile-local schema placeholder: %q", opts.Judge.Command)
	}
	if !strings.Contains(opts.Judge.Command, "{{ output_schema:clawhub/output.schema.json }}") {
		t.Fatalf("judge command missing profile-local embedded schema placeholder: %q", opts.Judge.Command)
	}
	if string(opts.Judge.Files["clawhub/prompt.md"]) == "" {
		t.Fatal("expected embedded clawhub prompt file")
	}
	if string(opts.Judge.Files["clawhub/output.schema.json"]) == "" {
		t.Fatal("expected embedded clawhub output schema file")
	}
	if got := strings.Join(opts.Sandbox.Env, ","); got != "OPENAI_API_KEY,CODEX_API_KEY,SKILLSPECTOR_PROVIDER" {
		t.Fatalf("sandbox env = %q", got)
	}
}

func TestResolveArgsUsesEmbeddedClawHubAIGCandidateProfile(t *testing.T) {
	dir := t.TempDir()

	clawhub, err := ResolveArgs([]string{"./skill", "--profile", "clawhub"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := ResolveArgs([]string{"./skill", "--profile", "clawhub-aig"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(candidate.Scanners, ","); got != "skillspector,aig" {
		t.Fatalf("scanners = %q", got)
	}
	if candidate.Judge == nil || clawhub.Judge == nil {
		t.Fatal("missing embedded ClawHub judge")
	}
	if candidate.Judge.Command != clawhub.Judge.Command {
		t.Fatalf("candidate judge command differs from clawhub:\n%s\n---\n%s", candidate.Judge.Command, clawhub.Judge.Command)
	}
	for _, path := range []string{"clawhub/prompt.md", "clawhub/output.schema.json"} {
		if string(candidate.Judge.Files[path]) != string(clawhub.Judge.Files[path]) {
			t.Fatalf("candidate judge file %s differs from clawhub", path)
		}
	}
	if got := strings.Join(candidate.Sandbox.Env, ","); got != "OPENAI_API_KEY,CODEX_API_KEY,SKILLSPECTOR_PROVIDER,LLM_API_KEY" {
		t.Fatalf("sandbox env = %q", got)
	}
}

func TestResolveArgsPassesExplicitRunContext(t *testing.T) {
	dir := t.TempDir()
	contextPath := filepath.Join(dir, "clawhub-context.json")
	writeFile(t, contextPath, `{"source":"vt-update"}`)

	opts, err := ResolveArgs([]string{
		"./skill",
		"--profile", "clawhub",
		"--context", contextPath,
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if opts.ContextPath != contextPath {
		t.Fatalf("context path = %q, want %q", opts.ContextPath, contextPath)
	}
}

func TestResolveArgsRejectsMissingExplicitSelection(t *testing.T) {
	dir := t.TempDir()

	for _, args := range [][]string{
		{},
		{"./skill"},
	} {
		_, err := ResolveArgs(args, dir)
		if err == nil {
			t.Fatalf("ResolveArgs(%v) succeeded", args)
		}
		if !strings.Contains(err.Error(), "Pass --scanner, --profile, or --config") {
			t.Fatalf("err = %v", err)
		}
	}
}

func TestResolveArgsTreatsScannerOnlyCommandAsAdHocWithoutDefaultJudge(t *testing.T) {
	dir := t.TempDir()

	opts, err := ResolveArgs([]string{"./skill", "--scanner", "clawscan-static"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
	if opts.Profile != "" {
		t.Fatalf("profile = %q", opts.Profile)
	}
	if opts.Judge != nil {
		t.Fatalf("judge = %#v", opts.Judge)
	}
}

func TestResolveArgsFlagsOnlyRunIgnoresAncestorConfig(t *testing.T) {
	parent := t.TempDir()
	writeFile(t, filepath.Join(parent, ".clawscan.yml"), `version: 1
profiles:
  custom:
    scanners:
      - virustotal
`)
	dir := filepath.Join(parent, "child")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	opts, err := ResolveArgs([]string{"./skill", "--scanner", "clawscan-static"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
	if opts.ConfigSource != "" {
		t.Fatalf("config source = %q, want empty for a flags-only run", opts.ConfigSource)
	}
}

func TestResolveArgsBuiltInProfileProvenanceSurvivesDiscoveredConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), `version: 1
profiles:
  unrelated:
    scanners:
      - clawscan-static
`)

	opts, err := ResolveArgs([]string{"./skill", "--profile", "clawhub", "--discover-config"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if opts.ConfigSource != "built-in" {
		t.Fatalf("config source = %q, want built-in (unrelated discovered config must not claim provenance)", opts.ConfigSource)
	}

	opts, err = ResolveArgs([]string{"./skill", "--profile", "clawhub", "--discover-config"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if opts.ConfigSource != "built-in" {
		t.Fatalf("config source = %q, want built-in when discovery finds nothing", opts.ConfigSource)
	}
}

func TestResolveArgsUnknownProfileDoesNotDiscoverConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), `version: 1
profiles:
  custom:
    scanners:
      - virustotal
`)

	_, err := ResolveArgs([]string{"./skill", "--profile", "custom"}, dir)
	if err == nil {
		t.Fatal("expected unknown profile error")
	}
	want := "Unknown profile: custom (available: clawhub, clawhub-aig)"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

func TestResolveArgsDiscoverConfigFlag_RestoresOldBehavior(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  custom:
    scanners:
      - clawscan-static
`)

	opts, err := ResolveArgs([]string{"./skill", "--profile", "custom", "--discover-config"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if opts.Profile != "custom" {
		t.Fatalf("profile = %q", opts.Profile)
	}
	if opts.ConfigSource != config {
		t.Fatalf("config source = %q, want %q", opts.ConfigSource, config)
	}
	if !opts.DiscoverConfig {
		t.Fatal("DiscoverConfig = false, want true")
	}
}

func TestResolveArgsDiscoverConfigRequiresProfile(t *testing.T) {
	// Without a profile the run would record the discovered file as its
	// ConfigSource while applying none of its settings (sandbox mode/image/
	// env); rejecting is honest, silently ignoring the config is not.
	_, err := ResolveArgs([]string{"./skill", "--scanner", "clawscan-static", "--discover-config"}, t.TempDir())
	if err == nil {
		t.Fatal("expected error for --discover-config without --profile")
	}
	if !strings.Contains(err.Error(), "--discover-config requires --profile") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsConfigAndDiscoverConfigFlagsAreMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	_, err := ResolveArgs([]string{"./skill", "--config", "config.yml", "--discover-config", "--scanner", "clawscan-static"}, dir)
	if err == nil {
		t.Fatal("expected error for --config and --discover-config together")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsExplicitConfigUsesExplicitSource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), `version: 1
profiles:
  builtin:
    scanners:
      - clawscan-static
`)
	explicit := filepath.Join(dir, "custom.yml")
	writeFile(t, explicit, `version: 1
profiles:
  custom:
    scanners:
      - virustotal
`)

	opts, err := ResolveArgs([]string{"./skill", "--config", explicit, "--profile", "custom"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if opts.ConfigSource != explicit {
		t.Fatalf("config source = %q", opts.ConfigSource)
	}
}

func TestResolveArgsAllowsExplicitProfileWithoutTarget(t *testing.T) {
	dir := t.TempDir()

	opts, err := ResolveArgs([]string{"--profile", "clawhub"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if opts.Target != "" {
		t.Fatalf("target = %q", opts.Target)
	}
	if got := strings.Join(opts.Scanners, ","); got != "skillspector,clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestResolveArgsDoesNotRequireVirusTotalForClawHubProfile(t *testing.T) {
	opts, err := ResolveArgs([]string{"./skill", "--profile", "clawhub"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if err := runner.ValidateRequirements(opts, map[string]string{}); err != nil {
		t.Fatalf("unexpected requirement error: %v", err)
	}
	if strings.Contains(strings.Join(opts.Sandbox.Env, ","), "VIRUSTOTAL_API_KEY") {
		t.Fatalf("clawhub sandbox env still includes VirusTotal: %v", opts.Sandbox.Env)
	}
}

func TestResolveArgsAllowsExplicitScannerWithoutTarget(t *testing.T) {
	opts, err := ResolveArgs([]string{"--scanner", "clawscan-static"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if opts.Target != "" {
		t.Fatalf("target = %q", opts.Target)
	}
	if opts.Profile != "" {
		t.Fatalf("profile = %q", opts.Profile)
	}
	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestResolveBenchmarkRunSetForwardsPredictionsOutput(t *testing.T) {
	resolved, err := ResolveBenchmarkRunSet("clawhub-security-signals", []string{
		"--scanner", "clawscan-static",
		"--predictions-output", "./submission/predictions.jsonl",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	opts := resolved.Options[0]
	if opts.Benchmark == nil {
		t.Fatal("missing benchmark options")
	}
	if opts.Benchmark.PredictionsOutputPath != "./submission/predictions.jsonl" {
		t.Fatalf("predictions output = %q", opts.Benchmark.PredictionsOutputPath)
	}
}

func TestResolveBenchmarkRunSetForwardsIDsSource(t *testing.T) {
	resolved, err := ResolveBenchmarkRunSet("SkillTrustBench", []string{
		"--scanner", "clawscan-static",
		"--ids", "./subset.jsonl",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	opts := resolved.Options[0]
	if opts.Benchmark == nil {
		t.Fatal("missing benchmark options")
	}
	if opts.Benchmark.IDsSource != "./subset.jsonl" {
		t.Fatalf("ids source = %q", opts.Benchmark.IDsSource)
	}
}

func TestResolveBenchmarkRunSetUsesDocumentedClawHubAIGCandidateCommand(t *testing.T) {
	const subset = "https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench-results/resolve/main/data/evaluation_subset_10pct.jsonl"

	resolved, err := ResolveBenchmarkRunSet("SkillTrustBench", []string{
		"--profile", "clawhub-aig",
		"--ids", subset,
		"--output", "./artifacts/skilltrustbench-clawhub-aig.json",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	opts := resolved.Options[0]
	if opts.Profile != "clawhub-aig" {
		t.Fatalf("profile = %q", opts.Profile)
	}
	if got := strings.Join(opts.Scanners, ","); got != "skillspector,aig" {
		t.Fatalf("scanners = %q", got)
	}
	if opts.Benchmark == nil || opts.Benchmark.IDsSource != subset {
		t.Fatalf("benchmark = %#v", opts.Benchmark)
	}
	if opts.OutputPath != "./artifacts/skilltrustbench-clawhub-aig.json" {
		t.Fatalf("output path = %q", opts.OutputPath)
	}
}

func TestResolveBenchmarkRunSetRejectsIDsWithLimitOrOffset(t *testing.T) {
	for _, args := range [][]string{
		{"--scanner", "clawscan-static", "--ids", "./subset.jsonl", "--limit", "1"},
		{"--scanner", "clawscan-static", "--ids", "./subset.jsonl", "--offset", "1"},
	} {
		_, err := ResolveBenchmarkRunSet("SkillTrustBench", args, t.TempDir())
		if err == nil || err.Error() != "--ids is mutually exclusive with --limit and --offset" {
			t.Fatalf("args = %#v err = %v", args, err)
		}
	}
}

func TestResolveBenchmarkRunSetUsesProposalClawHubProfileBeforeBuiltIn(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "proposals", "GHSA-abcd-1234-5678", "clawscan.yml"), `version: 1
profiles:
  clawhub:
    scanners:
      - clawscan-static
    json: true
`)

	resolved, err := ResolveBenchmarkRunSet("SkillTrustBench", []string{
		"--config", "proposals/GHSA-abcd-1234-5678/clawscan.yml",
		"--profile", "clawhub",
		"--output", "./artifacts/skilltrustbench-candidate.json",
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	opts := resolved.Options[0]
	if opts.Profile != "clawhub" {
		t.Fatalf("profile = %q", opts.Profile)
	}
	if opts.Benchmark == nil || opts.Benchmark.ID != "cuhk-zhuque/SkillTrustBench" || opts.Benchmark.Split != "benchmark" {
		t.Fatalf("benchmark = %#v", opts.Benchmark)
	}
	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
	if opts.Judge != nil {
		t.Fatalf("expected proposal profile to shadow built-in judge, got %#v", opts.Judge)
	}
	if !opts.JSON {
		t.Fatal("expected proposal profile json setting")
	}
	if opts.OutputPath != "./artifacts/skilltrustbench-candidate.json" {
		t.Fatalf("output = %q", opts.OutputPath)
	}
}

func TestResolveArgsDiscoversNearestProjectConfigAndShadowsBuiltIn(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, parent, `version: 1
profiles:
  clawhub:
    scanners:
      - virustotal
`)
	child := filepath.Join(dir, "nested")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(child, ".clawscan.yml"), `version: 1
profiles:
  clawhub:
    scanners:
      - clawscan-static
    json: true
`)

	opts, err := ResolveArgs([]string{"./skill", "--profile", "clawhub", "--discover-config"}, child)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
	if !opts.JSON {
		t.Fatal("expected project profile json setting")
	}
}

func TestResolveArgsLoadsExplicitConfigAndSkipsDiscovery(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), `version: 1
profiles:
  local:
    scanners:
      - virustotal
`)
	config := filepath.Join(dir, "security", "profile.yml")
	writeFile(t, config, `version: 1
profiles:
  local:
    scanners:
      - clawscan-static
    output: results/run.json
`)

	opts, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "local"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
	wantOutput := filepath.Join(dir, "security", "results", "run.json")
	if opts.OutputPath != wantOutput {
		t.Fatalf("output = %q, want %q", opts.OutputPath, wantOutput)
	}
}

func TestResolveArgsLoadsRelativeExplicitConfigFromCWD(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "security", "profile.yml")
	writeFile(t, config, `version: 1
profiles:
  local:
    scanners:
      - clawscan-static
`)

	opts, err := ResolveArgs([]string{"./skill", "--config", "security/profile.yml", "--profile", "local"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestResolveArgsRejectsAmbiguousDiscoveredConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), "version: 1\nprofiles: {}\n")
	writeFile(t, filepath.Join(dir, ".clawscan.yaml"), "version: 1\nprofiles: {}\n")

	_, err := ResolveArgs([]string{"./skill", "--profile", "clawhub", "--discover-config"}, dir)
	if err == nil || !strings.Contains(err.Error(), "Ambiguous ClawScan config files") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), ".clawscan.yml") || !strings.Contains(err.Error(), ".clawscan.yaml") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsRejectsMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), "version: [\n")

	_, err := ResolveArgs([]string{"./skill", "--profile", "clawhub", "--discover-config"}, dir)
	if err == nil || !strings.Contains(err.Error(), "parse ClawScan config") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsRejectsUnsupportedVersionAndUnknownFields(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yml")
	writeFile(t, config, "version: 2\nprofiles: {}\n")

	_, err := ResolveArgs([]string{"./skill", "--config", config}, dir)
	if err == nil || err.Error() != "Unsupported ClawScan config version: 2" {
		t.Fatalf("err = %v", err)
	}

	writeFile(t, config, "version: 1\nprofiles: {}\ndefaultProfile: clawhub\n")
	_, err = ResolveArgs([]string{"./skill", "--config", config}, dir)
	if err == nil || !strings.Contains(err.Error(), "field defaultProfile not found") {
		t.Fatalf("err = %v", err)
	}

	writeFile(t, config, "version: 1\nprofiles:\n  review:\n    scanners:\n      - id: custom\n        command: custom {{target}}\n        token: example\n")
	_, err = ResolveArgs([]string{"./skill", "--config", config}, dir)
	if err == nil || !strings.Contains(err.Error(), "field token not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsUnknownProfileListsAvailableProfiles(t *testing.T) {
	dir := t.TempDir()

	_, err := ResolveArgs([]string{"./skill", "--profile", "missing"}, dir)
	if err == nil || !strings.Contains(err.Error(), "Unknown profile: missing") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "available: clawhub") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsAppliesCLIOverrides(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "vt.json")
	writeFile(t, fixture, `{"ok":true}`)

	opts, err := ResolveArgs([]string{
		"./skill",
		"--profile", "clawhub",
		"--scanner", "virustotal",
		"--scanner-result", "virustotal=" + fixture,
		"--output", "cli.json",
		"--json",
		"--judge", "judge --out {{ output }}",
		"--sandbox", "off",
		"--sandbox-image", "ghcr.io/acme/runtime:v1",
		"--sandbox-env", "ANTHROPIC_API_KEY",
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(opts.Scanners, ","); got != "virustotal" {
		t.Fatalf("scanners = %q", got)
	}
	if opts.ScannerResultPaths["virustotal"] != fixture {
		t.Fatalf("scanner results = %#v", opts.ScannerResultPaths)
	}
	if opts.OutputPath != "cli.json" {
		t.Fatalf("output = %q", opts.OutputPath)
	}
	if !opts.JSON {
		t.Fatal("expected json override")
	}
	if opts.Judge == nil || opts.Judge.Command != "judge --out {{ output }}" {
		t.Fatalf("judge = %#v", opts.Judge)
	}
	if opts.Sandbox.Mode != "off" {
		t.Fatalf("sandbox mode = %q", opts.Sandbox.Mode)
	}
	if opts.Sandbox.Image != "ghcr.io/acme/runtime:v1" {
		t.Fatalf("sandbox image = %q", opts.Sandbox.Image)
	}
	if got := strings.Join(opts.Sandbox.Env, ","); got != "OPENAI_API_KEY,CODEX_API_KEY,SKILLSPECTOR_PROVIDER,ANTHROPIC_API_KEY" {
		t.Fatalf("sandbox env = %q", got)
	}
}

func TestResolveArgsSupportsSandboxConfig(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
sandbox:
  mode: docker
  image: ghcr.io/acme/default-runtime:v1
  env:
    - OPENAI_API_KEY
profiles:
  review:
    scanners:
      - clawscan-static
    sandbox:
      image: ghcr.io/acme/review-runtime:v2
      env:
        - ANTHROPIC_API_KEY
`)

	opts, err := ResolveArgs([]string{"./skill", "--profile", "review", "--discover-config"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Sandbox.Mode != "docker" {
		t.Fatalf("sandbox mode = %q", opts.Sandbox.Mode)
	}
	if opts.Sandbox.Image != "ghcr.io/acme/review-runtime:v2" {
		t.Fatalf("sandbox image = %q", opts.Sandbox.Image)
	}
	if got := strings.Join(opts.Sandbox.Env, ","); got != "OPENAI_API_KEY,ANTHROPIC_API_KEY" {
		t.Fatalf("sandbox env = %q", got)
	}
}

func TestResolveArgsSupportsSandboxMountConfig(t *testing.T) {
	dir := t.TempDir()
	readOnlyDir := t.TempDir()
	writableDir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, "version: 1\n"+
		"sandbox:\n"+
		"  mounts:\n"+
		"    - "+readOnlyDir+"\n"+
		"    - path: "+writableDir+"\n"+
		"      write: true\n"+
		"profiles:\n"+
		"  review:\n"+
		"    scanners:\n"+
		"      - clawscan-static\n")

	opts, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []runner.SandboxMount{
		{Path: readOnlyDir},
		{Path: writableDir, Write: true},
	}
	if !reflect.DeepEqual(opts.Sandbox.Mounts, want) {
		t.Fatalf("sandbox mounts = %#v, want %#v", opts.Sandbox.Mounts, want)
	}
}

func TestResolveArgsValidatesSandboxMountConfig(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "relative", path: "relative/rules", wantErr: "must be absolute"},
		{name: "missing", path: filepath.Join(t.TempDir(), "missing"), wantErr: "does not exist"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			config := filepath.Join(dir, ".clawscan.yml")
			writeFile(t, config, "version: 1\n"+
				"sandbox:\n"+
				"  mounts:\n"+
				"    - "+test.path+"\n"+
				"profiles:\n"+
				"  review:\n"+
				"    scanners:\n"+
				"      - clawscan-static\n")

			_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestResolveArgsRejectsUnrequestedScannerResultAfterOverrides(t *testing.T) {
	_, err := ResolveArgs([]string{
		"./skill",
		"--profile", "clawhub",
		"--scanner", "clawscan-static",
		"--scanner-result", "virustotal=./vt.json",
	}, t.TempDir())
	if err == nil || err.Error() != "Scanner result provided for unrequested scanner: virustotal" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsResolvesConfigRelativeJudgePlaceholderPaths(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "security", ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - clawscan-static
    judge:
      command: judge --prompt {{ prompt:./prompts/review.md }} --schema {{ output_schema:schemas/out.json }} --out {{ output }}
`)

	opts, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	wantPrompt := "{{ prompt:" + filepath.Join(dir, "security", "prompts", "review.md") + " }}"
	wantSchema := "{{ output_schema:" + filepath.Join(dir, "security", "schemas", "out.json") + " }}"
	if opts.Judge == nil || !strings.Contains(opts.Judge.Command, wantPrompt) || !strings.Contains(opts.Judge.Command, wantSchema) {
		t.Fatalf("judge command = %#v", opts.Judge)
	}
}

func TestResolveArgsRejectsSecretValuesInConfig(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  bad:
    scanners:
      - clawscan-static
    env:
      OPENAI_API_KEY: secret
`)

	_, err := ResolveArgs([]string{"./skill", "--profile", "bad", "--discover-config"}, dir)
	if err == nil || !strings.Contains(err.Error(), "field env not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsRejectsDuplicateScanners(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  dup:
    scanners:
      - clawscan-static
      - clawscan-static
`)

	_, err := ResolveArgs([]string{"./skill", "--profile", "dup", "--discover-config"}, dir)
	if err == nil || err.Error() != "Duplicate scanner in profile dup: clawscan-static" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsParsesUserDefinedScannerAlongsideBuiltIn(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - clawscan-static
      - id: my-scanner
        command: my-scanner --json {{target}}
        env:
          - MY_SCANNER_TOKEN
        targets:
          - plugin
`)

	opts, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static,my-scanner" {
		t.Fatalf("scanners = %q", got)
	}
	adapter, ok := opts.ScannerRegistry.Adapter("my-scanner")
	if !ok {
		t.Fatal("custom scanner missing from run registry")
	}
	if adapter.SupportsTargetKind("skill") {
		t.Fatal("plugin-only custom scanner unexpectedly supports skill targets")
	}
	if !adapter.SupportsTargetKind("plugin") {
		t.Fatal("plugin-only custom scanner does not support plugin targets")
	}
}

func TestResolveArgsParsesUserDefinedScannerExitCodeGateRules(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: blocker
        command: blocker {{target}}
        gate:
          blockOnExitCode: nonzero
      - id: warner
        command: warner {{target}}
        gate:
          warnOnExitCode: [1, 2, 3]
`)

	opts, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	block := opts.GateRules["blocker"].BlockOnExitCode
	if block == nil || !block.Nonzero {
		t.Fatalf("block rule = %#v", block)
	}
	warn := opts.GateRules["warner"].WarnOnExitCode
	if warn == nil || !reflect.DeepEqual(warn.Codes, []int{1, 2, 3}) {
		t.Fatalf("warn rule = %#v", warn)
	}
}

func TestResolveArgsAcceptsSingleExitCodeGateRule(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: blocker
        command: blocker {{target}}
        gate:
          blockOnExitCode: 7
`)
	opts, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := opts.GateRules["blocker"].BlockOnExitCode.Codes; !reflect.DeepEqual(got, []int{7}) {
		t.Fatalf("codes = %#v", got)
	}
}

func TestProfileScannerExitCodeGateRulesRoundTripYAML(t *testing.T) {
	scanner := ProfileScanner{
		ID: "demo", Command: "demo {{target}}", custom: true,
		Gate: &ProfileScannerGate{
			BlockOnExitCode: &profileExitCodeRule{Nonzero: true},
			WarnOnExitCode:  &profileExitCodeRule{Codes: []int{1, 2, 3}},
		},
	}
	encoded, err := yaml.Marshal(scanner)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ProfileScanner
	if err := yaml.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("round trip failed for %s: %v", encoded, err)
	}
	if decoded.Gate == nil || !decoded.Gate.BlockOnExitCode.Nonzero || !reflect.DeepEqual(decoded.Gate.WarnOnExitCode.Codes, []int{1, 2, 3}) {
		t.Fatalf("decoded scanner = %#v from %s", decoded, encoded)
	}
}

func TestResolveArgsRejectsInvalidExitCodeGateRules(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		want  string
	}{
		{name: "negative", rules: "blockOnExitCode: -1", want: "must contain only non-negative integers"},
		{name: "non integer", rules: "blockOnExitCode: nope", want: `must be a non-negative integer, a list of non-negative integers, or "nonzero"`},
		{name: "empty list", rules: "blockOnExitCode: []", want: "must not be an empty list"},
		{name: "overlap", rules: "blockOnExitCode: nonzero\n          warnOnExitCode: [0, 2]", want: "blockOnExitCode and warnOnExitCode both claim exit code 2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			config := filepath.Join(dir, ".clawscan.yml")
			writeFile(t, config, "version: 1\nprofiles:\n  review:\n    scanners:\n      - id: demo\n        command: demo {{target}}\n        gate:\n          "+test.rules+"\n")
			_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestGateRuleForProfileScannerExcludedByCLIOverrideFailsBeforeScanning(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: absent-scanner
        command: absent {{target}}
        gate:
          blockOnExitCode: nonzero
`)
	opts, err := ResolveArgs([]string{target, "--config", config, "--profile", "review", "--scanner", "clawscan-static", "--sandbox", "off"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &profileCommandRunner{stdout: `{}`}
	_, err = runner.Run(opts, runner.RunContext{Env: map[string]string{}, CommandRunner: commandRunner})
	if err == nil || err.Error() != "gate rule references scanner absent-scanner, but it was not requested" {
		t.Fatalf("err = %v", err)
	}
	if commandRunner.command != "" {
		t.Fatalf("scanner executed: %q", commandRunner.command)
	}
}

func TestResolveArgsRejectsUserDefinedScannerIDCollision(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: clawscan-static
        command: custom-static {{target}}
`)

	_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err == nil || err.Error() != "User-defined scanner clawscan-static collides with a built-in scanner ID" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsRejectsIncompleteUserDefinedScanner(t *testing.T) {
	for _, test := range []struct {
		name    string
		entry   string
		wantErr string
	}{
		{name: "missing id", entry: "command: scanner {{target}}", wantErr: "User-defined scanner in profile review must include a non-empty id"},
		{name: "missing command", entry: "id: my-scanner", wantErr: "User-defined scanner my-scanner in profile review must include a non-empty command"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			config := filepath.Join(dir, ".clawscan.yml")
			writeFile(t, config, "version: 1\nprofiles:\n  review:\n    scanners:\n      - "+test.entry+"\n")

			_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
			if err == nil || err.Error() != test.wantErr {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestResolveArgsRejectsUnknownUserDefinedScannerTarget(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: my-scanner
        command: my-scanner {{target}}
        targets:
          - package
`)

	_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err == nil || err.Error() != "User-defined scanner my-scanner in profile review has unsupported target kind: package" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsRejectsInvalidUserDefinedScannerID(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: foo=bar
        command: scanner {{target}}
`)

	_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err == nil || err.Error() != "User-defined scanner foo=bar in profile review has invalid id; use lowercase letters, digits, underscores, and hyphens, starting with a letter or digit" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsRejectsUppercaseUserDefinedScannerID(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: Foo
        command: scanner {{target}}
`)

	_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err == nil || err.Error() != "User-defined scanner Foo in profile review has invalid id; use lowercase letters, digits, underscores, and hyphens, starting with a letter or digit" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsRejectsOversizedUserDefinedScannerID(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	longID := strings.Repeat("a", 65)
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: `+longID+`
        command: scanner {{target}}
`)

	_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err == nil || err.Error() != "User-defined scanner id in profile review is 65 characters; scanner IDs are used as file names and must be at most 64 characters" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsRejectsInlineUserDefinedScannerEnvValue(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: my-scanner
        command: my-scanner {{target}}
        env:
          - API_TOKEN=sk-live-secret
`)

	_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	want := `User-defined scanner my-scanner in profile review has an invalid env entry "API_TOKEN"; declare bare variable names and set values in the environment, not inline`
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
	if err != nil && strings.Contains(err.Error(), "sk-live-secret") {
		t.Fatalf("error leaked the inline env value: %v", err)
	}
}

func TestResolveArgsAllowsBareUserDefinedScannerEnvName(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: my-scanner
        command: my-scanner {{target}}
        env:
          - API_TOKEN
`)

	if _, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir); err != nil {
		t.Fatalf("bare env name rejected: %v", err)
	}
}

func TestResolveArgsRejectsQuotedUserDefinedScannerTargetPlaceholder(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: my-scanner
        command: my-scanner "{{target}}"
`)

	_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err == nil || err.Error() != "User-defined scanner my-scanner in profile review must use {{target}} outside shell quotes" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveArgsAllowsApostropheInShellCommentBeforeTargetPlaceholder(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: my-scanner
        command: |-
          # don't quote the target here
          my-scanner {{target}}
`)

	if _, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir); err != nil {
		t.Fatal(err)
	}
}

func TestResolveArgsRejectsUserDefinedScannerWithoutTargetPlaceholder(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: my-scanner
        command: my-scanner --scan
`)

	_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	want := "User-defined scanner my-scanner in profile review must include an active {{target}} placeholder outside shell quotes and comments so the scanner receives the target"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestResolveArgsRejectsUserDefinedScannerWithOnlyCommentedTargetPlaceholder(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: my-scanner
        command: |-
          # scans {{target}}
          my-scanner --scan
`)

	_, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	want := "User-defined scanner my-scanner in profile review must include an active {{target}} placeholder outside shell quotes and comments so the scanner receives the target"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestResolveArgsSupportsAliasedScannerEntries(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  templates:
    scanners:
      - &builtin clawscan-static
      - &custom
        id: my-scanner
        command: my-scanner {{target}}
  review:
    scanners:
      - *builtin
      - *custom
`)

	opts, err := ResolveArgs([]string{"./skill", "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static,my-scanner" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestUserDefinedScannerRunsThroughDockerAndPreservesRawJSON(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: fixture-scanner
        command: fixture-scan --json {{target}}
`)
	opts, err := ResolveArgs([]string{target, "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	adapter, ok := opts.ScannerRegistry.Adapter("fixture-scanner")
	if !ok || !adapter.SupportsTargetKind("skill") || !adapter.SupportsTargetKind("url") || adapter.SupportsTargetKind("plugin") {
		t.Fatalf("default target support is incorrect: adapter=%#v ok=%v", adapter, ok)
	}
	commandRunner := &profileCommandRunner{stdout: `{"scanner":"fixture","findings":[]}`}
	artifact, err := runner.Run(opts, runner.RunContext{
		Env:                map[string]string{},
		HostCommandRunner:  commandRunner,
		DockerAvailability: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["fixture-scanner"]
	if result.Status != "completed" {
		t.Fatalf("result = %#v", result)
	}
	if !bytes.Equal(result.Raw, []byte(`{"scanner":"fixture","findings":[]}`)) {
		t.Fatalf("raw = %s", result.Raw)
	}
	if commandRunner.command != "docker" {
		t.Fatalf("command = %q", commandRunner.command)
	}
	joined := strings.Join(commandRunner.args, " ")
	if !strings.Contains(joined, "fixture-scan --json") || !strings.Contains(joined, target) || strings.Contains(joined, "{{target}}") {
		t.Fatalf("docker args = %#v", commandRunner.args)
	}
}

func TestUserDefinedScannerMissingEnvFailsBeforeExecution(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: credentialed-scanner
        command: credentialed-scan {{target}}
        env:
          - MY_SCANNER_TOKEN
`)
	opts, err := ResolveArgs([]string{target, "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &profileCommandRunner{stdout: `{}`}
	_, err = runner.Run(opts, runner.RunContext{
		Env:                map[string]string{},
		HostCommandRunner:  commandRunner,
		DockerAvailability: func() error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "MY_SCANNER_TOKEN") {
		t.Fatalf("err = %v", err)
	}
	if commandRunner.command != "" {
		t.Fatalf("scanner executed before env validation: %q %#v", commandRunner.command, commandRunner.args)
	}
}

func TestUserDefinedScannerEnvIsAllowlistedAndRecordedByPresenceOnly(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: credentialed-scanner
        command: credentialed-scan {{target}}
        env:
          - MY_SCANNER_TOKEN
`)
	opts, err := ResolveArgs([]string{target, "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	missingArtifact := runner.NewArtifact(opts, target, "start", "complete", map[string]string{})
	if missingArtifact.Env["MY_SCANNER_TOKEN"] != "missing" {
		t.Fatalf("missing env = %#v", missingArtifact.Env)
	}

	const envValue = "test-value-123"
	commandRunner := &profileCommandRunner{stdout: `{}`}
	artifact, err := runner.Run(opts, runner.RunContext{
		Env:                map[string]string{"MY_SCANNER_TOKEN": envValue},
		HostCommandRunner:  commandRunner,
		DockerAvailability: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Env["MY_SCANNER_TOKEN"] != "present" {
		t.Fatalf("env = %#v", artifact.Env)
	}
	encoded, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(envValue)) {
		t.Fatalf("artifact leaked env value: %s", encoded)
	}
	joined := strings.Join(commandRunner.args, "\x00")
	if !strings.Contains(joined, "\x00-e\x00MY_SCANNER_TOKEN\x00") {
		t.Fatalf("docker args missing env allowlist name: %#v", commandRunner.args)
	}
	if strings.Contains(joined, envValue) {
		t.Fatalf("docker args leaked env value: %#v", commandRunner.args)
	}
}

func TestUserDefinedPluginScannerSkipsSkillTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  review:
    scanners:
      - id: plugin-scanner
        command: plugin-scan {{target}}
        env:
          - PLUGIN_SCANNER_TOKEN
        targets:
          - plugin
        gate:
          blockOnExitCode: nonzero
`)
	opts, err := ResolveArgs([]string{target, "--config", config, "--profile", "review"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &profileCommandRunner{stdout: `{}`}
	artifact, err := runner.Run(opts, runner.RunContext{
		Env:                map[string]string{},
		HostCommandRunner:  commandRunner,
		DockerAvailability: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["plugin-scanner"]
	if result.Status != "skipped" || !strings.Contains(result.Error, "does not support skill targets") {
		t.Fatalf("result = %#v", result)
	}
	if artifact.Gate != "pass" || len(artifact.GateRules) != 0 {
		t.Fatalf("gate = %q, rules = %#v", artifact.Gate, artifact.GateRules)
	}
	if commandRunner.command != "" {
		t.Fatalf("unsupported scanner executed: %q %#v", commandRunner.command, commandRunner.args)
	}
}

func TestResolveArgsRejectsProfileWithoutScannersUnlessCLIOverrides(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  empty:
    json: true
`)

	_, err := ResolveArgs([]string{"./skill", "--profile", "empty", "--discover-config"}, dir)
	if err == nil || err.Error() != "Profile empty must include at least one scanner or use --scanner" {
		t.Fatalf("err = %v", err)
	}

	opts, err := ResolveArgs([]string{"./skill", "--profile", "empty", "--scanner", "clawscan-static", "--discover-config"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(opts.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

type profileCommandRunner struct {
	command string
	args    []string
	stdout  string
}

func (commandRunner *profileCommandRunner) Run(command string, args []string, _ string, _ time.Duration) (runner.CommandOutput, error) {
	commandRunner.command = command
	commandRunner.args = append([]string(nil), args...)
	return runner.CommandOutput{Stdout: commandRunner.stdout}, nil
}

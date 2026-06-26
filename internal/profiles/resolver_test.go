package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/runner"
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
	if got := strings.Join(opts.Scanners, ","); got != "skillspector,virustotal,clawscan-static" {
		t.Fatalf("scanners = %q", got)
	}
	if opts.Judge == nil {
		t.Fatal("expected embedded clawhub judge")
	}
	if !strings.Contains(opts.Judge.Command, "codex exec") {
		t.Fatalf("judge command = %q", opts.Judge.Command)
	}
	if !strings.Contains(opts.Judge.Command, "{{ prompt:clawhub/prompt.md }}") {
		t.Fatalf("judge command missing embedded prompt placeholder: %q", opts.Judge.Command)
	}
	if !strings.Contains(opts.Judge.Command, "{{ output_schema:clawhub/output.schema.json }}") {
		t.Fatalf("judge command missing embedded schema placeholder: %q", opts.Judge.Command)
	}
	if string(opts.Judge.Files["clawhub/prompt.md"]) == "" {
		t.Fatal("expected embedded clawhub prompt file")
	}
	if string(opts.Judge.Files["clawhub/output.schema.json"]) == "" {
		t.Fatal("expected embedded clawhub output schema file")
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

func TestResolveArgsAllowsExplicitProfileWithoutTarget(t *testing.T) {
	dir := t.TempDir()

	opts, err := ResolveArgs([]string{"--profile", "skills-sh"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	if opts.Target != "" {
		t.Fatalf("target = %q", opts.Target)
	}
	if got := strings.Join(opts.Scanners, ","); got != "socket,snyk" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestResolveArgsValidatesBuiltInProfileScannerEnv(t *testing.T) {
	opts, err := ResolveArgs([]string{"./skill", "--profile", "skills-sh"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	err = runner.ValidateRequirements(opts, map[string]string{"SOCKET_CLI_API_TOKEN": "", "SNYK_TOKEN": ""})
	if err == nil {
		t.Fatal("expected missing env error")
	}
	if !strings.Contains(err.Error(), "- SOCKET_CLI_API_TOKEN required by scanner socket") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "- SNYK_TOKEN required by scanner snyk") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaked value: %v", err)
	}
}

func TestResolveArgsValidatesClawHubScannerEnv(t *testing.T) {
	opts, err := ResolveArgs([]string{"./skill", "--profile", "clawhub"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	err = runner.ValidateRequirements(opts, map[string]string{
		"VIRUSTOTAL_API_KEY": "",
		"OPENAI_API_KEY":     "",
	})
	if err == nil {
		t.Fatal("expected missing env error")
	}
	if !strings.Contains(err.Error(), "- VIRUSTOTAL_API_KEY required by scanner virustotal") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "OPENAI_API_KEY") {
		t.Fatalf("err = %v", err)
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

	opts, err := ResolveArgs([]string{"./skill", "--profile", "clawhub"}, child)
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

	_, err := ResolveArgs([]string{"./skill", "--profile", "clawhub"}, dir)
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

	_, err := ResolveArgs([]string{"./skill", "--profile", "clawhub"}, dir)
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
}

func TestResolveArgsUnknownProfileListsAvailableProfiles(t *testing.T) {
	dir := t.TempDir()

	_, err := ResolveArgs([]string{"./skill", "--profile", "missing"}, dir)
	if err == nil || !strings.Contains(err.Error(), "Unknown profile: missing") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "available: clawhub, skills-sh") {
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

	_, err := ResolveArgs([]string{"./skill", "--profile", "bad"}, dir)
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

	_, err := ResolveArgs([]string{"./skill", "--profile", "dup"}, dir)
	if err == nil || err.Error() != "Duplicate scanner in profile dup: clawscan-static" {
		t.Fatalf("err = %v", err)
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

	_, err := ResolveArgs([]string{"./skill", "--profile", "empty"}, dir)
	if err == nil || err.Error() != "Profile empty must include at least one scanner or use --scanner" {
		t.Fatalf("err = %v", err)
	}

	opts, err := ResolveArgs([]string{"./skill", "--profile", "empty", "--scanner", "clawscan-static"}, dir)
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

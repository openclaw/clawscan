package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/runner"
)

func TestRunCommandPrintsHelp(t *testing.T) {
	stdout := captureStdout(t, func() {
		if err := run([]string{"--help"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{
		"Usage:",
		"clawscan install <scanner-id> [scanner-id ...]",
		"clawscan scanners [list|<scanner-id>]",
		"clawscan profiles [-v]",
		"clawscan benchmark list",
		"clawscan benchmark <benchmark-id> --scanner <scanner-id> [flags]",
		"clawscan benchmark <benchmark-id> --profile <profile-name> [flags]",
		"clawscan <target> --scanner <scanner-id> [flags]",
		"clawscan --scanner <scanner-id> [flags]",
		"clawscan --profile clawhub [flags]",
		"--scanner <id>",
		"--context <path>",
		"Install scanner dependencies without running scans.",
		"--profile <name>",
		"--config <path>",
		"--discover-config",
		"Benchmark command flags:",
		"--split <name>",
		"--ids <path-or-url>",
		"--limit <n>",
		"--offset <n>",
		"--predictions-output <path>",
		"clawscan-results/artifact.json",
		"--sandbox <docker|off>",
		"--sandbox-image <image>",
		"--sandbox-env <name>",
		"ghcr.io/openclaw/clawscan-runtime:latest",
		"Catalog commands:",
		"List supported scanners with required env vars.",
		"Print the resolved profile catalog as pasteable YAML.",
		"List supported benchmarks with source datasets and splits.",
		"Supported benchmarks:",
		"cuhk-zhuque/SkillTrustBench",
		"SkillTrustBench",
		"clawhub-security-signals",
		"Accepted scanner IDs:",
		"agentverus, aig, cisco, clawscan-static, relyable, skillspector, snyk, socket, virustotal",
		"Required environment variables:",
		"aig: LLM_API_KEY or OPENAI_API_KEY",
		"SOCKET_CLI_API_TOKEN",
		"SNYK_TOKEN",
		"VIRUSTOTAL_API_KEY",
		"skillspector: no ClawScan-required env vars",
		"cisco: no ClawScan-required env vars",
		"CLAWSCAN_SANDBOX=off",
		"CLAWSCAN_SANDBOX_IMAGE",
		"No target with --scanner, --profile, or --config scans child skill directories under ./skills",
		"--judge <cmd>",
		"{{ workspace }}",
		"{{ prompt[:path] }}",
		"{{ output_schema[:path] }}",
		"{{ output }}",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help missing %q:\n%s", want, stdout)
		}
	}

	if strings.Contains(stdout, "validate-submission") {
		t.Fatalf("help should not expose repository-only submission validation:\n%s", stdout)
	}
	if strings.Contains(stdout, "clawhub judge: OPENAI_API_KEY") {
		t.Fatalf("help should not document profile judge env validation:\n%s", stdout)
	}
}

func TestRunCommandInstallStaticScannerPrintsSkippedStatus(t *testing.T) {
	stdout := captureStdout(t, func() {
		if err := run([]string{"install", "clawscan-static"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(stdout, "clawscan-static: skipped") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "built in") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestRunCommandScannersPrintsCatalogTable(t *testing.T) {
	stdout := captureStdout(t, func() {
		if err := run([]string{"scanners"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})
	aliasStdout := captureStdout(t, func() {
		if err := run([]string{"scanners", "list"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	if stdout != aliasStdout {
		t.Fatalf("scanners and scanners list differ:\n--- scanners ---\n%s\n--- scanners list ---\n%s", stdout, aliasStdout)
	}
	for _, want := range []string{
		"ID",
		"Name",
		"Required env",
		"skillspector",
		"none",
		"virustotal",
		"VIRUSTOTAL_API_KEY",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("scanner catalog missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunCommandScannerDetailPrintsHumanReadableInfo(t *testing.T) {
	stdout := captureStdout(t, func() {
		if err := run([]string{"scanners", "aig"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{
		"Tencent AI-Infra-Guard",
		"ID: aig",
		"Repository: https://github.com/Tencent/AI-Infra-Guard/tree/main/skill-scan",
		"Description: Tencent Zhuque Lab's local directory scanner invoked through aig-skill-scan",
		"Required env vars: LLM_API_KEY",
		"Optional env vars: OPENAI_API_KEY, DEFAULT_MODEL, DEFAULT_BASE_URL, DEFAULT_MODEL_CONTEXT_WINDOW, LOG_LEVEL",
		"Install:",
		"pip install aig-skill-scan",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("scanner detail missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunCommandProfilesPrintsBuiltInProfilesOnly(t *testing.T) {
	dir := t.TempDir()
	removedProfile := "skills" + "-sh"
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), `version: 1
profiles:
  clawhub:
    scanners:
      - clawscan-static
  local-review:
    scanners:
      - snyk
    judge:
      command: judge --out {{ output }}
`)
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{"profiles"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{
		"Profile",
		"Source",
		"Scanners",
		"clawhub",
		"built-in",
		"skillspector, clawscan-static",
		"clawhub-aig",
		"skillspector, aig",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("profiles output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, removedProfile) {
		t.Fatalf("profiles output should not include removed profile %q:\n%s", removedProfile, stdout)
	}
	if strings.Contains(stdout, "local-review") {
		t.Fatalf("profiles output should not include project profile:\n%s", stdout)
	}
}

func TestRunCommandProfilesVerbosePrintsResolvedYAML(t *testing.T) {
	dir := t.TempDir()
	removedProfile := "skills" + "-sh"
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), `version: 1
profiles:
  local-review:
    scanners:
      - clawscan-static
    json: true
`)
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{"profiles", "-v"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{
		"version: 1",
		"profiles:",
		"clawhub:",
		"clawhub-aig:",
		"- skillspector",
		"- aig",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("verbose profiles output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, removedProfile+":") {
		t.Fatalf("verbose profiles output should not include removed profile %q:\n%s", removedProfile, stdout)
	}
	if strings.Contains(stdout, "local-review:") {
		t.Fatalf("verbose profiles output should not include project profile:\n%s", stdout)
	}
}

func TestRunCommandBenchmarkListPrintsCatalogTable(t *testing.T) {
	stdout := captureStdout(t, func() {
		if err := run([]string{"benchmark", "list"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{
		"ID",
		"Name",
		"Default split",
		"Required env",
		"clawhub-security-signals",
		"eval_holdout",
		"eval_holdout, test, train, validation",
		"cuhk-zhuque/SkillTrustBench",
		"benchmark",
		"none",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("benchmark catalog missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunCommandRejectsUnknownCommand(t *testing.T) {
	t.Chdir(t.TempDir())
	err := run([]string{"datasets"}, []string{})
	if err == nil || err.Error() != "Unknown command: datasets" {
		t.Fatalf("err = %v", err)
	}
}

func TestRunCommandShortHelpMatchesLongHelp(t *testing.T) {
	longHelp := captureStdout(t, func() {
		if err := run([]string{"--help"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})
	shortHelp := captureStdout(t, func() {
		if err := run([]string{"-h"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	if shortHelp != longHelp {
		t.Fatalf("-h help did not match --help:\n--- -h ---\n%s\n--- --help ---\n%s", shortHelp, longHelp)
	}
}

func TestRunCommandRequiresExplicitSelection(t *testing.T) {
	t.Chdir(t.TempDir())
	err := run([]string{}, []string{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Pass --scanner, --profile, or --config") {
		t.Fatalf("err = %q", err.Error())
	}
}

func TestRunCommandReportsMissingDefaultSkillsDirectoryWhenScannerExplicit(t *testing.T) {
	t.Chdir(t.TempDir())
	err := run([]string{"--scanner", "clawscan-static"}, []string{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "./skills was not found") {
		t.Fatalf("err = %q", err.Error())
	}
}

func TestRunCommandPrintsBatchJSONForDiscoveredSkills(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, filepath.Join(dir, "skills", "foo"), "# Foo\n")
	writeSkill(t, filepath.Join(dir, "skills", "bar"), "# Bar\n")
	skillSpectorFixture := filepath.Join(dir, "skillspector.json")
	writeFile(t, skillSpectorFixture, `{"status":"clean","findings":[]}`)
	virusTotalFixture := filepath.Join(dir, "virustotal.json")
	writeFile(t, virusTotalFixture, `{"data":{"attributes":{"last_analysis_stats":{"malicious":0}}}}`)
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{
			"--scanner", "skillspector",
			"--scanner", "virustotal",
			"--scanner", "clawscan-static",
			"--scanner-result", "skillspector=" + skillSpectorFixture,
			"--scanner-result", "virustotal=" + virusTotalFixture,
			"--json",
		}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var artifact struct {
		SchemaVersion string `json:"schemaVersion"`
		Profile       string `json:"profile"`
		Runs          []struct {
			Target struct {
				Input string `json:"input"`
			} `json:"target"`
			Scanners map[string]interface{} `json:"scanners"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "clawscan-batch-v1" {
		t.Fatalf("schema = %q", artifact.SchemaVersion)
	}
	if artifact.Profile != "" {
		t.Fatalf("profile = %q", artifact.Profile)
	}
	if len(artifact.Runs) != 2 {
		t.Fatalf("runs = %#v", artifact.Runs)
	}
	if got := artifact.Runs[0].Target.Input + "," + artifact.Runs[1].Target.Input; got != "skills/bar,skills/foo" {
		t.Fatalf("targets = %q", got)
	}
	for _, run := range artifact.Runs {
		if _, ok := run.Scanners["clawscan-static"]; !ok {
			t.Fatalf("missing static scanner for %s: %#v", run.Target.Input, run.Scanners)
		}
	}
}

func TestRunCommandWritesArtifact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "run.json")
	err := run([]string{target, "--scanner", "clawscan-static", "--output", out}, []string{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		SchemaVersion string                 `json:"schemaVersion"`
		Scanners      map[string]interface{} `json:"scanners"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "clawscan-run-v1" {
		t.Fatalf("schema = %q", artifact.SchemaVersion)
	}
	if _, ok := artifact.Scanners["clawscan-static"]; !ok {
		t.Fatalf("missing clawscan-static scanner: %#v", artifact.Scanners)
	}
}

func TestRunCommandScansPluginTargetWithClawHubScanners(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "probe-plugin")
	writePlugin(t, target, "probe-plugin")
	out := filepath.Join(dir, "run.json")
	skillSpectorFixture := filepath.Join(dir, "skillspector.json")
	writeFile(t, skillSpectorFixture, `{"status":"clean","findings":[]}`)
	virusTotalFixture := filepath.Join(dir, "virustotal.json")
	writeFile(t, virusTotalFixture, `{"status":"clean","source":"engines"}`)

	stdout := captureStdout(t, func() {
		if err := run([]string{
			target,
			"--scanner", "skillspector", "--scanner-result", "skillspector=" + skillSpectorFixture,
			"--scanner", "virustotal", "--scanner-result", "virustotal=" + virusTotalFixture,
			"--scanner", "clawscan-static",
			"--output", out,
		}, []string{}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(stdout, "scanner_completed: 3") {
		t.Fatalf("summary missing completed scanner:\n%s", stdout)
	}
	if !strings.Contains(stdout, "scanner_skipped: 0") {
		t.Fatalf("summary has unexpected skipped count:\n%s", stdout)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		Target struct {
			Kind         string `json:"kind"`
			ID           string `json:"id"`
			ResolvedPath string `json:"resolvedPath"`
		} `json:"target"`
		Scanners map[string]struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Target.Kind != "plugin" {
		t.Fatalf("target kind = %q", artifact.Target.Kind)
	}
	if artifact.Target.ID != "probe-plugin" {
		t.Fatalf("target id = %q", artifact.Target.ID)
	}
	for _, scanner := range []string{"skillspector", "virustotal", "clawscan-static"} {
		if result := artifact.Scanners[scanner]; result.Status != "completed" {
			t.Fatalf("%s result = %#v", scanner, result)
		}
	}
}

func TestRunCommandDoesNotAutoDiscoverPlugins(t *testing.T) {
	dir := t.TempDir()
	// A plugin placed under ./skills without a SKILL.md must not be discovered,
	// so plugin auto-discovery cannot silently scan arbitrary package dirs.
	writePlugin(t, filepath.Join(dir, "skills", "probe-plugin"), "probe-plugin")
	t.Chdir(dir)

	err := run([]string{"--scanner", "clawscan-static"}, []string{})
	if err == nil || !strings.Contains(err.Error(), "No valid skills found") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunCommandWritesDefaultOutputAndPrintsKeyValueSummary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Summary\n")
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{target, "--scanner", "clawscan-static"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{
		"targets: 1",
		"scanner_completed: 1",
		"scanner_failed: 0",
		"scanner_skipped: 0",
		"issues_found: 0",
		"full_results: ./clawscan-results/artifact.json",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "clawscan-results", "artifact.json"))
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		SchemaVersion string `json:"schemaVersion"`
		Scanners      map[string]struct {
			OutputPath string `json:"outputPath"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "clawscan-run-v1" {
		t.Fatalf("schema = %q", artifact.SchemaVersion)
	}
	outputPath := artifact.Scanners["clawscan-static"].OutputPath
	if outputPath != "skill/clawscan-static.json" {
		t.Fatalf("scanner output path = %q", outputPath)
	}
	if _, err := os.Stat(filepath.Join(dir, "clawscan-results", outputPath)); err != nil {
		t.Fatalf("scanner output file missing: %v", err)
	}
}

func TestPrintRunSummaryIncludesGateVerdictAndFiredRule(t *testing.T) {
	artifact := runner.Artifact{
		Gate: "block",
		GateRules: []runner.FiredGateRule{
			{Scanner: "my-scanner", Rule: "blockOnExitCode", ExitCode: 3, Action: "block"},
		},
		Scanners: map[string]runner.ScannerResult{},
	}
	var output strings.Builder
	printRunSummary(&output, runner.RunTargetsResult{Single: &artifact}, "")
	if !strings.Contains(output.String(), "gate: block (my-scanner exit 3 -> block)") {
		t.Fatalf("summary missing gate rule:\n%s", output.String())
	}
}

func TestRunCommandJSONDoesNotWriteDefaultOutput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# JSON\n")
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{target, "--scanner", "clawscan-static", "--json"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(stdout, `"schemaVersion": "clawscan-run-v1"`) {
		t.Fatalf("stdout was not artifact JSON:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "clawscan-results")); !os.IsNotExist(err) {
		t.Fatalf("default output directory exists or stat failed: %v", err)
	}
}

func TestRunCommandJSONWithExplicitOutputWritesArtifactBundle(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# JSON output bundle\n")
	out := filepath.Join(dir, "run.json")

	stdout := captureStdout(t, func() {
		if err := run([]string{target, "--scanner", "clawscan-static", "--json", "--output", out}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(stdout, `"schemaVersion": "clawscan-run-v1"`) {
		t.Fatalf("stdout was not artifact JSON:\n%s", stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		Scanners map[string]struct {
			OutputPath string `json:"outputPath"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	outputPath := artifact.Scanners["clawscan-static"].OutputPath
	if outputPath != "run/skill/clawscan-static.json" {
		t.Fatalf("scanner output path = %q", outputPath)
	}
	if _, err := os.Stat(filepath.Join(dir, outputPath)); err != nil {
		t.Fatalf("scanner output file missing: %v", err)
	}
}

func TestRunCommandUsesBuiltInProfile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Profile\n")
	skillSpectorFixture := filepath.Join(dir, "skillspector.json")
	writeFile(t, skillSpectorFixture, `{"status":"clean","findings":[]}`)

	stdout := captureStdout(t, func() {
		if err := run([]string{
			target,
			"--profile", "clawhub",
			"--scanner-result", "skillspector=" + skillSpectorFixture,
			"--judge", clawHubReceiptJudgeCommand(),
			"--sandbox", "off",
			"--json",
		}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var artifact struct {
		Profile  string                 `json:"profile"`
		Scanners map[string]interface{} `json:"scanners"`
		Judge    *struct {
			Status string `json:"status"`
		} `json:"judge"`
	}
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Profile != "clawhub" {
		t.Fatalf("profile = %q", artifact.Profile)
	}
	if _, ok := artifact.Scanners["clawscan-static"]; !ok {
		t.Fatalf("missing clawscan-static scanner: %#v", artifact.Scanners)
	}
	if artifact.Judge == nil || artifact.Judge.Status != "completed" {
		t.Fatalf("judge = %#v", artifact.Judge)
	}
}

func TestRunCommandDiscoversSkillsWithExplicitProfile(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, filepath.Join(dir, "skills", "foo"), "# Foo\n")
	writeSkill(t, filepath.Join(dir, "skills", "bar"), "# Bar\n")
	skillSpectorFixture := filepath.Join(dir, "skillspector.json")
	writeFile(t, skillSpectorFixture, `{"status":"clean","findings":[]}`)
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{
			"--profile", "clawhub",
			"--scanner-result", "skillspector=" + skillSpectorFixture,
			"--judge", clawHubReceiptJudgeCommand(),
			"--sandbox", "off",
			"--json",
		}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var artifact struct {
		SchemaVersion string `json:"schemaVersion"`
		Profile       string `json:"profile"`
		Runs          []struct {
			Target struct {
				Input string `json:"input"`
			} `json:"target"`
			Scanners map[string]interface{} `json:"scanners"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "clawscan-batch-v1" {
		t.Fatalf("schema = %q", artifact.SchemaVersion)
	}
	if artifact.Profile != "clawhub" {
		t.Fatalf("profile = %q", artifact.Profile)
	}
	if len(artifact.Runs) != 2 {
		t.Fatalf("runs = %#v", artifact.Runs)
	}
	if got := artifact.Runs[0].Target.Input + "," + artifact.Runs[1].Target.Input; got != "skills/bar,skills/foo" {
		t.Fatalf("targets = %q", got)
	}
	for _, run := range artifact.Runs {
		if _, ok := run.Scanners["clawscan-static"]; !ok {
			t.Fatalf("missing clawscan-static scanner for %s: %#v", run.Target.Input, run.Scanners)
		}
	}
}

func clawHubReceiptJudgeCommand() string {
	return `set -- "$(sed -n 's/.*"challenge": "\([^"]*\)".*/\1/p' {{ workspace }}/artifact-inspection.json)" "$(sed -n 's/.*"required_file": "\([^"]*\)".*/\1/p' {{ workspace }}/artifact-inspection.json)"; if command -v sha256sum >/dev/null 2>&1; then set -- "$1" "$2" "$(sha256sum {{ workspace }}/"$2" | cut -d ' ' -f 1)"; else set -- "$1" "$2" "$(shasum -a 256 {{ workspace }}/"$2" | cut -d ' ' -f 1)"; fi; printf '{"verdict":"benign","artifact_inspection":{"status":"completed","challenge":"%s","required_file_sha256":"%s","files_inspected":["%s"]}}\n' "$1" "$3" "$2" > {{ output }}`
}

func TestRunCommandUsesProjectProfile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Project profile\n")
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), `version: 1
profiles:
  local:
    scanners:
      - clawscan-static
    json: true
`)
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{target, "--profile", "local", "--discover-config"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var artifact struct {
		Profile  string                 `json:"profile"`
		Scanners map[string]interface{} `json:"scanners"`
	}
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Profile != "local" {
		t.Fatalf("profile = %q", artifact.Profile)
	}
	if _, ok := artifact.Scanners["clawscan-static"]; !ok {
		t.Fatalf("missing clawscan-static scanner: %#v", artifact.Scanners)
	}
}

func TestRunDefaultModeIgnoresConfigWithoutNotice(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Ignored config\n")
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, "version: [\n")
	t.Chdir(dir)

	stdout, stderr := captureOutput(t, func() {
		if err := run([]string{target, "--scanner", "clawscan-static", "--json"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var artifact struct {
		ConfigSource *string `json:"configSource"`
	}
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatalf("stdout is not artifact JSON: %v\n%s", err, stdout)
	}
	if artifact.ConfigSource != nil {
		t.Fatalf("config source = %q, want nil", *artifact.ConfigSource)
	}
	if !strings.Contains(stdout, `"configSource": null`) {
		t.Fatalf("stdout lacks explicit null config source: %s", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestRunWithDiscoverConfigLoadsConfig_NoNotice(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Discovered config\n")
	config := filepath.Join(dir, ".clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  custom:
    scanners:
      - clawscan-static
`)
	t.Chdir(dir)

	stdout, stderr := captureOutput(t, func() {
		if err := run([]string{target, "--profile", "custom", "--discover-config", "--json"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var artifact struct {
		ConfigSource *string `json:"configSource"`
	}
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.ConfigSource == nil {
		t.Fatalf("config source = nil, want %q", config)
	}
	if *artifact.ConfigSource != config {
		t.Fatalf("config source = %q, want %q", *artifact.ConfigSource, config)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestRunWithExplicitConfigLoadsConfig_NoNotice(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Explicit config\n")
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), "version: [\n")
	explicit := filepath.Join(dir, "explicit.yml")
	writeFile(t, explicit, `version: 1
profiles:
  p:
    scanners:
      - clawscan-static
`)
	t.Chdir(dir)

	stdout, stderr := captureOutput(t, func() {
		if err := run([]string{target, "--config", explicit, "--profile", "p", "--json"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var artifact struct {
		ConfigSource *string `json:"configSource"`
	}
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.ConfigSource == nil {
		t.Fatalf("config source = nil, want %q", explicit)
	}
	if *artifact.ConfigSource != explicit {
		t.Fatalf("config source = %q, want %q", *artifact.ConfigSource, explicit)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestBatchArtifactRuns_EachHasConfigSource(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, filepath.Join(dir, "skills", "foo"), "# Foo\n")
	writeSkill(t, filepath.Join(dir, "skills", "bar"), "# Bar\n")
	config := filepath.Join(dir, "security", "clawscan.yml")
	writeFile(t, config, `version: 1
profiles:
  release:
    scanners:
      - clawscan-static
  review:
    scanners:
      - clawscan-static
`)
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{"--config", config, "--json"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var artifact struct {
		SchemaVersion string `json:"schemaVersion"`
		Runs          []struct {
			Profile      string                 `json:"profile"`
			ConfigSource *string                `json:"configSource"`
			Scanners     map[string]interface{} `json:"scanners"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "clawscan-batch-v1" {
		t.Fatalf("schema = %q", artifact.SchemaVersion)
	}
	if len(artifact.Runs) != 4 {
		t.Fatalf("runs = %#v", artifact.Runs)
	}
	if got := artifact.Runs[0].Profile + "," + artifact.Runs[1].Profile + "," + artifact.Runs[2].Profile + "," + artifact.Runs[3].Profile; got != "release,release,review,review" {
		t.Fatalf("profiles = %q", got)
	}
	for _, run := range artifact.Runs {
		if run.ConfigSource == nil {
			t.Fatalf("config source = nil, want %q", config)
		}
		if *run.ConfigSource != config {
			t.Fatalf("config source = %q, want %q", *run.ConfigSource, config)
		}
		if _, ok := run.Scanners["clawscan-static"]; !ok {
			t.Fatalf("missing clawscan-static scanner for %s: %#v", run.Profile, run.Scanners)
		}
	}
}

func TestRunCommandProfilePlusOverride(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Override\n")

	stdout := captureStdout(t, func() {
		if err := run([]string{target, "--profile", "clawhub", "--scanner", "clawscan-static", "--json"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var artifact struct {
		Profile  string                 `json:"profile"`
		Scanners map[string]interface{} `json:"scanners"`
	}
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Profile != "clawhub" {
		t.Fatalf("profile = %q", artifact.Profile)
	}
	if len(artifact.Scanners) != 1 {
		t.Fatalf("scanners = %#v", artifact.Scanners)
	}
	if _, ok := artifact.Scanners["clawscan-static"]; !ok {
		t.Fatalf("missing clawscan-static scanner: %#v", artifact.Scanners)
	}
}

func TestVersionStringIncludesBuildMetadata(t *testing.T) {
	version = "v1.2.3"
	commit = "abc1234"
	date = "2026-06-12T00:00:00Z"
	t.Cleanup(func() {
		version = "dev"
		commit = "unknown"
		date = "unknown"
	})

	got := versionString()
	want := "clawscan v1.2.3 (commit abc1234, built 2026-06-12T00:00:00Z)"
	if got != want {
		t.Fatalf("version = %q, want %q", got, want)
	}
}

func TestRunCommandDoesNotLeakPresentSecrets(t *testing.T) {
	err := run([]string{"./README.md", "--scanner", "virustotal", "--scanner", "snyk"}, []string{"SNYK_TOKEN=secret-snyk"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "VIRUSTOTAL_API_KEY required by scanner virustotal") {
		t.Fatalf("err = %s", err)
	}
	if strings.Contains(err.Error(), "secret-snyk") {
		t.Fatalf("error leaked secret: %s", err)
	}
}

func writeSkill(t *testing.T, dir string, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writePlugin(t *testing.T, dir string, id string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"id":"` + id + `","name":"Probe Plugin","contracts":{"tools":["probe_tool"]}}`
	if err := os.WriteFile(filepath.Join(dir, "openclaw.plugin.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("// synthetic probe\n"), 0o644); err != nil {
		t.Fatal(err)
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

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = write
	t.Cleanup(func() {
		os.Stdout = original
	})

	fn()

	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = original
	return string(out)
}

func captureOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()

	originalStdout := os.Stdout
	originalStderr := os.Stderr
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = stdoutWrite
	os.Stderr = stderrWrite
	t.Cleanup(func() {
		os.Stdout = originalStdout
		os.Stderr = originalStderr
	})

	fn()

	if err := stdoutWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stderrWrite.Close(); err != nil {
		t.Fatal(err)
	}
	stdout, err := io.ReadAll(stdoutRead)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := io.ReadAll(stderrRead)
	if err != nil {
		t.Fatal(err)
	}
	if err := stdoutRead.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stderrRead.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = originalStdout
	os.Stderr = originalStderr
	return string(stdout), string(stderr)
}

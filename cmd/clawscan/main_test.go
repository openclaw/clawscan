package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		"Install scanner dependencies without running scans.",
		"--profile <name>",
		"--config <path>",
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
		"agentverus, aig, cisco, clawscan-static, skillspector, snyk, socket, virustotal",
		"Required environment variables:",
		"aig: no ClawScan-required env vars",
		"It is service-backed: start A.I.G separately",
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
		"Repository: https://github.com/Tencent/AI-Infra-Guard",
		"Description: API-backed MCP Server & Agent Skills scan",
		"Required env vars: none",
		"Optional env vars: AIG_BASE_URL, AIG_API_KEY, AIG_MODEL, AIG_MODEL_API_KEY, AIG_MODEL_BASE_URL, AIG_USERNAME, AIG_SCAN_LANGUAGE, AIG_SCAN_PROMPT, AIG_SCAN_THREAD_COUNT, AIG_POLL_INTERVAL_MS, AIG_POLL_MAX_ATTEMPTS",
		"Service-backed: yes",
		"Setup: Start the upstream A.I.G Docker/API service on localhost or a private network",
		"Smoke test: AIG_BASE_URL=http://localhost:8088 clawscan ./README.md --scanner aig --sandbox off --json",
		"Install:",
		"Run the A.I.G Docker/API service separately",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("scanner detail missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunCommandProfilesPrintsMergedDiscoveredProfiles(t *testing.T) {
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
		".clawscan.yml",
		"clawscan-static",
		"local-review",
		"snyk",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("profiles output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, removedProfile) {
		t.Fatalf("profiles output should not include removed profile %q:\n%s", removedProfile, stdout)
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
		"local-review:",
		"- clawscan-static",
		"json: true",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("verbose profiles output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, removedProfile+":") {
		t.Fatalf("verbose profiles output should not include removed profile %q:\n%s", removedProfile, stdout)
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
	virusTotalFixture := filepath.Join(dir, "virustotal.json")
	writeFile(t, virusTotalFixture, `{"status":"not_found","data":null}`)

	stdout := captureStdout(t, func() {
		if err := run([]string{
			target,
			"--profile", "clawhub",
			"--scanner-result", "skillspector=" + skillSpectorFixture,
			"--scanner-result", "virustotal=" + virusTotalFixture,
			"--judge", "printf '{\"verdict\":\"benign\"}\\n' > {{ output }}",
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
	virusTotalFixture := filepath.Join(dir, "virustotal.json")
	writeFile(t, virusTotalFixture, `{"status":"not_found","data":null}`)
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{
			"--profile", "clawhub",
			"--scanner-result", "skillspector=" + skillSpectorFixture,
			"--scanner-result", "virustotal=" + virusTotalFixture,
			"--judge", "printf '{\"verdict\":\"benign\"}\\n' > {{ output }}",
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
		if err := run([]string{target, "--profile", "local"}, []string{}); err != nil {
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

func TestRunCommandConfigWithoutProfileRunsEveryConfigProfile(t *testing.T) {
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
			Profile  string                 `json:"profile"`
			Scanners map[string]interface{} `json:"scanners"`
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

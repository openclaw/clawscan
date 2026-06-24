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
		"clawscan <target> --scanner <scanner-id> [flags]",
		"clawscan --scanner <scanner-id> [flags]",
		"clawscan --profile clawhub [flags]",
		"clawscan --profile skills-sh [flags]",
		"clawscan --benchmark --scanner <scanner-id> [flags]",
		"clawscan --benchmark OpenClaw/clawhub-security-signals --scanner <scanner-id> [flags]",
		"--scanner <id>",
		"--profile <name>",
		"--config <path>",
		"--benchmark [id]",
		"--split <name>",
		"--limit <n>",
		"--offset <n>",
		"--predictions-output <path>",
		"clawscan-results.json",
		"Supported benchmarks:",
		"cuhk-zhuque/SkillTrustBench",
		"SkillTrustBench",
		"OpenClaw/clawhub-security-signals",
		"Accepted scanner IDs:",
		"agentverus, ai-infra-guard, cisco, clawscan-static, skillspector, snyk, socket, virustotal",
		"Required environment variables:",
		"OPENAI_API_KEY",
		"AIG_BASE_URL",
		"AIG_MODEL",
		"AIG_MODEL_API_KEY",
		"SOCKET_TOKEN",
		"SNYK_TOKEN",
		"VIRUSTOTAL_API_KEY",
		"skillspector: OPENAI_API_KEY by default",
		"AI-Infra-Guard uses the self-hosted A.I.G taskapi",
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
	if !strings.Contains(err.Error(), "Pass --scanner, --profile, --config, or --benchmark") {
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
		"full_results: ./clawscan-results.json",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "clawscan-results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "clawscan-run-v1" {
		t.Fatalf("schema = %q", artifact.SchemaVersion)
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
	if _, err := os.Stat(filepath.Join(dir, "clawscan-results.json")); !os.IsNotExist(err) {
		t.Fatalf("default output file exists or stat failed: %v", err)
	}
}

func TestRunCommandUsesBuiltInProfile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Profile\n")
	skillSpectorFixture := filepath.Join(dir, "skillspector.json")
	writeFile(t, skillSpectorFixture, `{"status":"clean","findings":[]}`)
	virusTotalFixture := filepath.Join(dir, "virustotal.json")
	writeFile(t, virusTotalFixture, `{"data":{"attributes":{"last_analysis_stats":{"malicious":0}}}}`)

	stdout := captureStdout(t, func() {
		if err := run([]string{
			target,
			"--profile", "clawhub",
			"--scanner-result", "skillspector=" + skillSpectorFixture,
			"--scanner-result", "virustotal=" + virusTotalFixture,
			"--judge", "printf '{\"verdict\":\"benign\"}\\n' > {{ output }}",
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
	writeFile(t, virusTotalFixture, `{"data":{"attributes":{"last_analysis_stats":{"malicious":0}}}}`)
	t.Chdir(dir)

	stdout := captureStdout(t, func() {
		if err := run([]string{
			"--profile", "clawhub",
			"--scanner-result", "skillspector=" + skillSpectorFixture,
			"--scanner-result", "virustotal=" + virusTotalFixture,
			"--judge", "printf '{\"verdict\":\"benign\"}\\n' > {{ output }}",
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
		if err := run([]string{target, "--profile", "skills-sh", "--scanner", "clawscan-static", "--json"}, []string{}); err != nil {
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
	if artifact.Profile != "skills-sh" {
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

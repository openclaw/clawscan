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
		"clawscan [target] [flags]",
		"clawscan --profile skills-sh [flags]",
		"clawscan --benchmark --scanner <scanner-id> [flags]",
		"clawscan --benchmark OpenClaw/clawhub-security-signals --scanner <scanner-id> [flags]",
		"clawscan validate-submission <submission-dir> [--json]",
		"--scanner <id>",
		"--profile <name>",
		"--config <path>",
		"--benchmark [id]",
		"--split <name>",
		"--limit <n>",
		"--offset <n>",
		"--predictions-output <path>",
		"Submission validation:",
		"metadata.json",
		"predictions.jsonl",
		"Supported benchmarks:",
		"cuhk-zhuque/SkillTrustBench",
		"SkillTrustBench",
		"OpenClaw/clawhub-security-signals",
		"Accepted scanner IDs:",
		"agentverus, ai-infra-guard, cisco, clawscan-static, gendigital, skillspector, snyk, socket, virustotal",
		"Required environment variables:",
		"AIG_BASE_URL",
		"AIG_MODEL",
		"AIG_MODEL_API_KEY",
		"SOCKET_CLI_API_TOKEN",
		"SNYK_TOKEN",
		"VIRUSTOTAL_API_KEY",
		"CLAWSCAN_SKILLSPECTOR_LLM=1 requires the configured provider key",
		"AI-Infra-Guard uses the self-hosted A.I.G taskapi",
		"Gen Digital supports URL targets only in v1",
		"No target scans child skill directories under ./skills",
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
}

func TestRunCommandValidatesSubmissionJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "metadata.json"), `{
  "schemaVersion": "clawscan-security-signals-submission-v1",
  "benchmark": {
    "dataset": "OpenClaw/clawhub-security-signals",
    "split": "eval_holdout",
    "revision": "fixture-sha"
  },
  "system": {
    "name": "fixture-system",
    "role": "community"
  },
  "verificationStatus": "artifact-validated"
}
`)
	writeFile(t, filepath.Join(dir, "predictions.jsonl"), `{"id":"case-1","prediction":"clean"}
`)
	oldValidator := validateSubmission
	validateSubmission = func(path string) (runner.SecuritySignalsSubmissionResult, error) {
		if path != dir {
			t.Fatalf("submission path = %q", path)
		}
		return runner.SecuritySignalsSubmissionResult{
			SchemaVersion: "clawscan-security-signals-score-v1",
			Benchmark: runner.SecuritySignalsSubmissionBenchmark{
				Dataset:  "OpenClaw/clawhub-security-signals",
				Split:    "eval_holdout",
				Revision: "fixture-sha",
			},
			Metrics: runner.SecuritySignalsSubmissionMetrics{
				CaseCount:    1,
				TrueNegative: 1,
				Precision:    1,
				Recall:       1,
				F1:           1,
			},
		}, nil
	}
	t.Cleanup(func() {
		validateSubmission = oldValidator
	})

	stdout := captureStdout(t, func() {
		if err := run([]string{"validate-submission", dir, "--json"}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	var result runner.SecuritySignalsSubmissionResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	if result.Metrics.CaseCount != 1 || result.Metrics.TrueNegative != 1 || result.Metrics.F1 != 1 {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunCommandValidatesSubmissionSummary(t *testing.T) {
	dir := t.TempDir()
	oldValidator := validateSubmission
	validateSubmission = func(path string) (runner.SecuritySignalsSubmissionResult, error) {
		return runner.SecuritySignalsSubmissionResult{
			Benchmark: runner.SecuritySignalsSubmissionBenchmark{
				Dataset:  "OpenClaw/clawhub-security-signals",
				Split:    "eval_holdout",
				Revision: "fixture-sha",
			},
			Metrics: runner.SecuritySignalsSubmissionMetrics{
				CaseCount:         4,
				TruePositive:      1,
				FalsePositive:     1,
				TrueNegative:      1,
				FalseNegative:     1,
				Precision:         0.5,
				Recall:            0.5,
				F1:                0.5,
				FalsePositiveRate: 0.5,
			},
		}, nil
	}
	t.Cleanup(func() {
		validateSubmission = oldValidator
	})

	stdout := captureStdout(t, func() {
		if err := run([]string{"validate-submission", dir}, []string{}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{
		"Security Signals submission valid: 4 case(s)",
		"dataset=OpenClaw/clawhub-security-signals split=eval_holdout revision=fixture-sha",
		"F1=0.5000 precision=0.5000 recall=0.5000 FPR=0.5000",
		"TP=1 FP=1 TN=1 FN=1",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
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

func TestRunCommandReportsMissingDefaultSkillsDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	err := run([]string{}, []string{})
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
			"--json",
		}, []string{}); err != nil {
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
	if _, ok := artifact.Scanners["clawscan-static"]; !ok {
		t.Fatalf("missing clawscan-static scanner: %#v", artifact.Scanners)
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
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Multi-profile\n")
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
		if err := run([]string{target, "--config", config, "--json"}, []string{}); err != nil {
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
	if len(artifact.Runs) != 2 {
		t.Fatalf("runs = %#v", artifact.Runs)
	}
	if got := artifact.Runs[0].Profile + "," + artifact.Runs[1].Profile; got != "release,review" {
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

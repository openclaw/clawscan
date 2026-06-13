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
		"--scanner <id>",
		"Accepted scanner IDs:",
		"agentverus, cisco, gendigital, skillspector, snyk, static, virustotal",
		"Required environment variables:",
		"SNYK_TOKEN",
		"VIRUSTOTAL_API_KEY",
		"CLAWSCAN_SKILLSPECTOR_LLM=1 requires the configured provider key",
		"Gen Digital supports URL targets only in v1",
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

func TestRunCommandPreservesMissingTargetError(t *testing.T) {
	err := run([]string{}, []string{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "Missing scan target" {
		t.Fatalf("err = %q", err.Error())
	}
}

func TestRunCommandWritesArtifact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "run.json")
	err := run([]string{target, "--scanner", "static", "--output", out}, []string{})
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
	if _, ok := artifact.Scanners["static"]; !ok {
		t.Fatalf("missing static scanner: %#v", artifact.Scanners)
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

package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "skillspector",
		"--scanner", "virustotal",
		"--judge-prompt", "./prompt.md",
		"--judge-schema", "./schema.json",
		"--judge-model", "openai/gpt-5.5",
		"--judge-reasoning", "high",
		"--output", "./run.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Target != "./my-skill" {
		t.Fatalf("target = %q", opts.Target)
	}
	if got := strings.Join(opts.Scanners, ","); got != "skillspector,virustotal" {
		t.Fatalf("scanners = %q", got)
	}
	if opts.OutputPath != "./run.json" {
		t.Fatalf("output = %q", opts.OutputPath)
	}
	if opts.Judge == nil || opts.Judge.Model != "openai/gpt-5.5" || opts.Judge.Reasoning != "high" {
		t.Fatalf("judge = %#v", opts.Judge)
	}
}

func TestValidateRequirements(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "virustotal",
		"--scanner", "snyk",
		"--judge-prompt", "./prompt.md",
		"--judge-schema", "./schema.json",
		"--judge-model", "openai/gpt-5.5",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRequirements(opts, map[string]string{"SNYK_TOKEN": "present"})
	if err == nil {
		t.Fatal("expected missing env error")
	}
	want := strings.Join([]string{
		"Missing required environment variables:",
		"",
		"- VIRUSTOTAL_API_KEY required by scanner virustotal",
		"- OPENAI_API_KEY required by judge model openai/gpt-5.5",
	}, "\n")
	if err.Error() != want {
		t.Fatalf("error:\n%s", err)
	}
}

func TestRejectUnsupportedJudgeProvider(t *testing.T) {
	_, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "skillspector",
		"--judge-prompt", "./prompt.md",
		"--judge-schema", "./schema.json",
		"--judge-model", "google/gemini",
	})
	if err == nil || err.Error() != "Unsupported judge model provider: google/gemini" {
		t.Fatalf("err = %v", err)
	}
}

func TestArtifactRedactsEnvValues(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "virustotal", "--scanner", "snyk"})
	if err != nil {
		t.Fatal(err)
	}
	artifact := NewArtifact(opts, "/tmp/my-skill", "2026-06-03T00:00:00Z", "2026-06-03T00:00:01Z", map[string]string{
		"VIRUSTOTAL_API_KEY": "secret-vt",
		"SNYK_TOKEN":         "",
	})
	if artifact.Env["VIRUSTOTAL_API_KEY"] != "present" || artifact.Env["SNYK_TOKEN"] != "missing" {
		t.Fatalf("env = %#v", artifact.Env)
	}
	raw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-vt")) {
		t.Fatalf("artifact leaked secret: %s", raw)
	}
}

func TestRunWritesScannerOnlyArtifact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "run.json")
	opts, err := ParseArgs([]string{target, "--scanner", "skillspector", "--output", out})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{Env: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "clawscan-run-v1" {
		t.Fatalf("schema = %q", artifact.SchemaVersion)
	}
	if artifact.Target.ResolvedPath != target {
		t.Fatalf("resolved = %q", artifact.Target.ResolvedPath)
	}
	if artifact.Scanners["skillspector"].Status != "skipped" {
		t.Fatalf("scanner = %#v", artifact.Scanners["skillspector"])
	}
	if artifact.Judge != nil {
		t.Fatalf("judge = %#v", artifact.Judge)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var written Artifact
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatal(err)
	}
	if written.SchemaVersion != artifact.SchemaVersion {
		t.Fatalf("written schema = %q", written.SchemaVersion)
	}
}

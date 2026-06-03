package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCommandWritesArtifact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "run.json")
	err := run([]string{target, "--scanner", "skillspector", "--output", out}, []string{})
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
	if _, ok := artifact.Scanners["skillspector"]; !ok {
		t.Fatalf("missing skillspector scanner: %#v", artifact.Scanners)
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

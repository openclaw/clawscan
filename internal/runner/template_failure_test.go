package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTemplateScannerKeepsExistingFailureProtections(t *testing.T) {
	for _, test := range []struct{ name, raw, stderr string }{
		{"invalid report", "not json", ""},
		{"no runs", `{"version":"2.1.0","runs":[]}`, ""},
		{"partial report", strings.Replace(aigMCPSARIF, `"scanNote": "complete"`, `"scanNote": "partial"`, 1), ""},
		{"provider failed", aigMCPSARIF, "ERROR | LLM chat failed after retries: fixture failure"},
		{"iteration exhausted", aigMCPSARIF, "WARNING | Max iterations (80) reached"},
	} {
		t.Run(test.name, func(t *testing.T) {
			commands := &aigMCPCommandRunner{output: test.raw, stderr: test.stderr}
			artifact := runAIGMCPTest(t, templateFixture(t, "benign-mixed"), map[string]string{"LLM_API_KEY": "fixture-only"}, commands)
			if artifact.Scanners[aigMCPScannerID].Status != "failed" {
				t.Fatalf("incomplete audit accepted: %#v", artifact.Scanners)
			}
		})
	}
	root := templateFixture(t, "benign-mixed")
	commands := &aigMCPCommandRunner{output: aigMCPSARIF}
	r := ExternalScannerRunner{CommandRunner: commands, Env: map[string]string{"LLM_API_KEY": "fixture-only"}, TargetKind: targetKindTemplate}
	result, err := r.runAIGMCP(root, "now")
	if err != nil || result.Status != "failed" || len(commands.calls) != 0 {
		t.Fatalf("host execution gate bypassed: %#v %v", result, err)
	}
}

func TestTemplateSelectorAcceptsRootAndNestedAndDoesNotTrustMarkerAlone(t *testing.T) {
	for _, selector := range []string{"CLAW.md", "./CLAW.md", "manifests/CLAW.md", "./manifests/CLAW.md", "examples/v0/CLAW.md"} {
		t.Run(selector, func(t *testing.T) {
			root := t.TempDir()
			selected := filepath.Join(root, filepath.FromSlash(selector))
			if err := os.MkdirAll(filepath.Dir(selected), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(selected, []byte("Agent instructions"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "package.json"), mustTemplateJSON(t, map[string]any{"openclaw": map[string]string{"template": selector}}), 0600); err != nil {
				t.Fatal(err)
			}
			target, err := resolveTarget(root)
			if err != nil || target.kind != targetKindTemplate {
				t.Fatalf("%s: %#v %v", selector, target, err)
			}
		})
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CLAW.md"), []byte("Not a canonical package selector"), 0600); err != nil {
		t.Fatal(err)
	}
	target, err := resolveTarget(root)
	if err != nil || target.kind == targetKindTemplate {
		t.Fatalf("marker alone selected Template: %#v %v", target, err)
	}
	if _, err := resolveTargetForOptions(Options{Target: root, TargetKind: targetKindTemplate}); err == nil {
		t.Fatal("trusted override ignored missing selector")
	}
}

package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func evidenceArtifact(t *testing.T) Artifact {
	t.Helper()
	target := createAIGMCPTestPlugin(t)
	if err := os.WriteFile(filepath.Join(target, "index.js"), []byte("// ARTIFACT_ONLY_SOURCE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return Artifact{
		SchemaVersion: "clawscan-run-v1",
		Target:        Target{Kind: targetKindPlugin, Input: "plugin", ResolvedPath: target, ID: "probe-plugin"},
		Context:       json.RawMessage(`{"source":"publish"}`),
		Scanners: map[string]ScannerResult{
			"aig-mcp":      {Status: "completed", Raw: json.RawMessage(aigMCPSARIF)},
			"skillspector": {Status: "failed", Error: "SkillSpector command did not complete", Raw: json.RawMessage(`{"status":"partial"}`)},
		},
	}
}

func TestEvidenceOnlyWorkspaceHoldsNoArtifact(t *testing.T) {
	artifact := evidenceArtifact(t)
	// A real CLI target input is usually an absolute host path.
	artifact.Target.Input = artifact.Target.ResolvedPath
	for _, evidenceOnly := range []bool{false, true} {
		workspace := t.TempDir()
		if err := prepareHarnessWorkspaceContext(context.Background(), workspace, artifact, evidenceOnly); err != nil {
			t.Fatal(err)
		}
		_, statErr := os.Stat(filepath.Join(workspace, "artifact"))
		metadata, err := os.ReadFile(filepath.Join(workspace, "metadata.json"))
		if err != nil {
			t.Fatal(err)
		}
		if evidenceOnly {
			if !os.IsNotExist(statErr) || strings.Contains(string(metadata), artifact.Target.ResolvedPath) || strings.Contains(string(metadata), `"copied"`) {
				t.Fatalf("evidence-only workspace exposes the artifact (stat=%v):\n%s", statErr, metadata)
			}
			var parsed struct {
				Target map[string]any `json:"target"`
			}
			if err := json.Unmarshal(metadata, &parsed); err != nil {
				t.Fatal(err)
			}
			if want := map[string]any{"kind": "plugin", "id": "probe-plugin"}; !jsonEqual(parsed.Target, want) {
				t.Fatalf("evidence-only target = %v, want only %v", parsed.Target, want)
			}
		} else if statErr != nil {
			t.Fatalf("general judge workspace lost its artifact copy: %v", statErr)
		}
		raw, err := os.ReadFile(filepath.Join(workspace, "scanners", "aig-mcp.json"))
		if err != nil || string(raw) != aigMCPSARIF {
			t.Fatalf("scanner report changed in the workspace (evidenceOnly=%v): %v", evidenceOnly, err)
		}
	}
}

func TestEvidenceOnlyPromptRendersScannerResultsAndRefusesArtifactText(t *testing.T) {
	artifact := evidenceArtifact(t)
	prompt, err := renderPromptTemplateContext(context.Background(), "{{ run_context }}\n---\n{{ scanner_results }}", artifact, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "ARTIFACT_ONLY_SOURCE") || strings.Contains(prompt, artifact.Target.ResolvedPath) {
		t.Fatalf("prompt exposes artifact text or host path:\n%s", prompt)
	}
	parts := strings.SplitN(prompt, "\n---\n", 2)
	var results map[string]struct {
		Status string          `json:"status"`
		Error  string          `json:"error"`
		Raw    json.RawMessage `json:"raw"`
	}
	if err := json.Unmarshal([]byte(parts[1]), &results); err != nil {
		t.Fatal(err)
	}
	if results["skillspector"].Status != "failed" || results["skillspector"].Error == "" {
		t.Fatalf("failed coverage is not explicit: %#v", results["skillspector"])
	}
	var want, got any
	_ = json.Unmarshal([]byte(aigMCPSARIF), &want)
	_ = json.Unmarshal(results["aig-mcp"].Raw, &got)
	if !jsonEqual(want, got) {
		t.Fatalf("aig-mcp report changed: %s", results["aig-mcp"].Raw)
	}
	if !strings.Contains(parts[0], `"kind": "plugin"`) || !strings.Contains(parts[0], `"source": "publish"`) {
		t.Fatalf("run context = %s", parts[0])
	}

	if _, err := renderPromptTemplateContext(context.Background(), "{{ target.files }}", artifact, true); err == nil || !strings.Contains(err.Error(), "unavailable to an evidence-only command") || !strings.Contains(err.Error(), "use {{ scanner_results }}, or set evidenceOnly: false") {
		t.Fatalf("target.files err = %v", err)
	}
	if _, err := renderJudgePromptSourceContext(context.Background(), clawHubPromptSourceKey, "SYSTEM", artifact, true); err == nil || !strings.Contains(err.Error(), "cannot be used by an evidence-only command") || !strings.Contains(err.Error(), "or set evidenceOnly: false") {
		t.Fatalf("parity prompt err = %v", err)
	}
	if rendered, err := renderPromptTemplateContext(context.Background(), "{{ target.files }}", artifact, false); err != nil || !strings.Contains(rendered, "ARTIFACT_ONLY_SOURCE") {
		t.Fatalf("general judge lost {{ target.files }}: %v", err)
	}
}

func jsonEqual(left any, right any) bool {
	a, errA := json.Marshal(left)
	b, errB := json.Marshal(right)
	return errA == nil && errB == nil && string(a) == string(b)
}

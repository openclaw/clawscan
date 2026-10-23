package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSkillSpectorReportCompletion(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{"complete", `{"execution_successful":true,"analysis_completeness":{"is_complete":true},"issues":[]}`, "completed"},
		{"legacy", `{"status":"suspicious","issues":[{"id":"SSD-1"}]}`, "completed"},
		{"malicious", `{"status":"malicious","issues":[{"id":"SSD-1"}]}`, "completed"},
		{"legacy absent metadata", `{"risk_assessment":{"score":0,"recommendation":"SAFE"},"issues":[]}`, "completed"},
		{"legacy error", `{"error":"synthetic-sensitive-error-not-for-diagnostics"}`, "failed"},
		{"camel case partial", `{"executionSuccessful":true,"analysisCompleteness":{"isComplete":false}}`, "failed"},
		{"partial", `{"execution_successful":true,"analysis_completeness":{"is_complete":false},"issues":[{"id":"SSD-1","severity":"HIGH"}]}`, "failed"},
		{"execution failed", `{"execution_successful":false,"analysis_completeness":{"is_complete":false},"issues":[]}`, "failed"},
		{"nested failure", `{"analysis_completeness":{"execution_successful":false}}`, "failed"},
		{"invalid completeness", `{"analysis_completeness":null}`, "failed"},
		{"invalid flag", `{"execution_successful":"true"}`, "failed"},
		{"nested partial status", `{"analysis_completeness":{"status":"partial"}}`, "failed"},
		{"non-object", `[]`, "failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, exitCode := range []int{0, 1, 2} {
				want := test.want
				if exitCode > 1 {
					want = "failed"
				}
				commandRunner := &recordingCommandRunner{writeOutput: test.raw, exitCode: intPointer(exitCode)}
				if exitCode != 0 {
					commandRunner.err = errCommandFailed
				}
				result, err := (ExternalScannerRunner{
					CommandRunner: commandRunner, Env: map[string]string{},
					SkillSpectorCommand: []string{"skillspector"},
				}).runSkillSpector(t.TempDir(), "2026-10-23T00:00:00Z")
				if err != nil {
					t.Fatal(err)
				}
				if result.Status != want || !bytes.Equal(result.Raw, []byte(test.raw)) {
					t.Fatalf("exit=%d result=%#v", exitCode, result)
				}
				if result.ExitCode == nil || *result.ExitCode != exitCode {
					t.Fatalf("exit code changed: %#v", result.ExitCode)
				}
				if want == "failed" && result.Error == "" {
					t.Fatal("failed report lost its operational error")
				}
			}
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, []byte(test.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := scannerResult(Options{ScannerResultPaths: map[string]string{"skillspector": path}}, "skillspector", resolvedTarget{}, "now", nil)
			if err != nil || result.Status != test.want || !bytes.Equal(result.Raw, []byte(test.raw)) {
				t.Fatalf("precomputed result=%#v err=%v", result, err)
			}
		})
	}
}

func TestClawHubSkillSpectorIncompleteEvidenceIsNotClean(t *testing.T) {
	raw := json.RawMessage(`{"execution_successful":true,"analysis_completeness":{"is_complete":false},"risk_assessment":{"score":0,"recommendation":"CAUTION"},"issues":[{"id":"SSD-1","severity":"HIGH"}]}`)
	normalized, err := normalizeClawHubSkillSpector(raw, 123)
	if err != nil || normalized.Status != "error" || normalized.Error == "" || len(normalized.Issues) != 1 {
		t.Fatalf("normalized=%#v err=%v", normalized, err)
	}
	if normalized.Issues[0].IssueID != "SSD-1" || normalized.Issues[0].Severity != "HIGH" {
		t.Fatalf("findings changed: %#v", normalized.Issues)
	}
}

func TestClawHubSkillSpectorCommandFailureIsNotClean(t *testing.T) {
	analysis, err := clawHubSkillSpectorAnalysis(Artifact{Scanners: map[string]ScannerResult{
		"skillspector": {Status: "failed", Raw: json.RawMessage(`{"status":"clean","issues":[]}`)},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	normalized := analysis.(clawHubNormalizedSkillSpectorAnalysis)
	if normalized.Status != "error" || normalized.Error == "" {
		t.Fatalf("normalized=%#v", normalized)
	}
}

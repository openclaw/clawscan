package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func upstreamReferenceCaveatFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/skillspector-reference-caveat.json")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	accounting := report["analysis_completeness"].(map[string]any)
	accounting["status"], accounting["is_complete"] = "complete_with_caveats", true
	// Upstream meta review annotates a deterministic finding; disagreement does
	// not authorize an adapter to delete the finding or lower its confidence.
	report["issues"] = []any{map[string]any{
		"id": "RA2", "finding": "start a background process", "severity": "MEDIUM", "confidence": 0.7,
		"tags":     []any{"llm-unconfirmed"},
		"evidence": map[string]any{"llm_review_outcome": "disagreed", "llm_review_confidence": 0.99},
	}}
	return report
}

func TestSkillSpectorUpstreamCompleteWithCaveatsPreservesRawEvidence(t *testing.T) {
	for _, exitCode := range []int{0, 1} {
		report := upstreamReferenceCaveatFixture(t)
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		result := validateSkillSpectorReportForProfile(ScannerResult{
			Status: "completed", ExitCode: intPointer(exitCode), Raw: raw,
		}, "clawhub")
		if result.Status != "completed" || result.ReportPolicy != "" || !bytes.Equal(result.Raw, raw) {
			t.Fatalf("complete_with_caveats must retain its raw evidence: %#v", result)
		}
		normalized, err := normalizeClawHubSkillSpector(raw, 123)
		if err != nil || normalized.InspectionCaveats == nil || normalized.InspectionCaveats.Status != "complete_with_caveats" {
			t.Fatalf("upstream completeness status lost: %#v err=%v", normalized, err)
		}
		prompt, err := RenderClawHubPrompt("Independently review retained scanner evidence.", Artifact{
			Scanners: map[string]ScannerResult{"skillspector": result},
		})
		for _, evidence := range []string{"complete_with_caveats", "reference_missing", "runtime-note.md", "RA2", "llm-unconfirmed", "disagreed"} {
			if err != nil || !strings.Contains(prompt, evidence) {
				t.Fatalf("judge prompt lost %s: err=%v", evidence, err)
			}
		}
	}
}

func TestSkillSpectorCaveatSummaryBoundsDoNotChangeRawFindings(t *testing.T) {
	report := upstreamReferenceCaveatFixture(t)
	accounting := report["analysis_completeness"].(map[string]any)
	references := accounting["references"].([]any)
	exceptions := accounting["ledger_exceptions"].([]any)
	for range 30 {
		references = append(references, map[string]any{"evidence": strings.Repeat("x", 3000)})
		exceptions = append(exceptions, map[string]any{"message": strings.Repeat("x", 3000)})
	}
	accounting["references"], accounting["ledger_exceptions"] = references, exceptions
	issue := report["issues"].([]any)[0].(map[string]any)
	issue["tags"] = []any{"llm-unconfirmed", 123, "", "a", "b", "c", "d", "e", "f", strings.Repeat("x", 3000), "overflow"}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeClawHubSkillSpector(raw, 123)
	if err != nil {
		t.Fatal(err)
	}
	caveats := normalized.InspectionCaveats
	if caveats.ReferenceCount != len(references) || caveats.ExceptionCount != len(exceptions) || len(caveats.References) != 10 || len(caveats.LedgerExceptions) != 10 {
		t.Fatalf("caveat truncation lost counts: %#v", caveats)
	}
	if len(caveats.References[1]["evidence"].(string)) > 550 || len(normalized.Issues[0].Tags) != 8 {
		t.Fatalf("caveat evidence exceeded bounds: %#v", normalized)
	}
	if normalized.Status != "suspicious" || normalized.Issues[0].IssueID != "RA2" || *normalized.Issues[0].Confidence != 0.7 || normalized.Issues[0].ReviewOutcome != "disagreed" || *normalized.Issues[0].ReviewConfidence != 0.99 {
		t.Fatalf("meta disagreement altered deterministic finding: %#v", normalized)
	}
}

func TestSkillSpectorUpstreamCaveatAdoptionKeepsOrdinaryJudgeGapsPath(t *testing.T) {
	report := upstreamReferenceCaveatFixture(t)
	accounting := report["analysis_completeness"].(map[string]any)
	accounting["status"], accounting["is_complete"] = "partial", false
	accounting["limitations"] = []any{"A separate analyzer could not inspect the module."}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	result := validateSkillSpectorReportForProfile(ScannerResult{
		Status: "completed", ExitCode: intPointer(0), Raw: raw,
	}, "clawhub")
	if result.Status != "partial" || result.ReportPolicy != "judge-gaps" || !bytes.Equal(result.Raw, raw) {
		t.Fatalf("ordinary partial evidence must retain independent gap review: %#v", result)
	}
}

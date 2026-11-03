package runner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func readerRegressionBundle(t *testing.T, mutate func(map[string]any, map[string]any)) json.RawMessage {
	t.Helper()
	_, report := completeBundleFixture(t)
	child := report["bundled_reports"].([]any)[0].(map[string]any)["report"].(map[string]any)
	report["status"], report["issue_count"], report["filtered_findings"] = "clean", float64(0), []any{}
	report["risk_assessment"] = map[string]any{"score": float64(0), "severity": "NONE", "recommendation": "SAFE"}
	mutate(report, child)
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	result := validateSkillSpectorReportForProfile(ScannerResult{Status: "completed", Raw: raw}, "clawhub")
	if result.Status != "completed" || !bytes.Equal(result.Raw, raw) {
		t.Fatalf("regression fixture must retain valid complete child evidence: %+v", result)
	}
	return raw
}

func assertReaderRegressionGate(t *testing.T, raw json.RawMessage, path string, expected any) {
	t.Helper()
	equals, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(raw)
	artifact := &Artifact{}
	evaluateClawHubCompleteBundleGateRules(artifact, "skillspector", raw, []JSONGateRule{{ID: "native-child-evidence", Paths: []string{path}, Equals: equals, Action: "block"}})
	if len(artifact.GateRules) != 1 || artifact.GateRules[0].Action != "block" {
		t.Errorf("native child gate %q = %s did not block: %+v", path, equals, artifact.GateRules)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("derived gate evaluation changed original raw bytes")
	}
}

func TestClawHubCompleteBundleReaderPreservesUnsafeRecommendations(t *testing.T) {
	for _, recommendation := range []string{"UNSAFE", "DO_NOT_INSTALL"} {
		t.Run(recommendation, func(t *testing.T) {
			raw := readerRegressionBundle(t, func(_ map[string]any, child map[string]any) {
				delete(child, "status")
				child["risk_assessment"] = map[string]any{"score": float64(95), "severity": "CRITICAL", "recommendation": recommendation}
			})
			analysis, err := normalizeClawHubSkillSpector(raw, 123)
			if err != nil || analysis.Status != "malicious" || analysis.Recommendation != recommendation || analysis.Score == nil || *analysis.Score != 95 || analysis.Severity != "CRITICAL" {
				t.Errorf("unsafe native child was weakened: %+v err=%v", analysis, err)
			}
			assertReaderRegressionGate(t, raw, "risk_assessment.recommendation", recommendation)
		})
	}
}

func TestClawHubCompleteBundleReaderPreservesRelativePaths(t *testing.T) {
	root := "skills/council-network"
	for _, test := range []struct{ name, source, expected string }{
		{"relative-repeated-root", "assets/" + root + "/payload.sh", root + "/assets/" + root + "/payload.sh"},
		{"dot-relative-repeated-root", "./assets/" + root + "/payload.sh", root + "/assets/" + root + "/payload.sh"},
		{"relative", "payload.sh", root + "/payload.sh"},
		{"already-rooted", root + "/payload.sh", root + "/payload.sh"},
		{"absolute-stage", "/tmp/stage/" + root + "/payload.sh", root + "/payload.sh"},
		{"absolute-repeated-root", "/tmp/stage/" + root + "/assets/" + root + "/payload.sh", root + "/assets/" + root + "/payload.sh"},
		{"windows-stage", `C:\stage\skills\council-network\payload.sh`, root + "/payload.sh"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := readerRegressionBundle(t, func(_ map[string]any, child map[string]any) {
				child["issues"].([]any)[0].(map[string]any)["file"] = test.source
			})
			analysis, err := normalizeClawHubSkillSpector(raw, 123)
			if err != nil || len(analysis.Issues) != 1 || analysis.Issues[0].File != test.expected {
				t.Errorf("child finding points at the wrong original: %+v err=%v", analysis.Issues, err)
			}
			assertReaderRegressionGate(t, raw, "filtered_findings[].file", test.expected)
		})
	}
}

func TestClawHubCompleteBundleReaderGateKeepsNativeFindingFields(t *testing.T) {
	longText := strings.Repeat("x", maxClawHubSkillSpectorTextChars+100) + "-native-tail"
	longTag := strings.Repeat("tag", 100)
	tags := make([]any, maxClawHubSkillSpectorTags+1)
	for index := range tags {
		tags[index] = "ordinary"
	}
	tags[len(tags)-1] = longTag
	raw := readerRegressionBundle(t, func(_ map[string]any, child map[string]any) {
		issue := child["issues"].([]any)[0].(map[string]any)
		issue["id"], issue["severity"], issue["description"], issue["tags"] = "NATIVE-ID", "HIGH", longText, tags
		issue["evidence"] = map[string]any{"vendor_detail": "keep-native-evidence"}
		issue["vendor_counter"] = json.Number("9007199254740993")
	})
	for _, findingPath := range []string{"issues[]", "findings[]", "filtered_findings[]"} {
		for _, test := range []struct {
			field string
			value any
		}{
			{"id", "NATIVE-ID"},
			{"severity", "HIGH"},
			{"description", longText},
			{"tags[]", longTag},
			{"evidence.vendor_detail", "keep-native-evidence"},
			{"vendor_counter", json.Number("9007199254740993")},
		} {
			t.Run(findingPath+"."+test.field, func(t *testing.T) {
				assertReaderRegressionGate(t, raw, findingPath+"."+test.field, test.value)
			})
		}
	}
}

func TestClawHubCompleteBundleReaderGateRootsFullNativeLocations(t *testing.T) {
	relative := "assets/skills/council-network/" + strings.Repeat("p", maxClawHubSkillSpectorShortTextChars+1) + ".sh"
	expected := "skills/council-network/" + relative
	raw := readerRegressionBundle(t, func(_ map[string]any, child map[string]any) {
		issue := child["issues"].([]any)[0].(map[string]any)
		for _, field := range []string{"file", "file_path", "filePath", "path"} {
			issue[field] = relative
		}
		issue["location"] = map[string]any{"file": relative, "path": relative, "line": float64(17)}
	})
	for _, field := range []string{"file", "file_path", "filePath", "path", "location.file", "location.path"} {
		t.Run(field, func(t *testing.T) {
			assertReaderRegressionGate(t, raw, "issues[]."+field, expected)
		})
	}
	assertReaderRegressionGate(t, raw, "issues[].location.line", 17)
}

func TestClawHubCompleteBundleReaderGateRetainsFindingAfterPresentationCap(t *testing.T) {
	raw := readerRegressionBundle(t, func(_ map[string]any, child map[string]any) {
		findings := []any{}
		for index := range maxClawHubSkillSpectorIssues {
			findings = append(findings, map[string]any{"id": index, "severity": "HIGH", "file": "SKILL.md"})
		}
		findings = append(findings, map[string]any{"id": "NATIVE-AFTER-CAP", "severity": "LOW", "file": "SKILL.md"})
		child["issues"] = findings
		accounting := child["analysis_completeness"].(map[string]any)
		accounting["findings_before_filtering"], accounting["findings_after_filtering"] = len(findings), len(findings)
	})
	for _, path := range []string{"issues[].id", "findings[].id", "filtered_findings[].id"} {
		assertReaderRegressionGate(t, raw, path, "NATIVE-AFTER-CAP")
	}
}

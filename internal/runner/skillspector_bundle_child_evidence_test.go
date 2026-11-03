package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestClawHubCompleteBundleReaderNativeRecommendationsAreOrderIndependent(t *testing.T) {
	for _, order := range [][]string{{"UNSAFE", "DO_NOT_INSTALL"}, {"DO_NOT_INSTALL", "UNSAFE"}} {
		t.Run(strings.Join(order, "-"), func(t *testing.T) {
			raw := readerRegressionBundle(t, func(report map[string]any, first map[string]any) {
				_, other := completeBundleFixture(t)
				second := other["bundled_reports"].([]any)[0].(map[string]any)
				second["rootPath"] = "skills/other"
				first["risk_assessment"].(map[string]any)["recommendation"] = order[0]
				second["report"].(map[string]any)["risk_assessment"].(map[string]any)["recommendation"] = order[1]
				report["bundled_reports"] = append(report["bundled_reports"].([]any), second)
			})
			for _, recommendation := range []string{"UNSAFE", "DO_NOT_INSTALL"} {
				assertReaderRegressionGate(t, raw, "risk_assessment.recommendation", recommendation)
			}
			analysis, err := normalizeClawHubSkillSpector(raw, 123)
			if err != nil || analysis.Status != "malicious" || clawHubSkillSpectorRecommendationRank(analysis.Recommendation) != 3 {
				t.Fatalf("strongest risk lost: %+v err=%v", analysis, err)
			}
		})
	}
}

func TestClawHubCompleteBundleReaderInventoriedLeadingRootPath(t *testing.T) {
	root := "skills/council-network"
	for _, test := range []struct{ name, source, component, expected string }{
		{"leading-root-is-child-relative", root + "/payload.sh", root + "/payload.sh", root + "/" + root + "/payload.sh"},
		{"dot-leading-root-is-child-relative", "./" + root + "/payload.sh", root + "/payload.sh", root + "/" + root + "/payload.sh"},
		{"already-rooted-is-compatible", root + "/payload.sh", "payload.sh", root + "/payload.sh"},
		{"already-rooted-skill-is-compatible", root + "/SKILL.md", "fixture-001.md", root + "/SKILL.md"},
		{"absolute-staging-is-compatible", "/tmp/stage/" + root + "/payload.sh", "payload.sh", root + "/payload.sh"},
		{"long-leading-root-before-display-cap", root + "/" + strings.Repeat("p", maxClawHubSkillSpectorShortTextChars+1) + ".sh", root + "/" + strings.Repeat("p", maxClawHubSkillSpectorShortTextChars+1) + ".sh", root + "/" + root + "/" + strings.Repeat("p", maxClawHubSkillSpectorShortTextChars+1) + ".sh"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := readerRegressionBundle(t, func(_ map[string]any, child map[string]any) {
				child["components"].([]any)[1].(map[string]any)["path"] = test.component
				child["issues"].([]any)[0].(map[string]any)["file"] = test.source
			})
			analysis, err := normalizeClawHubSkillSpector(raw, 123)
			if err != nil || len(analysis.Issues) != 1 || analysis.Issues[0].File != truncateClawHubText(test.expected, maxClawHubSkillSpectorShortTextChars) {
				t.Errorf("attested component did not disambiguate the original path: %+v err=%v", analysis, err)
			}
			for _, field := range []string{"issues[].file", "findings[].file", "filtered_findings[].file"} {
				assertReaderRegressionGate(t, raw, field, test.expected)
			}
		})
	}
}

func TestClawHubCompleteBundleReaderNativeGateMatchesRemainDeduplicated(t *testing.T) {
	raw := readerRegressionBundle(t, func(report map[string]any, child map[string]any) {
		report["risk_assessment"].(map[string]any)["recommendation"] = "DO_NOT_INSTALL"
		child["risk_assessment"].(map[string]any)["recommendation"] = "DO_NOT_INSTALL"
		child["issues"].([]any)[0].(map[string]any)["severity"] = "HIGH"
	})
	rules := []JSONGateRule{
		{ID: "native-disposition", Paths: []string{"risk_assessment.recommendation"}, Equals: json.RawMessage(`"DO_NOT_INSTALL"`), Action: "block"},
		{ID: "native-high", Paths: []string{"issues[].severity"}, Equals: json.RawMessage(`"HIGH"`), Action: "block"},
	}
	artifact := &Artifact{}
	evaluateClawHubCompleteBundleGateRules(artifact, "skillspector", raw, rules)
	if len(artifact.GateRules) != 2 || artifact.GateRules[0].Rule != "native-disposition" || artifact.GateRules[1].Rule != "native-high" {
		t.Fatalf("raw/aggregate/child gate results lost or duplicated: %+v", artifact.GateRules)
	}
}

func TestClawHubCompleteBundleReaderKeepsOriginalChildGateFields(t *testing.T) {
	raw := readerRegressionBundle(t, func(_ map[string]any, child map[string]any) {
		child["filtered_findings"] = []any{map[string]any{"id": "CHILD-NATIVE-ALIAS", "severity": "HIGH"}}
	})
	assertReaderRegressionGate(t, raw, "filtered_findings[].id", "CHILD-NATIVE-ALIAS")
	assertReaderRegressionGate(t, raw, "filtered_findings[].severity", "HIGH")
}

func TestClawHubCompleteBundleReaderNativeDispositionBlocksRun(t *testing.T) {
	for _, order := range [][]string{{"UNSAFE", "DO_NOT_INSTALL"}, {"DO_NOT_INSTALL", "UNSAFE"}} {
		t.Run(strings.Join(order, "-"), func(t *testing.T) {
			raw := readerRegressionBundle(t, func(report map[string]any, child map[string]any) {
				_, other := completeBundleFixture(t)
				entry := other["bundled_reports"].([]any)[0].(map[string]any)
				entry["rootPath"] = "skills/other"
				child["risk_assessment"].(map[string]any)["recommendation"] = order[0]
				entry["report"].(map[string]any)["risk_assessment"].(map[string]any)["recommendation"] = order[1]
				report["bundled_reports"] = append(report["bundled_reports"].([]any), entry)
			})
			target := t.TempDir()
			for _, name := range []string{"openclaw.plugin.json", "skills/council-network/SKILL.md", "skills/council-network/fixture-001.md", "skills/other/SKILL.md", "skills/other/fixture-001.md"} {
				path := filepath.Join(target, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				content := []byte("# Generated inert fixture\n")
				if name == "openclaw.plugin.json" {
					content = []byte(`{"id":"generated-bundle"}`)
				}
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			command := judgeRetryCommand(func(workspace string, _ time.Duration) (CommandOutput, error) {
				return judgeRetryOutput(t, map[string]any{"verdict": "benign", "artifact_inspection": partialJudgeReceipt(t, workspace)}), nil
			})
			artifact, err := Run(Options{Profile: "clawhub", Target: target, Scanners: []string{"skillspector"}, ScannerResultPaths: map[string]string{"skillspector": path}, Judge: &JudgeOptions{Command: "judge"}, GateRules: map[string]ScannerGatePolicy{"skillspector": {JSONRules: []JSONGateRule{{ID: "native-do-not-install", Paths: []string{"risk_assessment.recommendation"}, Equals: json.RawMessage(`"DO_NOT_INSTALL"`), Action: "block"}}}}}, RunContext{Env: map[string]string{}, CommandRunner: command})
			if err != nil || !artifact.Complete || artifact.Gate != "block" || len(artifact.GateRules) != 1 || !bytes.Equal(artifact.Scanners["skillspector"].Raw, raw) {
				t.Fatalf("native child disposition bypassed the real Run gate: gate=%s rules=%+v err=%v", artifact.Gate, artifact.GateRules, err)
			}
		})
	}
}

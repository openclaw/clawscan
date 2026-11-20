package runner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestClawHubInspectionCaveatsPreserveEveryPathIdentity(t *testing.T) {
	for _, bundled := range []bool{false, true} {
		for _, paths := range []struct{ name, source, target string }{
			{"leading", " SKILL.md", " fixture-001.md"},
			{"trailing", "SKILL.md ", "fixture-001.md "},
			{"both", " SKILL.md ", " fixture-001.md "},
			{"tabs", "\tSKILL.md\t", "\tfixture-001.md\t"},
			{"spaces-only", " ", "  "},
		} {
			name := "single/" + paths.name
			if bundled {
				name = "bundle/" + paths.name
			}
			t.Run(name, func(t *testing.T) {
				report := upstreamReferenceCaveatFixture(t)
				child := report
				prefix := ""
				if bundled {
					_, report = completeBundleFixture(t)
					entry := report["bundled_reports"].([]any)[0].(map[string]any)
					child = entry["report"].(map[string]any)
					prefix = entry["rootPath"].(string) + "/"
				}
				child["components"].([]any)[0].(map[string]any)["path"] = paths.source
				child["components"].([]any)[1].(map[string]any)["path"] = paths.target
				accounting := child["analysis_completeness"].(map[string]any)
				references := accounting["references"].([]any)
				reference := references[0].(map[string]any)
				reference["source_path"], reference["evidence"] = paths.source, " Keep evidence "
				accounting["references"] = append(references, map[string]any{
					"source_path": paths.source, "target_path": paths.target,
					"line": float64(1), "column": float64(1), "evidence": " linked target ",
					"status": "resolved", "disposition": "analyzed", "reference_kind": "markdown_link",
				})
				exception := accounting["ledger_exceptions"].([]any)[0].(map[string]any)
				exception["path"], exception["message"] = paths.source, " Keep message "
				raw, err := json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				before := bytes.Clone(raw)
				result := validateSkillSpectorReportForProfile(ScannerResult{Status: "completed", Raw: raw}, "clawhub")
				if result.Status != "completed" || !bytes.Equal(result.Raw, raw) {
					t.Fatalf("whitespace paths must be admitted with exact original evidence: %+v", result)
				}
				analysis, err := normalizeClawHubSkillSpector(raw, 123)
				if err != nil || analysis.InspectionCaveats == nil {
					t.Fatalf("caveats lost: %+v err=%v", analysis, err)
				}
				caveats := analysis.InspectionCaveats
				if caveats.ReferenceCount != 2 || caveats.ExceptionCount != 1 || len(caveats.References) != 2 || len(caveats.LedgerExceptions) != 1 {
					t.Fatalf("caveat counts changed: %+v", caveats)
				}
				for index, reference := range caveats.References {
					if reference["sourcePath"] != prefix+paths.source {
						t.Errorf("reference %d source path identity changed: got %q want %q", index, reference["sourcePath"], prefix+paths.source)
					}
				}
				if caveats.References[1]["targetPath"] != prefix+paths.target {
					t.Errorf("resolved target path identity changed: got %q want %q", caveats.References[1]["targetPath"], prefix+paths.target)
				}
				if _, present := caveats.References[0]["targetPath"]; present {
					t.Error("missing reference's null target became a path")
				}
				if caveats.LedgerExceptions[0]["path"] != prefix+paths.source {
					t.Errorf("exception path identity changed: got %q want %q", caveats.LedgerExceptions[0]["path"], prefix+paths.source)
				}
				if caveats.References[0]["evidence"] != "Keep evidence" || caveats.References[1]["evidence"] != "linked target" || caveats.LedgerExceptions[0]["message"] != "Keep message" {
					t.Errorf("ordinary display text normalization changed: %+v", caveats)
				}
				prompt, err := RenderClawHubPrompt("Inspect the exact retained files.", Artifact{Scanners: map[string]ScannerResult{"skillspector": result}})
				for _, expected := range []string{prefix + paths.source, prefix + paths.target} {
					quoted, _ := json.Marshal(expected)
					if err != nil || !strings.Contains(prompt, string(quoted)) {
						t.Errorf("judge prompt lost exact caveat path %q: %v", expected, err)
					}
				}
				if !bytes.Equal(raw, before) || analysis.Issues[0].IssueID != "RA2" || analysis.Issues[0].ReviewOutcome != "disagreed" {
					t.Error("path summary changed original findings or raw bytes")
				}
			})
		}
	}
}

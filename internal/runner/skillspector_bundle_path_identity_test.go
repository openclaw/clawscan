package runner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClawHubCompleteBundleReaderRootsEverySupportedNativeAlias(t *testing.T) {
	for _, alias := range []string{"filtered_findings", "filteredFindings", "findings", "issues", "vulnerabilities"} {
		t.Run(alias, func(t *testing.T) {
			raw := readerRegressionBundle(t, func(_ map[string]any, child map[string]any) {
				child[alias] = []any{map[string]any{
					"id": "EVERY-NATIVE-ALIAS", "severity": "HIGH",
					"file": "fixture-001.md", "file_path": "fixture-001.md",
					"filePath": "fixture-001.md", "path": "fixture-001.md",
					"location": map[string]any{"file": "fixture-001.md", "path": "fixture-001.md"},
				}}
			})
			for _, field := range []string{"file", "file_path", "filePath", "path", "location.file", "location.path"} {
				t.Run(field, func(t *testing.T) {
					assertReaderRegressionGate(t, raw, alias+"[]."+field, "fixture-001.md")
					assertReaderRegressionGate(t, raw, alias+"[]."+field, "skills/council-network/fixture-001.md")
				})
			}
			assertReaderRegressionGate(t, raw, alias+"[].id", "EVERY-NATIVE-ALIAS")
			canonical := "skills/council-network/SKILL.md"
			if alias == "issues" {
				canonical = "skills/council-network/fixture-001.md"
			}
			for _, compatibility := range []string{"filtered_findings", "findings", "issues"} {
				assertReaderRegressionGate(t, raw, compatibility+"[].file", canonical)
			}
		})
	}
}

func TestClawHubCompleteBundleReaderPreservesInventoriedPathWhitespace(t *testing.T) {
	root := "skills/council-network"
	for _, file := range []string{" fixture-001.md", "fixture-001.md ", "\tfixture-001.md \t", " skills/council-network/payload.sh "} {
		for _, field := range []string{"file", "file_path", "filePath", "path", "location.file", "location.path"} {
			t.Run(file+"/"+field, func(t *testing.T) {
				raw := readerRegressionBundle(t, func(_ map[string]any, child map[string]any) {
					child["components"].([]any)[1].(map[string]any)["path"] = file
					issue := map[string]any{"id": "INVENTORIED-WHITESPACE", "severity": "HIGH"}
					if nested, ok := strings.CutPrefix(field, "location."); ok {
						issue["location"] = map[string]any{nested: file}
					} else {
						issue[field] = file
					}
					child["issues"] = []any{issue}
				})
				analysis, err := normalizeClawHubSkillSpector(raw, 123)
				if err != nil || len(analysis.Issues) != 1 || analysis.Issues[0].File != root+"/"+file {
					t.Errorf("inventoried filename changed before judge: %+v err=%v", analysis.Issues, err)
				}
				assertReaderRegressionGate(t, raw, "issues[]."+field, file)
				assertReaderRegressionGate(t, raw, "issues[]."+field, root+"/"+file)
			})
		}
	}
}

func TestClawHubBundleFindingPathDisambiguatesExactWhitespaceIdentity(t *testing.T) {
	root := "skills/council-network"
	for _, file := range []string{"skills/council-network/payload.sh ", " skills/council-network/payload.sh", " "} {
		components := map[string]bool{file: true, strings.TrimSpace(file): true}
		if got := clawHubBundleFindingPath(root, file, components); got != root+"/"+file {
			t.Errorf("exact inventoried path %q confused with trimmed path: %q", file, got)
		}
	}
}

func TestClawHubLegacyFindingFilePreservesWhitespace(t *testing.T) {
	for _, file := range []string{" fixture-001.md", "fixture-001.md ", " "} {
		for _, field := range []string{"file", "file_path", "filePath", "path", "location.file", "location.path"} {
			issue := map[string]any{"id": "PATH-WHITESPACE"}
			if nested, ok := strings.CutPrefix(field, "location."); ok {
				issue["location"] = map[string]any{nested: file}
			} else {
				issue[field] = file
			}
			raw, err := json.Marshal(issue)
			if err != nil {
				t.Fatal(err)
			}
			got := normalizeClawHubSkillSpectorIssue(issue, 0)
			if got.File != file {
				t.Errorf("finding %s path changed: got %q want %q; raw=%s", field, got.File, file, raw)
			}
		}
	}
}

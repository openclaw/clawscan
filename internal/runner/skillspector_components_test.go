package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func caveatScopeFixture(t *testing.T, archive, binary bool) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/skillspector-reference-caveat.json")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	components := report["components"].([]any)
	inventory, coverage, static, semantic := 2, 2, 2, 2
	if archive {
		components = append(components,
			map[string]any{"path": "samples/data.zip", "type": "zip", "lines": float64(0), "executable": false, "size_bytes": float64(200), "source_url": nil, "source_identity": nil, "source_digest": nil},
			map[string]any{"path": "samples/data.zip!/member.md", "type": "markdown", "lines": float64(3), "executable": false, "size_bytes": float64(40), "source_url": nil, "source_identity": nil, "source_digest": nil, "outer_path": "samples/data.zip", "nested_path": "member.md", "container_type": "zip", "container_depth": float64(1), "container_ancestry": []any{"zip"}},
		)
		inventory += 2
		coverage++
		static += 2
	}
	accounting := report["analysis_completeness"].(map[string]any)
	if binary {
		components = append(components, map[string]any{"path": "samples/image.png", "type": "other", "lines": float64(0), "executable": false, "size_bytes": float64(100), "source_url": nil, "source_identity": nil, "source_digest": nil})
		inventory++
		analyzers := []any{}
		for _, value := range accounting["analyzer_statuses"].([]any) {
			id := value.(map[string]any)["analyzer_id"].(string)
			if len(id) > 16 && id[:16] == "static_patterns_" {
				analyzers = append(analyzers, id)
			}
		}
		accounting["scope_exclusions"] = []any{map[string]any{"outcome": "out_of_scope", "phase": "static", "reason_code": "binary_content", "message": "Binary content is unsupported by this analyzer.", "path": "samples/image.png", "start_line": nil, "end_line": nil, "fatal": false, "analyzers": analyzers}}
	}
	report["components"] = components
	for _, field := range []string{"total_components", "scanned_components", "fully_inspected_files"} {
		accounting[field] = float64(coverage)
	}
	for _, value := range accounting["analyzer_statuses"].([]any) {
		row := value.(map[string]any)
		id := row["analyzer_id"].(string)
		expected := -1
		if id == "artifact_integrity" || id == "static_yara" {
			expected = inventory
		}
		if len(id) > 16 && id[:16] == "static_patterns_" {
			expected = static
		}
		if len(id) > 9 && id[:9] == "semantic_" {
			expected = semantic
		}
		if expected >= 0 {
			row["planned_work"], row["completed"] = float64(expected), float64(expected)
		}
	}
	return report
}

func checkCaveatScope(t *testing.T, report map[string]any, completed bool) {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	result := validateSkillSpectorReport(ScannerResult{Status: "completed", Raw: raw, ExitCode: intPointer(0)})
	expected := "failed"
	if completed {
		expected = "completed"
	}
	if result.Status != expected || !bytes.Equal(result.Raw, raw) {
		t.Fatalf("status=%s want=%s error=%s; raw preserved=%v", result.Status, expected, result.Error, bytes.Equal(result.Raw, raw))
	}
}

func TestSkillSpectorDistinctComponentScopes(t *testing.T) {
	for _, test := range []struct {
		name            string
		archive, binary bool
	}{
		{"archive", true, false}, {"passive image", false, true}, {"archive and image", true, true},
	} {
		t.Run(test.name, func(t *testing.T) { checkCaveatScope(t, caveatScopeFixture(t, test.archive, test.binary), true) })
	}
}

func TestSkillSpectorDistinctScopesFailClosed(t *testing.T) {
	component := func(r map[string]any) map[string]any {
		c := r["components"].([]any)
		return c[len(c)-1].(map[string]any)
	}
	exclusion := func(r map[string]any) map[string]any {
		return r["analysis_completeness"].(map[string]any)["scope_exclusions"].([]any)[0].(map[string]any)
	}
	analyzer := func(r map[string]any, id string) map[string]any {
		for _, v := range r["analysis_completeness"].(map[string]any)["analyzer_statuses"].([]any) {
			if v.(map[string]any)["analyzer_id"] == id {
				return v.(map[string]any)
			}
		}
		t.Fatalf("missing analyzer %s", id)
		return nil
	}
	cases := []struct {
		name   string
		binary bool
		change func(map[string]any)
	}{
		{"missing member provenance", false, func(r map[string]any) { delete(component(r), "outer_path") }},
		{"unknown component field", false, func(r map[string]any) { component(r)["unchecked"] = true }},
		{"foreign parent", false, func(r map[string]any) { component(r)["outer_path"] = "absent.zip" }},
		{"mismatched member", false, func(r map[string]any) { component(r)["nested_path"] = "other.md" }},
		{"traversal member", false, func(r map[string]any) { component(r)["nested_path"] = "../member.md" }},
		{"unsupported depth", false, func(r map[string]any) { component(r)["container_depth"] = float64(2) }},
		{"incorrect ancestry", false, func(r map[string]any) { component(r)["container_ancestry"] = []any{"tar"} }},
		{"incorrect container type", false, func(r map[string]any) { component(r)["container_type"] = "tar" }},
		{"noncontainer parent", false, func(r map[string]any) { r["components"].([]any)[2].(map[string]any)["type"] = "text" }},
		{"executable container", false, func(r map[string]any) { r["components"].([]any)[2].(map[string]any)["executable"] = true }},
		{"container text", false, func(r map[string]any) { r["components"].([]any)[2].(map[string]any)["lines"] = float64(1) }},
		{"duplicate component", false, func(r map[string]any) { r["components"] = append(r["components"].([]any), component(r)) }},
		{"invented remote source", false, func(r map[string]any) { component(r)["source_digest"] = "unchecked" }},
		{"missing static member work", false, func(r map[string]any) {
			a := analyzer(r, "static_patterns_tool_misuse")
			a["planned_work"], a["completed"] = float64(3), float64(3)
		}},
		{"missing visible semantic work", false, func(r map[string]any) {
			a := analyzer(r, "semantic_security_discovery")
			a["planned_work"], a["completed"] = float64(1), float64(1)
		}},
		{"missing container integrity", false, func(r map[string]any) {
			a := analyzer(r, "artifact_integrity")
			a["planned_work"], a["completed"] = float64(3), float64(3)
		}},
		{"false coverage denominator", false, func(r map[string]any) {
			a := r["analysis_completeness"].(map[string]any)
			for _, k := range []string{"total_components", "scanned_components", "fully_inspected_files"} {
				a[k] = float64(4)
			}
		}},
		{"binary missing inventory integrity", true, func(r map[string]any) {
			a := analyzer(r, "artifact_integrity")
			a["planned_work"], a["completed"] = float64(2), float64(2)
		}},
		{"binary missing YARA", true, func(r map[string]any) {
			a := analyzer(r, "static_yara")
			a["planned_work"], a["completed"] = float64(2), float64(2)
		}},
		{"executable binary", true, func(r map[string]any) { component(r)["executable"] = true }},
		{"bytecode exclusion", true, func(r map[string]any) {
			component(r)["path"] = "samples/unsafe.pyc"
			exclusion(r)["path"] = "samples/unsafe.pyc"
		}},
		{"read failure exclusion", true, func(r map[string]any) { exclusion(r)["reason_code"] = "read_error" }},
		{"partial binary projection", true, func(r map[string]any) { exclusion(r)["reason_code"] = "binary_text_projection" }},
		{"cache exclusion", true, func(r map[string]any) { exclusion(r)["phase"] = "cache" }},
		{"missing exclusion target", true, func(r map[string]any) { exclusion(r)["path"] = "missing.png" }},
		{"duplicate exclusion", true, func(r map[string]any) {
			a := r["analysis_completeness"].(map[string]any)
			a["scope_exclusions"] = append(a["scope_exclusions"].([]any), exclusion(r))
		}},
		{"missing scoped analyzer", true, func(r map[string]any) { a := exclusion(r); a["analyzers"] = a["analyzers"].([]any)[1:] }},
		{"duplicate scoped analyzer", true, func(r map[string]any) { a := exclusion(r)["analyzers"].([]any); a[0] = a[1] }},
		{"semantic scope exclusion", true, func(r map[string]any) { exclusion(r)["analyzers"].([]any)[0] = "semantic_security_discovery" }},
		{"fatal exclusion", true, func(r map[string]any) { exclusion(r)["fatal"] = true }},
		{"unknown exclusion field", true, func(r map[string]any) { exclusion(r)["unchecked"] = true }},
		{"missing exclusion field", true, func(r map[string]any) { delete(exclusion(r), "start_line") }},
		{"ambiguous executable flag", true, func(r map[string]any) { component(r)["executable"] = nil }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report := caveatScopeFixture(t, !test.binary, test.binary)
			test.change(report)
			checkCaveatScope(t, report, false)
		})
	}
}

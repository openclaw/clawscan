package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkillSpectorReferenceCaveatCompletion(t *testing.T) {
	raw, err := os.ReadFile("testdata/skillspector-reference-caveat.json")
	if err != nil {
		t.Fatal(err)
	}
	command := &recordingCommandRunner{writeOutput: string(raw), exitCode: intPointer(0)}
	result, err := (ExternalScannerRunner{
		CommandRunner: command, Env: map[string]string{},
		SkillSpectorCommand: []string{"skillspector"},
	}).runSkillSpector(t.TempDir(), "2026-10-23T00:00:00Z")
	if err != nil || result.Status != "completed" || !bytes.Equal(result.Raw, raw) {
		t.Fatalf("reference caveat must not fail completed inspection: status=%s error=%s err=%v", result.Status, result.Error, err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	imported, err := scannerResult(Options{ScannerResultPaths: map[string]string{"skillspector": path}}, "skillspector", resolvedTarget{}, "now", nil)
	if err != nil || imported.Status != "completed" || !bytes.Equal(imported.Raw, raw) {
		t.Fatalf("imported reference caveat: status=%s error=%s err=%v", imported.Status, imported.Error, err)
	}
	var report map[string]any
	if err := json.Unmarshal(result.Raw, &report); err != nil {
		t.Fatal(err)
	}
	completeness := report["analysis_completeness"].(map[string]any)
	if completeness["is_complete"] != false || completeness["status"] != "partial" {
		t.Fatal("raw caveats were rewritten")
	}
	normalized, err := normalizeClawHubSkillSpector(raw, 123)
	if err != nil || normalized.Status == "clean" {
		t.Fatalf("operational completion is not clean analysis: %#v err=%v", normalized, err)
	}
	if normalized.AnalysisCompleteness["is_complete"] != false {
		t.Fatal("normalized judge evidence lost raw completeness caveats")
	}
	prompt, err := RenderClawHubPrompt("Use scanner evidence without treating it as a security verdict.", Artifact{
		Scanners: map[string]ScannerResult{"skillspector": result},
	})
	if err != nil || !strings.Contains(prompt, "reference_missing") || !strings.Contains(prompt, "runtime-note.md") || !strings.Contains(prompt, "analysisCompleteness") {
		t.Fatalf("judge prompt lost reference caveats: err=%v", err)
	}
}

func TestSkillSpectorReferenceCaveatsFailClosed(t *testing.T) {
	fixture, err := os.ReadFile("testdata/skillspector-reference-caveat.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		section string
		field   string
		value   any
	}{
		{"execution failure", "root", "execution_successful", false},
		{"execution malformed", "root", "execution_successful", "true"},
		{"error", "root", "error", "generated failure"},
		{"malformed error", "root", "error", true},
		{"failed status", "root", "status", "failed"},
		{"conflicting schema", "root", "analysisCompleteness", map[string]any{"isComplete": true}},
		{"unknown report schema", "root", "new_contract", true},
		{"nested failure", "accounting", "execution_successful", false},
		{"nested failed status", "accounting", "status", "failed"},
		{"unknown accounting schema", "accounting", "new_contract", true},
		{"case aliased accounting schema", "accounting", "Status", "failed"},
		{"null excluded count", "accounting", "excluded_file_count", nil},
		{"null excluded patterns", "accounting", "exclude_patterns", nil},
		{"unknown metadata schema", "metadata", "new_contract", true},
		{"null inference usage", "metadata", "inference_usage", nil},
		{"object inference usage", "metadata", "inference_usage", map[string]any{}},
		{"malformed inference entry", "metadata", "inference_usage", []any{nil}},
		{"unknown inference schema", "metadata", "inference_usage", []any{map[string]any{"future": true}}},
		{"null provenance", "metadata", "llm_provenance", nil},
		{"malformed provenance", "metadata", "llm_provenance", []any{}},
		{"unknown provenance schema", "metadata", "llm_provenance", map[string]any{"schema_version": float64(2)}},
		{"different producer", "metadata", "skillspector_version", "2.13.0"},
		{"malformed executable flag", "metadata", "has_executable_scripts", nil},
		{"malformed filtering mode", "metadata", "filtering_mode", nil},
		{"missing source identity", "root", "skill", nil},
		{"malformed summaries", "root", "structured_summaries", nil},
		{"missing LLM", "metadata", "llm_available", false},
		{"disabled LLM", "metadata", "llm_requested", false},
		{"degraded LLM", "metadata", "llm_degraded", true},
		{"LLM error", "metadata", "llm_error", "generated failure"},
		{"LLM calls lost", "metadata", "llm_calls_succeeded", float64(2)},
		{"invalid LLM calls", "metadata", "llm_calls_attempted", "3"},
		{"missing meta outcome", "metadata", "meta_analysis_applied", nil},
		{"transitive limit", "metadata", "transitive_truncated", true},
		{"total mismatch", "accounting", "total_components", float64(3)},
		{"scanned mismatch", "accounting", "scanned_components", float64(1)},
		{"fully mismatch", "accounting", "fully_inspected_files", float64(1)},
		{"partial bytes", "accounting", "partially_inspected_files", float64(1)},
		{"uninspected bytes", "accounting", "entirely_uninspected_files", float64(1)},
		{"partial coverage", "accounting", "coverage_percent", float64(99.9)},
		{"missing denominator", "accounting", "total_components", nil},
		{"fractional count", "accounting", "total_components", float64(2.5)},
		{"unsafe count", "accounting", "total_components", float64(1 << 54)},
		{"limit", "accounting", "limitations", []any{"generated limit"}},
		{"missing limitations", "accounting", "limitations", nil},
		{"excluded file", "accounting", "scope_exclusions", []any{map[string]any{"reason_code": "hidden_file"}}},
		{"excluded pattern", "accounting", "exclude_patterns", []any{"generated*"}},
		{"excluded count", "accounting", "excluded_file_count", float64(1)},
		{"lost finding", "accounting", "findings_after_filtering", float64(1)},
		{"lost canonical finding", "accounting", "findings_before_filtering", float64(1)},
		{"unsafe recommendation", "risk", "recommendation", "SAFE"},
		{"malformed risk score", "risk", "score", "0"},
		{"malformed risk severity", "risk", "severity", nil},
		{"unknown risk metadata", "risk", "unknown", true},
		{"missing component", "root", "components", []any{}},
		{"malformed issue", "root", "issues", []any{nil}},
		{"missing suppression accounting", "root", "suppressed", nil},
		{"suppressed finding", "root", "suppressed_count", float64(1)},
		{"missing references", "accounting", "references", nil},
		{"no exceptions", "accounting", "ledger_exceptions", []any{}},
		{"fatal caveat", "exception", "fatal", true},
		{"unknown fatality", "exception", "fatal", nil},
		{"uninspected reference", "exception", "reason_code", "referenced_uninspected"},
		{"static parse limit", "exception", "reason_code", "static_parse_limit"},
		{"MCP cap", "exception", "reason_code", "artifact_count_limit"},
		{"byte bound", "exception", "reason_code", "total_bytes_limit"},
		{"unsupported content", "exception", "reason_code", "unsupported_primary_content"},
		{"obfuscation", "exception", "reason_code", "obfuscated_instruction_text"},
		{"unresolved runtime command", "exception", "reason_code", "reference_extraction_limit"},
		{"unknown reason", "exception", "reason_code", "future_reason"},
		{"unknown exception schema", "exception", "new_contract", true},
		{"case aliased exception schema", "exception", "Fatal", true},
		{"analyzer caveat", "exception", "analyzers", []any{"artifact_integrity"}},
		{"rule caveat", "exception", "scope", "rule_set"},
		{"reference error", "exception", "error_class", "GeneratedError"},
		{"null reference error", "exception", "error_class", nil},
		{"null caveat analyzer metadata", "exception", "analyzers", nil},
		{"failed caveat", "exception", "outcome", "failed"},
		{"other phase", "exception", "phase", "cache"},
		{"missing file", "exception", "path", "missing.md"},
		{"invalid line", "exception", "start_line", float64(0)},
		{"mismatched line", "exception", "end_line", float64(7)},
		{"missing reason message", "exception", "message", ""},
		{"unmatched exception", "reference", "line", float64(5)},
		{"invalid reference line", "reference", "line", float64(99)},
		{"invalid reference column", "reference", "column", nil},
		{"reference with uninspected target", "reference", "target_path", "missing.md"},
		{"reference malformed disposition", "reference", "disposition", "analyzed"},
		{"unknown reference status", "reference", "status", "unknown"},
		{"unknown reference kind", "reference", "reference_kind", "unknown"},
		{"unknown reference schema", "reference", "new_contract", true},
		{"case aliased reference schema", "reference", "Disposition", "failed"},
		{"missing source", "reference", "source_path", "missing.md"},
		{"missing evidence", "reference", "evidence", ""},
		{"incomplete analyzer", "analyzer", "status", "degraded"},
		{"failed analyzer", "analyzer", "status", "failed"},
		{"unknown analyzer", "analyzer", "analyzer_id", "future_analyzer"},
		{"unknown analyzer schema", "analyzer", "new_contract", true},
		{"case aliased analyzer schema", "analyzer", "Completed", float64(0)},
		{"missing planned work", "analyzer", "planned_work", nil},
		{"unaccounted work", "analyzer", "unaccounted", float64(1)},
		{"failed work", "analyzer", "failed", float64(1)},
		{"partial work", "analyzer", "partial", float64(1)},
		{"skipped work", "analyzer", "skipped", float64(1)},
		{"accounting mismatch", "analyzer", "completed", float64(1)},
		{"missing component size", "component", "size_bytes", nil},
		{"negative size", "component", "size_bytes", float64(-1)},
		{"missing component lines", "component", "lines", nil},
		{"missing component kind", "component", "type", nil},
		{"missing component flags", "component", "executable", nil},
		{"unsafe path", "component", "path", "../SKILL.md"},
		{"unverified digest", "component", "source_digest", "sha256:forged"},
		{"unknown component schema", "component", "new_contract", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var report map[string]any
			if err := json.Unmarshal(fixture, &report); err != nil {
				t.Fatal(err)
			}
			accounting := report["analysis_completeness"].(map[string]any)
			sections := map[string]map[string]any{
				"root": report, "accounting": accounting,
				"metadata":  report["metadata"].(map[string]any),
				"risk":      report["risk_assessment"].(map[string]any),
				"exception": accounting["ledger_exceptions"].([]any)[0].(map[string]any),
				"reference": accounting["references"].([]any)[0].(map[string]any),
				"analyzer":  accounting["analyzer_statuses"].([]any)[0].(map[string]any),
				"component": report["components"].([]any)[0].(map[string]any),
			}
			sections[test.section][test.field] = test.value
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := scannerResult(Options{ScannerResultPaths: map[string]string{"skillspector": path}}, "skillspector", resolvedTarget{}, "now", nil)
			if err != nil || result.Status != "failed" || result.Error == "" || !bytes.Equal(result.Raw, raw) {
				t.Fatalf("invalid caveat accepted or evidence lost: status=%s error=%s err=%v", result.Status, result.Error, err)
			}
		})
	}
}

func TestSkillSpectorReferenceCaveatTelemetryContract(t *testing.T) {
	fixture, err := os.ReadFile("testdata/skillspector-reference-caveat.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing usage", "missing provenance", "empty usage", "no counters", "unknown usage key", "case alias", "negative counter", "fractional counter", "null counter", "bad model source", "bad usage source", "unknown provider field", "aliased nullable field", "missing provenance analyzers", "null routing", "null sampling", "malformed analyzer revision"} {
		t.Run(mode, func(t *testing.T) {
			var report map[string]any
			if err := json.Unmarshal(fixture, &report); err != nil {
				t.Fatal(err)
			}
			metadata := report["metadata"].(map[string]any)
			entry := metadata["inference_usage"].([]any)[0].(map[string]any)
			provenance := metadata["llm_provenance"].(map[string]any)
			switch mode {
			case "missing usage":
				delete(metadata, "inference_usage")
			case "missing provenance":
				delete(metadata, "llm_provenance")
			case "empty usage":
				metadata["inference_usage"] = []any{}
			case "no counters":
				for _, field := range []string{"prompt_tokens", "completion_tokens", "total_tokens"} {
					delete(entry, field)
				}
			case "unknown usage key":
				entry["future"] = true
			case "case alias":
				entry["Prompt_tokens"] = float64(1)
			case "negative counter":
				entry["prompt_tokens"] = float64(-1)
			case "fractional counter":
				entry["prompt_tokens"] = float64(0.5)
			case "null counter":
				entry["prompt_tokens"] = nil
			case "bad model source":
				entry["model_source"] = "unknown"
			case "bad usage source":
				entry["usage_source"] = "estimated"
			case "unknown provider field":
				provenance["provider"].(map[string]any)["future"] = true
			case "aliased nullable field":
				routing := provenance["provider"].(map[string]any)["routing"].(map[string]any)
				delete(routing, "api_version")
				routing["API_version"] = nil
			case "missing provenance analyzers":
				provenance["analyzers"] = []any{}
			case "null routing":
				provenance["provider"].(map[string]any)["routing"] = nil
			case "null sampling":
				provenance["sampling"] = nil
			case "malformed analyzer revision":
				provenance["analyzers"].([]any)[0].(map[string]any)["analyzer_revision"] = nil
			}
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			command := &recordingCommandRunner{writeOutput: string(raw), exitCode: intPointer(0)}
			result, err := (ExternalScannerRunner{CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
			want := "failed"
			if mode == "empty usage" {
				want = "completed"
			}
			if err != nil || result.Status != want || !bytes.Equal(result.Raw, raw) {
				t.Fatalf("telemetry contract: status=%s want=%s err=%v", result.Status, want, err)
			}
		})
	}
}

func TestSkillSpectorCaveatReportRequiresUnambiguousJSON(t *testing.T) {
	fixture, err := os.ReadFile("testdata/skillspector-reference-caveat.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(string(fixture), `"execution_successful": true`, `"execution_successful": false, "execution_successful": true`, 1),
		strings.Replace(string(fixture), `"fatal": false`, `"fatal": true, "fatal": false`, 1),
		strings.Replace(string(fixture), `"is_complete": false`, `"is_complete": true, "is_complete": false`, 1),
		strings.Replace(string(fixture), `"total_components": 2`, `"total_components": 999, "total_components": 2`, 1),
		`{"analysis_completeness":`,
	} {
		command := &recordingCommandRunner{writeOutput: raw, exitCode: intPointer(0)}
		result, err := (ExternalScannerRunner{CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
		if err != nil || result.Status != "failed" {
			t.Fatalf("ambiguous or malformed report accepted: status=%s err=%v", result.Status, err)
		}
	}
}

func TestSkillSpectorReferenceCaveatRequiresCanonicalAccounting(t *testing.T) {
	fixture, err := os.ReadFile("testdata/skillspector-reference-caveat.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing analyzer", "duplicate analyzer", "inflated completed work", "unplanned completed work", "duplicate component", "escaping canonical paths", "MCP bound", "resolved uninspected reference"} {
		t.Run(mode, func(t *testing.T) {
			var report map[string]any
			if err := json.Unmarshal(fixture, &report); err != nil {
				t.Fatal(err)
			}
			accounting := report["analysis_completeness"].(map[string]any)
			analyzers := accounting["analyzer_statuses"].([]any)
			first := analyzers[0].(map[string]any)
			switch mode {
			case "missing analyzer":
				accounting["analyzer_statuses"] = analyzers[1:]
			case "duplicate analyzer":
				accounting["analyzer_statuses"] = append(analyzers, first)
			case "inflated completed work":
				first["planned_work"], first["completed"] = float64(3), float64(3)
			case "unplanned completed work":
				first["planned_work"], first["completed"] = float64(0), float64(0)
			case "duplicate component":
				components := report["components"].([]any)
				components[1] = components[0]
			case "escaping canonical paths":
				for _, value := range report["components"].([]any) {
					component := value.(map[string]any)
					component["path"] = "../" + component["path"].(string)
				}
				for _, value := range accounting["ledger_exceptions"].([]any) {
					exception := value.(map[string]any)
					exception["path"] = "../" + exception["path"].(string)
				}
				for _, value := range accounting["references"].([]any) {
					reference := value.(map[string]any)
					reference["source_path"] = "../" + reference["source_path"].(string)
				}
			case "MCP bound":
				for _, value := range analyzers {
					analyzer := value.(map[string]any)
					if analyzer["analyzer_id"] == "mcp_tool_poisoning" {
						analyzer["planned_work"], analyzer["completed"] = float64(129), float64(129)
					}
				}
			case "resolved uninspected reference":
				references := accounting["references"].([]any)
				references = append(references, map[string]any{
					"source_path": "SKILL.md", "line": float64(6), "column": float64(1),
					"evidence": "Generated required artifact reference", "reference_kind": "markdown_link",
					"status": "resolved", "disposition": "analyzed", "target_path": "missing-required.md",
				})
				accounting["references"] = references
			}
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			command := &recordingCommandRunner{writeOutput: string(raw), exitCode: intPointer(0)}
			result, err := (ExternalScannerRunner{CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
			if err != nil || result.Status != "failed" || !bytes.Equal(result.Raw, raw) {
				t.Fatalf("noncanonical report accepted or changed: status=%s err=%v", result.Status, err)
			}
		})
	}
}

func TestSkillSpectorCaveatsDoNotOverrideCommandFailures(t *testing.T) {
	raw, err := os.ReadFile("testdata/skillspector-reference-caveat.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, exitCode := range []int{0, 1, 2, -1} {
		command := &recordingCommandRunner{writeOutput: string(raw), exitCode: intPointer(exitCode)}
		if exitCode != 0 {
			command.err = errCommandFailed
		}
		result, err := (ExternalScannerRunner{CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
		want := "completed"
		if exitCode < 0 || exitCode > 1 {
			want = "failed"
		}
		if err != nil || result.Status != want || !bytes.Equal(result.Raw, raw) {
			t.Fatalf("exit=%d status=%s err=%v", exitCode, result.Status, err)
		}
	}
}

func TestSkillSpectorReferenceCaveatsRejectUnsafeAnalyzerIntegers(t *testing.T) {
	fixture, err := os.ReadFile("testdata/skillspector-reference-caveat.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, counts := range [][2]string{{"9007199254740993", "9007199254740992"}, {"2147483649", "2147483649"}} {
		t.Run(strings.Join(counts[:], "-"), func(t *testing.T) {
			var report map[string]any
			if err := json.Unmarshal(fixture, &report); err != nil {
				t.Fatal(err)
			}
			accounting := report["analysis_completeness"].(map[string]any)
			for _, value := range accounting["analyzer_statuses"].([]any) {
				analyzer := value.(map[string]any)
				if analyzer["analyzer_id"] == "behavioral_ast" {
					analyzer["status"] = "completed"
					delete(analyzer, "reason_code")
					analyzer["planned_work"], analyzer["completed"] = json.Number(counts[0]), json.Number(counts[1])
				}
			}
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			command := &recordingCommandRunner{writeOutput: string(raw), exitCode: intPointer(0)}
			result, err := (ExternalScannerRunner{CommandRunner: command, Env: map[string]string{}, SkillSpectorCommand: []string{"skillspector"}}).runSkillSpector(t.TempDir(), "now")
			if err != nil || result.Status != "failed" || !bytes.Equal(result.Raw, raw) {
				t.Fatalf("unsafe non-per-file accounting accepted: status=%s err=%v", result.Status, err)
			}
		})
	}
}

package runner

import (
	"bytes"
	"encoding/json"
	"io"
	"path"
	"strings"
)

type skillSpectorCaveatAccounting struct {
	Total       *int                             `json:"total_components"`
	Scanned     *int                             `json:"scanned_components"`
	Fully       *int                             `json:"fully_inspected_files"`
	Partial     *int                             `json:"partially_inspected_files"`
	Uninspected *int                             `json:"entirely_uninspected_files"`
	Before      *int                             `json:"findings_before_filtering"`
	After       *int                             `json:"findings_after_filtering"`
	Coverage    *float64                         `json:"coverage_percent"`
	Complete    *bool                            `json:"is_complete"`
	Successful  *bool                            `json:"execution_successful"`
	Status      string                           `json:"status"`
	Exceptions  []skillSpectorReferenceException `json:"ledger_exceptions"`
	Exclusions  []json.RawMessage                `json:"scope_exclusions"`
	Limitations []string                         `json:"limitations"`
	Analyzers   []skillSpectorCaveatAnalyzer     `json:"analyzer_statuses"`
	References  []skillSpectorCaveatReference    `json:"references"`
	Patterns    []string                         `json:"exclude_patterns"`
	Excluded    int                              `json:"excluded_file_count"`
}

type skillSpectorReferenceException struct {
	Outcome    string   `json:"outcome"`
	Phase      string   `json:"phase"`
	Reason     string   `json:"reason_code"`
	Message    string   `json:"message"`
	Path       string   `json:"path"`
	Start      *int     `json:"start_line"`
	End        *int     `json:"end_line"`
	Fatal      *bool    `json:"fatal"`
	Analyzers  []string `json:"analyzers"`
	ErrorClass string   `json:"error_class"`
	Scope      string   `json:"scope"`
}

type skillSpectorCaveatAnalyzer struct {
	ID          string `json:"analyzer_id"`
	Status      string `json:"status"`
	Planned     *int   `json:"planned_work"`
	Completed   *int   `json:"completed"`
	Partial     *int   `json:"partial"`
	Skipped     *int   `json:"skipped"`
	Failed      *int   `json:"failed"`
	Unaccounted *int   `json:"unaccounted"`
	Reason      string `json:"reason_code"`
	Message     string `json:"message"`
}

type skillSpectorCaveatReference struct {
	Source      string          `json:"source_path"`
	Line        *int            `json:"line"`
	Column      *int            `json:"column"`
	Evidence    string          `json:"evidence"`
	Target      json.RawMessage `json:"target_path"`
	Status      string          `json:"status"`
	Disposition string          `json:"disposition"`
	Kind        string          `json:"reference_kind"`
}

func skillSpectorReferenceCaveatsOnly(record map[string]any) bool {
	if record["execution_successful"] != true || !skillSpectorKnownFields(record, "skill risk_assessment components structured_summaries issues suppressed_count suppressed metadata execution_successful analysis_completeness") {
		return false
	}
	for _, key := range []string{"error", "status", "executionSuccessful", "is_complete", "isComplete", "analysisCompleteness"} {
		if _, exists := record[key]; exists {
			return false
		}
	}
	metadata, ok := record["metadata"].(map[string]any)
	if !ok || metadata["skillspector_version"] != "2.12.0" || metadata["llm_requested"] != true || metadata["llm_available"] != true {
		return false
	}
	if !skillSpectorKnownFields(metadata, "has_executable_scripts skillspector_version llm_requested llm_available meta_analysis_applied inference_usage llm_provenance filtering_mode llm_calls_attempted llm_calls_succeeded") {
		return false
	}
	if !skillSpectorCaveatTelemetryKnown(metadata) {
		return false
	}
	if _, valid := metadata["has_executable_scripts"].(bool); !valid {
		return false
	}
	if value, exists := metadata["filtering_mode"]; exists && value != "heuristic" {
		return false
	}
	skill, ok := record["skill"].(map[string]any)
	if !ok || !skillSpectorKnownFields(skill, "name source scanned_at") {
		return false
	}
	for _, field := range []string{"name", "source", "scanned_at"} {
		if value, valid := skill[field].(string); !valid || strings.TrimSpace(value) == "" {
			return false
		}
	}
	if _, valid := record["structured_summaries"].([]any); !valid {
		return false
	}
	attempted, attemptedOK := skillSpectorReportCount(metadata["llm_calls_attempted"])
	succeeded, succeededOK := skillSpectorReportCount(metadata["llm_calls_succeeded"])
	if !attemptedOK || !succeededOK || attempted < 3 || attempted != succeeded {
		return false
	}
	risk, ok := record["risk_assessment"].(map[string]any)
	if !ok || (risk["recommendation"] != "CAUTION" && risk["recommendation"] != "DO_NOT_INSTALL") {
		return false
	}
	score, scoreOK := skillSpectorReportCount(risk["score"])
	severity, severityOK := risk["severity"].(string)
	if !scoreOK || score > 100 || !severityOK || severity == "" || !skillSpectorKnownFields(risk, "score severity recommendation max_issue_severity") {
		return false
	}
	if value, exists := risk["max_issue_severity"]; exists {
		if severity, valid := value.(string); !valid || severity == "" {
			return false
		}
	}
	completeness, ok := record["analysis_completeness"].(map[string]any)
	if !ok || !skillSpectorCaveatSchemaKnown(completeness) {
		return false
	}
	encoded, err := json.Marshal(completeness)
	if err != nil {
		return false
	}
	var accounting skillSpectorCaveatAccounting
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&accounting) != nil || accounting.Complete == nil || *accounting.Complete || accounting.Successful == nil || !*accounting.Successful || accounting.Status != "partial" {
		return false
	}
	components, ok := record["components"].([]any)
	total := len(components)
	if !ok || total == 0 || !skillSpectorCountsEqual(total, accounting.Total, accounting.Scanned, accounting.Fully) || !skillSpectorCountsEqual(0, accounting.Partial, accounting.Uninspected) || accounting.Coverage == nil || *accounting.Coverage != 100 {
		return false
	}
	if accounting.Exclusions == nil || len(accounting.Exclusions) != 0 || accounting.Limitations == nil || len(accounting.Limitations) != 0 || len(accounting.Patterns) != 0 || accounting.Excluded != 0 || len(accounting.Exceptions) == 0 {
		return false
	}
	lines := make(map[string]int, total)
	for _, value := range components {
		component, ok := value.(map[string]any)
		if !ok || !skillSpectorKnownFields(component, "path type lines executable size_bytes source_url source_identity source_digest") {
			return false
		}
		if component["source_url"] != nil || component["source_identity"] != nil || component["source_digest"] != nil {
			return false
		}
		if kind, ok := component["type"].(string); !ok || kind == "" {
			return false
		}
		if _, ok := component["executable"].(bool); !ok {
			return false
		}
		name, _ := component["path"].(string)
		lineCount, linesOK := skillSpectorReportCount(component["lines"])
		_, sizeOK := skillSpectorReportCount(component["size_bytes"])
		if name == "" || name == "." || name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) || path.Clean(name) != name || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) || !linesOK || !sizeOK {
			return false
		}
		if _, duplicate := lines[name]; duplicate {
			return false
		}
		lines[name] = lineCount
	}
	if !skillSpectorCaveatAnalyzersComplete(accounting.Analyzers, total) {
		return false
	}
	issues, issuesOK := record["issues"].([]any)
	suppressed, suppressedOK := record["suppressed"].([]any)
	if !issuesOK || !suppressedOK || len(suppressed) != 0 || record["suppressed_count"] != float64(0) || !skillSpectorCountsEqual(len(issues), accounting.Before, accounting.After) {
		return false
	}
	if len(issues) > 0 && attempted < 4 {
		return false
	}
	identities := make(map[string]bool, len(issues))
	for _, value := range issues {
		issue, ok := value.(map[string]any)
		if !ok {
			return false
		}
		identity, _ := issue["finding_id"].(string)
		identifier, _ := issue["id"].(string)
		severity, _ := issue["severity"].(string)
		if identity == "" || identifier == "" || severity == "" || identities[identity] {
			return false
		}
		identities[identity] = true
	}
	if metadata["meta_analysis_applied"] != (len(issues) > 0) {
		return false
	}
	for _, analyzer := range accounting.Analyzers {
		if analyzer.ID == "meta_analyzer" && (analyzer.Status == "completed") != (len(issues) > 0) {
			return false
		}
	}
	return skillSpectorReferenceAccountingComplete(accounting, lines)
}

func skillSpectorKnownFields(record map[string]any, fields string) bool {
	allowed := make(map[string]bool)
	for _, field := range strings.Fields(fields) {
		allowed[field] = true
	}
	for field := range record {
		if !allowed[field] {
			return false
		}
	}
	return true
}

func skillSpectorCaveatSchemaKnown(completeness map[string]any) bool {
	if !skillSpectorKnownFields(completeness, "total_components scanned_components fully_inspected_files partially_inspected_files entirely_uninspected_files findings_before_filtering findings_after_filtering coverage_percent is_complete execution_successful status ledger_exceptions scope_exclusions limitations analyzer_statuses references exclude_patterns excluded_file_count") {
		return false
	}
	if value, exists := completeness["exclude_patterns"]; exists {
		patterns, valid := value.([]any)
		if !valid || len(patterns) != 0 {
			return false
		}
	}
	if value, exists := completeness["excluded_file_count"]; exists {
		count, valid := skillSpectorReportCount(value)
		if !valid || count != 0 {
			return false
		}
	}
	for field, fields := range map[string]string{
		"ledger_exceptions": "outcome phase reason_code message path start_line end_line fatal analyzers error_class scope",
		"analyzer_statuses": "analyzer_id status planned_work completed partial skipped failed unaccounted reason_code message",
		"references":        "source_path line column evidence target_path status disposition reference_kind",
	} {
		rows, valid := completeness[field].([]any)
		if !valid {
			return false
		}
		for _, value := range rows {
			row, valid := value.(map[string]any)
			if !valid || !skillSpectorKnownFields(row, fields) {
				return false
			}
			for field, value := range row {
				if value == nil && field != "start_line" && field != "end_line" && field != "target_path" {
					return false
				}
			}
		}
	}
	return true
}

func skillSpectorCaveatAnalyzersComplete(analyzers []skillSpectorCaveatAnalyzer, total int) bool {
	required := strings.Fields("artifact_integrity behavioral_ast behavioral_taint_tracking bundled_execution_surface mcp_least_privilege mcp_rug_pull mcp_tool_poisoning meta_analyzer semantic_developer_intent semantic_quality_policy semantic_security_discovery static_patterns_agent_snooping static_patterns_anti_refusal static_patterns_data_exfiltration static_patterns_deserialization static_patterns_excessive_agency static_patterns_harmful_content static_patterns_memory_poisoning static_patterns_output_handling static_patterns_privilege_escalation static_patterns_prompt_injection static_patterns_rogue_agent static_patterns_ssrf static_patterns_supply_chain static_patterns_system_prompt_leakage static_patterns_tool_misuse static_yara")
	remaining := make(map[string]bool, len(required))
	for _, name := range required {
		remaining[name] = true
	}
	for _, analyzer := range analyzers {
		if !remaining[analyzer.ID] || analyzer.Planned == nil || *analyzer.Planned < 0 || *analyzer.Planned > 1<<31 || !skillSpectorCountsEqual(*analyzer.Planned, analyzer.Completed) || !skillSpectorCountsEqual(0, analyzer.Partial, analyzer.Skipped, analyzer.Failed, analyzer.Unaccounted) {
			return false
		}
		delete(remaining, analyzer.ID)
		perFile := analyzer.ID == "artifact_integrity" || analyzer.ID == "static_yara" || strings.HasPrefix(analyzer.ID, "static_patterns_") || strings.HasPrefix(analyzer.ID, "semantic_")
		if perFile && *analyzer.Planned != total {
			return false
		}
		if analyzer.ID == "mcp_tool_poisoning" && *analyzer.Planned > 128 {
			return false
		}
		switch analyzer.Status {
		case "completed":
			if *analyzer.Planned == 0 || analyzer.Reason != "" {
				return false
			}
		case "not_applicable":
			if perFile || *analyzer.Planned != 0 || analyzer.Reason != "no_applicable_files" {
				return false
			}
		default:
			return false
		}
	}
	return len(remaining) == 0
}

func skillSpectorReferenceAccountingComplete(accounting skillSpectorCaveatAccounting, lines map[string]int) bool {
	type referenceKey struct {
		source string
		line   int
		reason string
	}
	exceptions := make(map[referenceKey]bool)
	for _, exception := range accounting.Exceptions {
		if exception.Outcome != "partial" || exception.Phase != "reference_resolution" || (exception.Reason != "reference_missing" && exception.Reason != "reference_unresolved") || exception.Message == "" || exception.Fatal == nil || *exception.Fatal || len(exception.Analyzers) != 0 || exception.Scope != "" || exception.ErrorClass != "" || exception.Start == nil || *exception.Start < 1 || *exception.Start > lines[exception.Path] || !skillSpectorCountsEqual(*exception.Start, exception.End) {
			return false
		}
		key := referenceKey{exception.Path, *exception.Start, exception.Reason}
		if _, duplicate := exceptions[key]; duplicate {
			return false
		}
		exceptions[key] = false
	}
	for _, reference := range accounting.References {
		if reference.Line == nil || *reference.Line < 1 || *reference.Line > lines[reference.Source] || reference.Column == nil || *reference.Column < 1 || reference.Evidence == "" {
			return false
		}
		switch reference.Kind {
		case "markdown_image", "markdown_link", "inline_command", "quoted_or_code", "plain_path":
		default:
			return false
		}
		if reference.Status == "resolved" {
			var target string
			if json.Unmarshal(reference.Target, &target) != nil || reference.Disposition != "analyzed" {
				return false
			}
			if _, present := lines[target]; !present {
				return false
			}
			continue
		}
		reason := map[string]string{"missing": "reference_missing", "ambiguous": "reference_unresolved"}[reference.Status]
		key := referenceKey{reference.Source, *reference.Line, reason}
		if _, exists := exceptions[key]; !exists || reason == "" || reference.Disposition != "partial" || !bytes.Equal(reference.Target, []byte("null")) {
			return false
		}
		exceptions[key] = true
	}
	for _, matched := range exceptions {
		if !matched {
			return false
		}
	}
	return true
}

func skillSpectorCountsEqual(expected int, counts ...*int) bool {
	for _, count := range counts {
		if count == nil || *count != expected {
			return false
		}
	}
	return true
}

func skillSpectorReportCount(value any) (int, bool) {
	count, ok := value.(float64)
	if !ok || count < 0 || count > 1<<31 || count != float64(int(count)) {
		return 0, false
	}
	return int(count), true
}

func skillSpectorUnambiguousJSON(raw json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var readValue func() bool
	readValue = func() bool {
		value, err := decoder.Token()
		if err != nil {
			return false
		}
		delimiter, container := value.(json.Delim)
		if !container {
			return true
		}
		if delimiter != '{' && delimiter != '[' {
			return false
		}
		keys := make(map[string]bool)
		for decoder.More() {
			if delimiter == '{' {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || keys[name] {
					return false
				}
				keys[name] = true
			}
			if !readValue() {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && ((delimiter == '{' && closing == json.Delim('}')) || (delimiter == '[' && closing == json.Delim(']')))
	}
	if !readValue() {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

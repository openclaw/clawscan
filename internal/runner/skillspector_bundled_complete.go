package runner

import (
	"encoding/json"
	"strings"
)

// This full ledger is required only for the new complete bundle envelope.
// Legacy complete reports and usable partials retain their existing policies.
func skillSpectorCompleteInspection(record map[string]any) bool {
	if record["execution_successful"] != true || skillSpectorHasBundle(record) || !skillSpectorBundledChildIntegrity(record) || skillSpectorReportError(record) != "" {
		return false
	}
	for _, key := range []string{"executionSuccessful", "isComplete", "analysisCompleteness"} {
		if _, exists := record[key]; exists {
			return false
		}
	}
	metadata, ok := record["metadata"].(map[string]any)
	version, versionOK := metadata["skillspector_version"].(string)
	if !ok || !versionOK || strings.TrimSpace(version) == "" {
		return false
	}
	accounting, ok := record["analysis_completeness"].(map[string]any)
	if !ok || !skillSpectorKnownFields(accounting, "total_components scanned_components fully_inspected_files partially_inspected_files entirely_uninspected_files findings_before_filtering findings_after_filtering coverage_percent is_complete execution_successful status ledger_exceptions scope_exclusions limitations analyzer_statuses references exclude_patterns excluded_file_count") {
		return false
	}
	for _, key := range strings.Fields("total_components scanned_components fully_inspected_files partially_inspected_files entirely_uninspected_files findings_before_filtering findings_after_filtering") {
		if _, ok := skillSpectorReportCount(accounting[key]); !ok {
			return false
		}
	}
	if value, exists := accounting["exclude_patterns"]; exists {
		patterns, ok := value.([]any)
		if !ok {
			return false
		}
		for _, pattern := range patterns {
			if _, ok := pattern.(string); !ok {
				return false
			}
		}
	}
	if value, exists := accounting["excluded_file_count"]; exists {
		if _, ok := skillSpectorReportCount(value); !ok {
			return false
		}
	}
	encoded, err := json.Marshal(accounting)
	var typed skillSpectorCaveatAccounting
	if err != nil || json.Unmarshal(encoded, &typed) != nil || typed.Successful == nil || !*typed.Successful || typed.Complete == nil || !*typed.Complete {
		return false
	}
	if typed.Status != "complete" && typed.Status != "completed" && typed.Status != "complete_with_caveats" {
		return false
	}
	for field, fields := range map[string]string{
		"ledger_exceptions": "outcome phase reason_code message path start_line end_line fatal analyzers error_class scope",
		"analyzer_statuses": "analyzer_id status planned_work completed partial skipped failed unaccounted reason_code message",
		"references":        "source_path line column evidence target_path status disposition reference_kind",
	} {
		rows, ok := accounting[field].([]any)
		if !ok {
			return false
		}
		for _, value := range rows {
			row, ok := value.(map[string]any)
			if !ok || !skillSpectorKnownFields(row, fields) {
				return false
			}
			for key, value := range row {
				if value == nil && key != "target_path" {
					return false
				}
				switch key {
				case "start_line", "end_line", "line", "column", "planned_work", "completed", "partial", "skipped", "failed", "unaccounted":
					if _, ok := skillSpectorReportCount(value); !ok {
						return false
					}
				}
			}
		}
	}
	components, ok := record["components"].([]any)
	if !ok || len(components) == 0 {
		return false
	}
	scopes, valid := skillSpectorCaveatComponentScopes(components, typed.Exclusions)
	if !valid {
		return false
	}
	lines := scopes.lines
	if typed.Total == nil || *typed.Total < 1 || *typed.Total != scopes.coverage || !skillSpectorCountsEqual(*typed.Total, typed.Scanned, typed.Fully) || !skillSpectorCountsEqual(0, typed.Partial, typed.Uninspected) || typed.Coverage == nil || *typed.Coverage != 100*float64(*typed.Fully)/float64(*typed.Total) {
		return false
	}
	issues, ok := record["issues"].([]any)
	if !ok || typed.Before == nil || *typed.Before > 1<<31 || typed.After == nil || *typed.Before < *typed.After || !skillSpectorCountsEqual(len(issues), typed.After) {
		return false
	}
	for _, value := range issues {
		if issue, ok := value.(map[string]any); !ok || len(issue) == 0 {
			return false
		}
	}
	if typed.Limitations == nil || len(typed.Limitations) != 0 || typed.Exclusions == nil || typed.Excluded < 0 || typed.Excluded > 1<<31 {
		return false
	}
	for _, value := range typed.Exclusions {
		var row map[string]any
		if json.Unmarshal(value, &row) != nil || len(row) == 0 {
			return false
		}
	}
	if len(typed.Analyzers) == 0 {
		return false
	}
	// The pinned runtime emits a receipt for every registered analyzer, including
	// those disabled by configuration. Requiring receipts does not require work
	// from a declared disabled/inapplicable analyzer or attest the runtime config;
	// runtime/profile parity is qualified separately from this report contract.
	analyzers := map[string]bool{}
	for _, id := range strings.Fields("artifact_integrity behavioral_ast behavioral_taint_tracking bundled_execution_surface mcp_least_privilege mcp_rug_pull mcp_tool_poisoning meta_analyzer semantic_developer_intent semantic_quality_policy semantic_security_discovery static_yara " + skillSpectorStaticPatternAnalyzers) {
		analyzers[id] = true
	}
	for _, row := range typed.Analyzers {
		if !analyzers[row.ID] || row.Planned == nil || *row.Planned < 0 || *row.Planned > 1<<31 || !skillSpectorCountsEqual(*row.Planned, row.Completed) || !skillSpectorCountsEqual(0, row.Partial, row.Skipped, row.Failed, row.Unaccounted) {
			return false
		}
		delete(analyzers, row.ID)
		expected := -1
		switch {
		case row.ID == "artifact_integrity" || row.ID == "static_yara":
			expected = scopes.inventory
		case strings.HasPrefix(row.ID, "static_patterns_"):
			expected = scopes.staticPatterns
		case strings.HasPrefix(row.ID, "semantic_"):
			expected = scopes.semantic
		}
		if row.Status != "disabled" && expected >= 0 && *row.Planned != expected {
			return false
		}
		switch row.Status {
		case "completed":
			if *row.Planned == 0 || row.Reason != "" {
				return false
			}
		case "not_applicable":
			if *row.Planned != 0 || row.Reason != "no_applicable_files" {
				return false
			}
		case "disabled":
			if *row.Planned != 0 || row.Reason != "disabled_by_configuration" {
				return false
			}
		default:
			return false
		}
		if row.ID == "artifact_integrity" && *row.Planned != len(components) {
			return false
		}
	}
	if len(analyzers) != 0 {
		return false
	}
	for _, row := range typed.Exceptions {
		if row.Reason != "reference_missing" {
			return false
		}
	}
	if !skillSpectorReferenceAccountingComplete(typed, lines) {
		return false
	}
	missing := 0
	for _, row := range typed.References {
		if row.Status == "missing" {
			missing++
		}
	}
	if typed.Status == "complete_with_caveats" {
		return missing > 0 && len(typed.Exceptions) > 0
	}
	return missing == 0 && len(typed.Exceptions) == 0
}
